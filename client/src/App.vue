<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import {
  createKeyPacket,
  decryptBytes,
  decryptJson,
  deriveSessionKey,
  encryptBytes,
  encryptJson,
  randomSecret,
  type KeyPacket,
} from "./lib/crypto";

type Status = { state: "WAITING" | "LOCKED" | "CLOSING" | "DESTROYED"; expiresAt: number; destroyAt?: number; you: string; peerOnline: boolean; peerJoined: boolean; fileTransferAvailable: boolean; serverNow: number };
type ChatItem = { id: string; sender: "you" | "peer"; kind: "message" | "file"; text?: string; file?: { id: string; name: string; type: string; size: number } };

const phase = ref<"home" | "joining" | "room" | "ended">("home");
const sessionId = ref("");
const participantToken = ref("");
const pairingSecret = ref("");
const invitation = ref("");
const joinCode = ref("");
const message = ref("");
const status = ref<Status | null>(null);
const error = ref("");
const notice = ref("");
const messages = ref<ChatItem[]>([]);
const now = ref(Date.now());
const isSecure = ref(false);
const sendingFile = ref(false);
let socket: WebSocket | null = null;
let privateKey: CryptoKey | null = null;
let sessionKey: CryptoKey | null = null;
let ownKeyPacket: KeyPacket | null = null;
let sequence = 0;
let lastPeerSequence = 0;
let ticker: number | undefined;

const countdownTarget = computed(() => Math.min(status.value?.expiresAt ?? 0, status.value?.destroyAt ?? Number.POSITIVE_INFINITY));
const remaining = computed(() => Math.max(0, countdownTarget.value - now.value));
const formattedRemaining = computed(() => {
  const seconds = Math.ceil(remaining.value / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
});
const isClosing = computed(() => status.value?.state === "CLOSING" || remaining.value <= 60_000);
const peerLabel = computed(() => status.value?.peerOnline ? "在线且已加密" : status.value?.peerJoined ? "已加入，等待连接" : "等待受邀者");
const canSend = computed(() => isSecure.value && status.value?.state === "LOCKED" && status.value.peerOnline);
const canSendFile = computed(() => Boolean(canSend.value && status.value?.fileTransferAvailable));

onMounted(() => {
  ticker = window.setInterval(() => { now.value = Date.now(); }, 250);
  const match = window.location.pathname.match(/^\/s\/([A-Za-z0-9_-]{20,})$/);
  const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  if (match && fragment.get("p")) {
    sessionId.value = match[1];
    pairingSecret.value = fragment.get("p") ?? "";
    phase.value = "joining";
  }
});

onBeforeUnmount(() => {
  if (ticker) window.clearInterval(ticker);
  closeSocket();
});

async function api(path: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers);
  headers.set("Cache-Control", "no-store");
  if (participantToken.value) headers.set("Authorization", `Bearer ${participantToken.value}`);
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: "request_failed" }));
    throw new Error(body.error ?? "request_failed");
  }
  return response;
}

async function createSession() {
  error.value = "";
  try {
    pairingSecret.value = randomSecret();
    const response = await api("/api/sessions", { method: "POST" });
    const data = await response.json() as { sessionId: string; token: string };
    sessionId.value = data.sessionId;
    participantToken.value = data.token;
    invitation.value = `${window.location.origin}/s/${sessionId.value}#p=${pairingSecret.value}`;
    window.history.replaceState({}, "", `/s/${sessionId.value}#p=${pairingSecret.value}`);
    phase.value = "room";
    await connect();
  } catch (caught) {
    error.value = humanError(caught);
  }
}

async function joinSession() {
  error.value = "";
  try {
    if (!sessionId.value || !pairingSecret.value) throw new Error("invalid_invitation");
    const response = await api(`/api/sessions/${encodeURIComponent(sessionId.value)}/join`, { method: "POST" });
    const data = await response.json() as { token: string };
    participantToken.value = data.token;
    phase.value = "room";
    await connect();
  } catch (caught) {
    error.value = humanError(caught);
    phase.value = "joining";
  }
}

function useCode() {
  const input = joinCode.value.trim();
  try {
    const url = new URL(input.includes("://") ? input : `${window.location.origin}/s/${input}`);
    const match = url.pathname.match(/^\/s\/([A-Za-z0-9_-]{20,})$/);
    const secret = new URLSearchParams(url.hash.replace(/^#/, "")).get("p");
    if (!match || !secret) throw new Error("invalid_invitation");
    sessionId.value = match[1];
    pairingSecret.value = secret;
    phase.value = "joining";
  } catch {
    error.value = "请输入完整的 VeilRoom 邀请链接。密钥仅存在链接的 # 片段中。";
  }
}

async function connect() {
  closeSocket();
  isSecure.value = false;
  sessionKey = null;
  const socketScheme = window.location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${socketScheme}://${window.location.host}/api/ws?sessionId=${encodeURIComponent(sessionId.value)}&token=${encodeURIComponent(participantToken.value)}`);
  socket.onopen = async () => {
    try {
      const keyMaterial = await createKeyPacket(sessionId.value, pairingSecret.value);
      privateKey = keyMaterial.privateKey;
      ownKeyPacket = keyMaterial.packet;
      sendKeyIfReady();
    } catch {
      failSecurely("无法建立本地加密材料，已拒绝会话。");
    }
  };
  socket.onmessage = async (event) => {
    try { await handleIncoming(event.data); } catch { failSecurely("检测到无效或被篡改的数据，已终止会话。"); }
  };
  socket.onclose = () => {
    if (phase.value === "room" && !error.value) notice.value = "连接已关闭。基于隐私保护规则，本会话将进入销毁流程。";
  };
  socket.onerror = () => { error.value = "安全通道无法建立。未发送任何内容。"; };
}

async function handleIncoming(raw: string) {
  const event = JSON.parse(raw) as Record<string, unknown>;
  if (event.type === "session-status") {
    status.value = event as unknown as Status;
    sendKeyIfReady();
    if (status.value.state === "CLOSING") notice.value = "已有参与者离开；会话将在一分钟内销毁。";
    return;
  }
  if (event.type === "key") {
    if (!privateKey) throw new Error("missing_local_key");
    sessionKey = await deriveSessionKey(sessionId.value, pairingSecret.value, privateKey, { publicKey: String(event.publicKey), proof: String(event.proof) });
    isSecure.value = true;
    notice.value = "端到端加密已验证。服务器只能看到密文。";
    return;
  }
  if (event.type === "ciphertext") {
    if (!sessionKey) throw new Error("not_secure");
    const peerSequence = validatePeerSequence(event.seq);
    const payload = await decryptJson<{ kind: "message"; text: string; id: string }>(sessionKey, { nonce: String(event.nonce), ciphertext: String(event.ciphertext) }, aad("message", peerSequence, peerRole()));
    messages.value.push({ id: payload.id, sender: "peer", kind: "message", text: payload.text });
    return;
  }
  if (event.type === "file-offer") {
    if (!sessionKey) throw new Error("not_secure");
    const peerSequence = validatePeerSequence(event.seq);
    const payload = await decryptJson<{ kind: "file"; id: string; name: string; type: string; size: number }>(sessionKey, { nonce: String(event.nonce), ciphertext: String(event.ciphertext) }, aad("file", peerSequence, peerRole()));
    messages.value.push({ id: payload.id, sender: "peer", kind: "file", file: payload });
  }
}

async function sendMessage() {
  const text = message.value.trim();
  if (!text || !sessionKey || !canSend.value) return;
  const id = crypto.randomUUID();
  const seq = ++sequence;
  const encrypted = await encryptJson(sessionKey, { kind: "message", id, text }, aad("message", seq, ownRole()));
  socket?.send(JSON.stringify({ type: "ciphertext", seq, ...encrypted }));
  messages.value.push({ id, sender: "you", kind: "message", text });
  message.value = "";
}

async function sendFile(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file || !sessionKey || !canSend.value) return;
  if (file.size > 15 * 1024 * 1024) { error.value = "MVP 单文件限制为 15 MB。"; return; }
  sendingFile.value = true;
  try {
    const id = crypto.randomUUID();
    const encrypted = await encryptBytes(sessionKey, await file.arrayBuffer(), `veilroom:v1:${sessionId.value}:file:${id}`);
    await api(`/api/files?sessionId=${encodeURIComponent(sessionId.value)}&fileId=${encodeURIComponent(id)}`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream", "Content-Length": String(encrypted.byteLength) },
      body: encrypted.buffer,
    });
    const seq = ++sequence;
    const offer = await encryptJson(sessionKey, { kind: "file", id, name: file.name, type: file.type || "application/octet-stream", size: file.size }, aad("file", seq, ownRole()));
    socket?.send(JSON.stringify({ type: "file-offer", seq, ...offer }));
    messages.value.push({ id, sender: "you", kind: "file", file: { id, name: file.name, type: file.type, size: file.size } });
  } catch (caught) {
    error.value = humanError(caught);
  } finally {
    sendingFile.value = false;
  }
}

async function downloadFile(file: NonNullable<ChatItem["file"]>) {
  if (!sessionKey) return;
  try {
    const response = await api(`/api/files/${encodeURIComponent(file.id)}?sessionId=${encodeURIComponent(sessionId.value)}`);
    const encrypted = await response.arrayBuffer();
    const clear = await decryptBytes(sessionKey, encrypted, `veilroom:v1:${sessionId.value}:file:${file.id}`);
    const anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(new Blob([clear], { type: file.type }));
    anchor.download = file.name;
    anchor.click();
    URL.revokeObjectURL(anchor.href);
  } catch (caught) {
    error.value = humanError(caught);
  }
}

async function copyInvitation() {
  try { await navigator.clipboard.writeText(invitation.value); notice.value = "邀请链接已复制。请仅通过可信渠道分享。"; } catch { error.value = "复制失败，请手动复制邀请链接。"; }
}

async function leaveSession() {
  const id = sessionId.value;
  const token = participantToken.value;
  closeSocket();
  if (id && token) {
    try { await fetch(`/api/sessions/${encodeURIComponent(id)}/leave`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, keepalive: true, cache: "no-store" }); } catch { /* close is still fail-safe */ }
  }
  wipeLocalState();
  phase.value = "ended";
}

function closeSocket() { socket?.close(); socket = null; }
function sendKeyIfReady() {
  if (!ownKeyPacket || !status.value?.peerJoined || socket?.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({ type: "key", ...ownKeyPacket }));
}
function wipeLocalState() { privateKey = null; sessionKey = null; ownKeyPacket = null; participantToken.value = ""; pairingSecret.value = ""; sequence = 0; lastPeerSequence = 0; }
function failSecurely(reason: string) { error.value = reason; closeSocket(); wipeLocalState(); phase.value = "ended"; }
function ownRole() { return status.value?.you ?? "unknown"; }
function peerRole() { return ownRole() === "A" ? "B" : "A"; }
function validatePeerSequence(value: unknown) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= lastPeerSequence) throw new Error("invalid_message_sequence");
  lastPeerSequence = parsed;
  return parsed;
}
function aad(kind: string, seq: number, role: string) { return `veilroom:v1:${sessionId.value}:${role}:${kind}:${seq}`; }
function humanError(caught: unknown) {
  const code = caught instanceof Error ? caught.message : "request_failed";
  const map: Record<string, string> = {
    session_unavailable: "此会话不存在、已被销毁或已过期。",
    session_locked: "此会话已经锁定，无法再加入。",
    session_closing: "此会话正在销毁，已安全拒绝操作。",
    encrypted_file_transfer_unavailable: "加密文件传输尚未配置安全对象存储。",
    invalid_invitation: "邀请链接无效或缺少本地密钥片段。",
  };
  return map[code] ?? "操作未完成。为保护隐私，系统没有保留任何待重试内容。";
}
</script>

<template>
  <main class="app-shell">
    <header class="topbar">
      <a class="brand" href="/" aria-label="VeilRoom 首页"><span class="brand-mark">V</span><span>veilroom</span></a>
      <span class="privacy-mark"><i></i> 零存储 · 端到端加密</span>
    </header>

    <section v-if="phase === 'home'" class="landing-grid">
      <div class="landing-copy">
        <p class="eyebrow">A private moment, by design</p>
        <h1>只留下此刻，<br><em>不留下痕迹。</em></h1>
        <p class="lede">为两个人设计的临时私密空间。无需账户，十分钟后自动消隐，聊天与文件仅以密文经过服务端。</p>
        <button class="primary-action" @click="createSession"><span>创建私密会话</span><b>→</b></button>
        <p class="fine-print">创建即代表你将通过可信渠道分享加密邀请链接。</p>
      </div>
      <aside class="join-card" aria-label="加入会话">
        <div class="card-orbit"></div>
        <p class="eyebrow">Have an invitation?</p>
        <h2>进入已开启的房间</h2>
        <label for="invite">邀请链接</label>
        <textarea id="invite" v-model="joinCode" placeholder="粘贴完整 VeilRoom 邀请链接" rows="3"></textarea>
        <button class="secondary-action" @click="useCode">验证并继续 <span>↗</span></button>
        <p class="key-note">链接的 <code>#</code> 后部分只留在你的浏览器中，不会发送到服务器。</p>
      </aside>
    </section>

    <section v-else-if="phase === 'joining'" class="decision-panel">
      <span class="veil-icon">◌</span>
      <p class="eyebrow">Private invitation detected</p>
      <h1>准备进入这段对话？</h1>
      <p>连接后会话立即锁定，之后不会接受第三人，也不允许重新加入。</p>
      <div class="decision-actions"><button class="primary-action" @click="joinSession">安全加入</button><a href="/">取消</a></div>
    </section>

    <section v-else-if="phase === 'room'" class="room-layout">
      <aside class="room-sidebar">
        <div>
          <p class="eyebrow">Ephemeral session</p>
          <h2>仅限两人</h2>
          <div class="timer-block" :class="{ warning: isClosing }"><span>剩余时间</span><strong>{{ formattedRemaining }}</strong><small>{{ status?.state === 'CLOSING' ? '会话即将消隐' : '最长 10 分钟' }}</small></div>
        </div>
        <div class="peer-state"><span class="presence" :class="{ online: status?.peerOnline }"></span><div><b>另一位参与者</b><p>{{ peerLabel }}</p></div></div>
        <div class="security-detail"><span>⌁</span><p><b>{{ isSecure ? '加密已验证' : '正在验证密钥' }}</b>你的密钥仅存在于此浏览器内存中。</p></div>
        <button class="leave-button" @click="leaveSession">离开并销毁访问权 <span>×</span></button>
      </aside>
      <article class="conversation">
        <div class="conversation-head"><div><p class="eyebrow">Veil Channel</p><h2>{{ status?.you === 'A' ? '你发起的会话' : '受邀会话' }}</h2></div><span class="locked">锁定</span></div>
        <div v-if="notice" class="notice">{{ notice }}</div>
        <div v-if="error" class="error-notice" role="alert">{{ error }}</div>
        <div class="message-stream" aria-live="polite">
          <div v-if="messages.length === 0" class="empty-state"><div class="signal">⌇</div><p>{{ isSecure ? '安全通道已建立。说点什么吧。' : '正在让两把密钥彼此确认。' }}</p></div>
          <div v-for="item in messages" :key="item.id" class="message-row" :class="item.sender">
            <div v-if="item.kind === 'message'" class="bubble">{{ item.text }}</div>
            <button v-else class="file-card" @click="item.sender === 'peer' && item.file && downloadFile(item.file)">
              <span class="file-symbol">↥</span><span><b>{{ item.file?.name }}</b><small>{{ Math.ceil((item.file?.size ?? 0) / 1024) }} KB · 已加密</small></span><i v-if="item.sender === 'peer'">下载</i>
            </button>
          </div>
        </div>
        <form class="composer" @submit.prevent="sendMessage">
          <label class="file-picker" :class="{ disabled: !canSendFile || sendingFile }" :title="canSendFile ? '加密并发送文件' : '文件传输仅会在可安全删除的对象存储配置后启用'"><input type="file" :disabled="!canSendFile || sendingFile" @change="sendFile" /><span>＋</span></label>
          <input v-model="message" :disabled="!canSend" maxlength="4096" placeholder="写下只属于此刻的话…" autocomplete="off" />
          <button type="submit" :disabled="!canSend || !message.trim()" aria-label="发送消息">↑</button>
        </form>
      </article>
      <section v-if="invitation" class="invite-drawer"><p><span>给另一位参与者的钥匙</span>分享此链接后，会话将锁定为两人。</p><div><code>{{ invitation }}</code><button @click="copyInvitation">复制</button></div></section>
    </section>

    <section v-else class="decision-panel ended"><span class="veil-icon">—</span><p class="eyebrow">Session sealed</p><h1>这段会话已消隐。</h1><p>本地密钥、访问能力和内存消息均已清除。任何加密文件也会进入删除流程。</p><a class="primary-action" href="/">开启新的会话</a></section>

    <p v-if="error && phase === 'home'" class="global-error" role="alert">{{ error }}</p>
  </main>
</template>
