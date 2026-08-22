<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import {
	bytesToBase64Url,
	base64UrlToBytes,
  createKeyPacket,
  decryptBytes,
  decryptJson,
  deriveSessionKey,
  encryptBytes,
  encryptJson,
  randomSecret,
  type KeyPacket,
} from "./lib/crypto";
import { addReceivedChunk, clearReceivedFiles, createReceivedFile, isComplete, type ReceivedFile } from "./lib/fileRelay";
import { ConnectionEpoch, resetSessionUrl } from "./lib/sessionLifecycle";

type Status = { state: "WAITING" | "LOCKED" | "CLOSING" | "DESTROYED"; expiresAt: number; destroyAt?: number; you: string; peerOnline: boolean; peerJoined: boolean; fileTransferAvailable: boolean; serverNow: number };
type FileMeta = { id: string; name: string; type: string; size: number; chunks?: number; state?: "sending" | "receiving" | "ready" };
type ChatItem = { id: string; sender: "you" | "peer"; kind: "message" | "file"; text?: string; file?: FileMeta };
type IncomingFile = ReceivedFile & { meta: FileMeta };

const directFileLimit = 2 * 1024 * 1024;
const directChunkSize = 24 * 1024;

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
const incomingFiles = new Map<string, IncomingFile>();
let incomingFrameQueue: Promise<void> = Promise.resolve();
const connectionEpoch = new ConnectionEpoch();
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
  prepareNewSession();
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
  const epoch = connectionEpoch.start();
  isSecure.value = false;
  sessionKey = null;
  const socketScheme = window.location.protocol === "https:" ? "wss" : "ws";
  const connection = new WebSocket(`${socketScheme}://${window.location.host}/api/ws?sessionId=${encodeURIComponent(sessionId.value)}&token=${encodeURIComponent(participantToken.value)}`);
  socket = connection;
  connection.onopen = async () => {
    if (!connectionEpoch.isCurrent(epoch) || socket !== connection) return;
    try {
      const keyMaterial = await createKeyPacket(sessionId.value, pairingSecret.value);
      privateKey = keyMaterial.privateKey;
      ownKeyPacket = keyMaterial.packet;
      sendKeyIfReady();
    } catch {
      if (connectionEpoch.isCurrent(epoch) && socket === connection) failSecurely("无法建立本地加密材料，已拒绝会话。");
    }
  };
  connection.onmessage = (event) => {
    if (!connectionEpoch.isCurrent(epoch) || socket !== connection) return;
    incomingFrameQueue = incomingFrameQueue
      .then(() => {
        if (!connectionEpoch.isCurrent(epoch) || socket !== connection) return;
        return handleIncoming(event.data);
      })
      .catch(() => { if (connectionEpoch.isCurrent(epoch) && socket === connection) failSecurely("检测到无效、重放或被篡改的数据，已终止会话。"); });
  };
  connection.onclose = () => {
    if (connectionEpoch.isCurrent(epoch) && socket === connection && phase.value === "room") {
      closeSocket();
      wipeLocalState();
      phase.value = "ended";
    }
  };
  connection.onerror = () => { if (connectionEpoch.isCurrent(epoch) && socket === connection) failSecurely("安全通道无法建立。未发送任何内容。"); };
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
    const payload = await decryptJson<{ kind: "file"; id: string; name: string; type: string; size: number; chunks: number }>(sessionKey, { nonce: String(event.nonce), ciphertext: String(event.ciphertext) }, aad("file-offer", peerSequence, peerRole()));
    if (!isSafeFileMeta(payload)) throw new Error("invalid_file_offer");
    const meta: FileMeta = { id: payload.id, name: payload.name, type: payload.type, size: payload.size, chunks: payload.chunks, state: "receiving" };
    incomingFiles.set(payload.id, { meta, ...createReceivedFile(payload.size, payload.chunks) });
    messages.value.push({ id: payload.id, sender: "peer", kind: "file", file: meta });
    return;
  }
  if (event.type === "file-chunk") {
    if (!sessionKey) throw new Error("not_secure");
    const peerSequence = validatePeerSequence(event.seq);
    const fileID = String(event.fileId);
    const index = Number(event.index);
    const transfer = incomingFiles.get(fileID);
    if (!transfer) throw new Error("invalid_file_chunk");
    const clearChunk = await decryptBytes(sessionKey, base64UrlToBytes(String(event.payload)).buffer, aad("file-chunk", peerSequence, peerRole(), fileID, index));
    if (clearChunk.byteLength === 0 || clearChunk.byteLength > directChunkSize) throw new Error("invalid_file_chunk_size");
    if (!addReceivedChunk(transfer, index, clearChunk)) throw new Error("invalid_file_chunk");
    if (isComplete(transfer)) markFileReady(fileID);
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
  if (file.size > directFileLimit) { error.value = "零持久化文件中继的单文件限制为 2 MB。"; return; }
  sendingFile.value = true;
  try {
    const id = crypto.randomUUID();
    const chunks = Math.ceil(file.size / directChunkSize);
    const seq = ++sequence;
    const offer = await encryptJson(sessionKey, { kind: "file", id, name: file.name, type: file.type || "application/octet-stream", size: file.size, chunks }, aad("file-offer", seq, ownRole()));
    socket?.send(JSON.stringify({ type: "file-offer", seq, ...offer }));
    messages.value.push({ id, sender: "you", kind: "file", file: { id, name: file.name, type: file.type, size: file.size, chunks, state: "sending" } });
    for (let index = 0; index < chunks; index += 1) {
      await waitForSocketCapacity();
      const chunk = await file.slice(index * directChunkSize, Math.min(file.size, (index + 1) * directChunkSize)).arrayBuffer();
      const chunkSequence = ++sequence;
      const encryptedChunk = await encryptBytes(sessionKey, chunk, aad("file-chunk", chunkSequence, ownRole(), id, index));
      socket?.send(JSON.stringify({ type: "file-chunk", seq: chunkSequence, fileId: id, index, payload: bytesToBase64Url(encryptedChunk) }));
    }
    updateFileState(id, "ready");
  } catch (caught) {
    error.value = humanError(caught);
  } finally {
    sendingFile.value = false;
  }
}

async function downloadFile(file: NonNullable<ChatItem["file"]>) {
  const transfer = incomingFiles.get(file.id);
  if (!transfer || !isComplete(transfer)) {
    error.value = "文件尚未完整抵达，无法安全下载。";
    return;
  }
  try {
    const anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(new Blob(transfer.chunks as BlobPart[], { type: file.type }));
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

function closeSocket() { connectionEpoch.invalidate(); const active = socket; socket = null; active?.close(); }
function prepareNewSession() {
  closeSocket();
  wipeLocalState();
  sessionId.value = "";
  invitation.value = "";
  joinCode.value = "";
  message.value = "";
  status.value = null;
  messages.value = [];
  notice.value = "";
  error.value = "";
  sendingFile.value = false;
  resetSessionUrl(window.history);
  phase.value = "home";
}
function sendKeyIfReady() {
  if (!ownKeyPacket || !status.value?.peerJoined || socket?.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({ type: "key", ...ownKeyPacket }));
}
function wipeLocalState() { privateKey = null; sessionKey = null; ownKeyPacket = null; clearReceivedFiles(incomingFiles); incomingFrameQueue = Promise.resolve(); participantToken.value = ""; pairingSecret.value = ""; sequence = 0; lastPeerSequence = 0; }
function failSecurely(reason: string) { error.value = reason; closeSocket(); wipeLocalState(); phase.value = "ended"; }
function ownRole() { return status.value?.you ?? "unknown"; }
function peerRole() { return ownRole() === "A" ? "B" : "A"; }
function validatePeerSequence(value: unknown) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= lastPeerSequence) throw new Error("invalid_message_sequence");
  lastPeerSequence = parsed;
  return parsed;
}
function aad(kind: string, seq: number, role: string, fileID = "", index = -1) { return `veilroom:v1:${sessionId.value}:${role}:${kind}:${seq}:${fileID}:${index}`; }
function isSafeFileMeta(value: { id: string; name: string; type: string; size: number; chunks: number }) {
  return typeof value.id === "string" && value.id.length > 0 && value.id.length < 128 && typeof value.name === "string" && value.name.length <= 512 && typeof value.type === "string" && value.type.length <= 256 && Number.isSafeInteger(value.size) && value.size > 0 && value.size <= directFileLimit && Number.isSafeInteger(value.chunks) && value.chunks === Math.ceil(value.size / directChunkSize);
}
function updateFileState(id: string, state: NonNullable<FileMeta["state"]>) {
  const item = messages.value.find((candidate) => candidate.id === id && candidate.kind === "file");
  if (item?.file) item.file.state = state;
}
function markFileReady(id: string) { updateFileState(id, "ready"); }
async function waitForSocketCapacity() {
  while (socket && socket.bufferedAmount > 512 * 1024) await new Promise((resolve) => window.setTimeout(resolve, 16));
  if (!socket || socket.readyState !== WebSocket.OPEN) throw new Error("session_closing");
}
function humanError(caught: unknown) {
  const code = caught instanceof Error ? caught.message : "request_failed";
  const map: Record<string, string> = {
    session_unavailable: "此会话不存在、已被销毁或已过期。",
    session_locked: "此会话已经锁定，无法再加入。",
    session_closing: "此会话正在销毁，已安全拒绝操作。",
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
              <span class="file-symbol">↥</span><span><b>{{ item.file?.name }}</b><small>{{ Math.ceil((item.file?.size ?? 0) / 1024) }} KB · {{ item.file?.state === 'receiving' ? '正在内存中接收' : item.file?.state === 'sending' ? '正在加密中继' : '已加密 · 不落盘' }}</small></span><i v-if="item.sender === 'peer'">{{ item.file?.state === 'ready' ? '下载' : '接收中' }}</i>
            </button>
          </div>
        </div>
        <form class="composer" @submit.prevent="sendMessage">
          <label class="file-picker" :class="{ disabled: !canSendFile || sendingFile }" :title="canSendFile ? '以端到端加密分片经内存中继发送文件' : '等待安全会话就绪'"><input type="file" :disabled="!canSendFile || sendingFile" @change="sendFile" /><span>＋</span></label>
          <input v-model="message" :disabled="!canSend" maxlength="4096" placeholder="写下只属于此刻的话…" autocomplete="off" />
          <button type="submit" :disabled="!canSend || !message.trim()" aria-label="发送消息">↑</button>
        </form>
      </article>
      <section v-if="invitation" class="invite-drawer"><p><span>给另一位参与者的钥匙</span>分享此链接后，会话将锁定为两人。</p><div><code>{{ invitation }}</code><button @click="copyInvitation">复制</button></div></section>
    </section>

    <section v-else class="decision-panel ended"><span class="veil-icon">—</span><p class="eyebrow">Session sealed</p><h1>这段会话已消隐。</h1><p>本地密钥、访问能力、内存消息与文件分片均已清除，服务器没有保留文件副本。</p><button class="primary-action" @click="createSession">开启新的会话</button></section>

    <p v-if="error && phase === 'home'" class="global-error" role="alert">{{ error }}</p>
  </main>
</template>
