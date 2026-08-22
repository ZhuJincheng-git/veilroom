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
import { clearExpiredSessionView, ConnectionEpoch } from "./lib/sessionLifecycle";
import { formatCountdown, sessionDeadline } from "./lib/countdown";
import { secondsUntilReturn } from "./lib/returnCountdown";
import { notificationDuration, type AppNotification, type NotificationKind } from "./lib/notification";

type Status = { state: "WAITING" | "LOCKED" | "CLOSING" | "DESTROYED"; expiresAt: number; destroyAt?: number; you: string; peerOnline: boolean; peerJoined: boolean; fileTransferAvailable: boolean; serverNow: number };
type FileMeta = { id: string; name: string; type: string; size: number; chunks?: number; state?: "sending" | "receiving" | "ready" };
type ChatItem = { id: string; sender: "you" | "peer"; kind: "message" | "file"; text?: string; file?: FileMeta };
type IncomingFile = ReceivedFile & { meta: FileMeta };
type ByteGlyph = { bit: "0" | "1"; x: number; y: number; changedAt: number; bright: boolean };

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
const toast = ref<AppNotification | null>(null);
const messages = ref<ChatItem[]>([]);
const now = ref(Date.now());
const isSecure = ref(false);
const sendingFile = ref(false);
const byteCanvas = ref<HTMLCanvasElement | null>(null);
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
let returnHomeTimer: number | undefined;
const returnHomeAt = ref<number | null>(null);
let toastTimer: number | undefined;
let toastSequence = 0;
let heartbeatTimer: number | undefined;
let byteAnimationFrame: number | undefined;
let byteResizeHandler: (() => void) | undefined;
let byteGlyphs: ByteGlyph[] = [];
let byteMaskCanvas: HTMLCanvasElement | null = null;
let byteMasks: Array<{ x: number; y: number; radius: number }> = [];

const countdownTarget = computed(() => sessionDeadline(status.value));
const remaining = computed(() => countdownTarget.value === null ? null : Math.max(0, countdownTarget.value - now.value));
const formattedRemaining = computed(() => formatCountdown(status.value, now.value));
const isClosing = computed(() => status.value?.state === "CLOSING" || (remaining.value !== null && remaining.value <= 60_000));
const peerLabel = computed(() => status.value?.peerOnline ? "在线且已加密" : status.value?.peerJoined ? "已加入，等待连接" : "等待受邀者");
const canSend = computed(() => isSecure.value && status.value?.state === "LOCKED" && status.value.peerOnline);
const canSendFile = computed(() => Boolean(canSend.value && status.value?.fileTransferAvailable));
const returnHomeSeconds = computed(() => secondsUntilReturn(returnHomeAt.value, now.value));
const isReadOnlyGrace = computed(() => status.value?.state === "CLOSING");

onMounted(() => {
  ticker = window.setInterval(() => { now.value = Date.now(); }, 250);
  initialiseByteField();
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
  clearReturnHomeTimer();
  clearToastTimer();
  clearHeartbeat();
  clearByteFieldTimer();
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
    notify(humanError(caught), "error");
  }
}

async function joinSession() {
  try {
    if (!sessionId.value || !pairingSecret.value) throw new Error("invalid_invitation");
    const response = await api(`/api/sessions/${encodeURIComponent(sessionId.value)}/join`, { method: "POST" });
    const data = await response.json() as { token: string };
    participantToken.value = data.token;
    phase.value = "room";
    await connect();
  } catch (caught) {
    notify(humanError(caught), "error");
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
    notify("请输入完整的 VeilRoom 邀请链接。密钥仅存在于浏览器中，不会发送到服务器。", "error");
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
      void hydrateStatus(epoch, connection);
      startHeartbeat(epoch, connection);
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
      endSession();
    }
  };
  connection.onerror = () => { if (connectionEpoch.isCurrent(epoch) && socket === connection) failSecurely("安全通道无法建立。未发送任何内容。"); };
}

async function hydrateStatus(epoch: number, connection: WebSocket) {
  try {
    const response = await api(`/api/sessions/${encodeURIComponent(sessionId.value)}/status`);
    const currentStatus = await response.json() as Status;
    if (connectionEpoch.isCurrent(epoch) && socket === connection) status.value = currentStatus;
  } catch (caught) {
    if (connectionEpoch.isCurrent(epoch) && socket === connection) failSecurely(humanError(caught));
  }
}

async function handleIncoming(raw: string) {
  const event = JSON.parse(raw) as Record<string, unknown>;
  if (event.type === "session-status") {
    status.value = event as unknown as Status;
    sendKeyIfReady();
    if (status.value.state === "CLOSING") notify("已有参与者离开；会话将在一分钟内销毁。", "warning");
    return;
  }
  if (event.type === "key") {
    if (!privateKey) throw new Error("missing_local_key");
    sessionKey = await deriveSessionKey(sessionId.value, pairingSecret.value, privateKey, { publicKey: String(event.publicKey), proof: String(event.proof) });
    isSecure.value = true;
    notify("端到端加密已验证。服务器只能看到密文。", "success");
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
  if (file.size > directFileLimit) { notify("零持久化文件中继的单文件限制为 2 MB。", "error"); return; }
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
    notify(humanError(caught), "error");
  } finally {
    sendingFile.value = false;
  }
}

async function downloadFile(file: NonNullable<ChatItem["file"]>) {
  const transfer = incomingFiles.get(file.id);
  if (!transfer || !isComplete(transfer)) {
    notify("文件尚未完整抵达，无法安全下载。", "warning");
    return;
  }
  try {
    const anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(new Blob(transfer.chunks as BlobPart[], { type: file.type }));
    anchor.download = file.name;
    anchor.click();
    URL.revokeObjectURL(anchor.href);
  } catch (caught) {
    notify(humanError(caught), "error");
  }
}

async function copyInvitation() {
  try { await navigator.clipboard.writeText(invitation.value); notify("邀请链接已复制。请仅通过可信渠道分享。", "success"); } catch { notify("复制失败，请手动复制邀请链接。", "error"); }
}

async function leaveSession() {
  const id = sessionId.value;
  const token = participantToken.value;
  closeSocket();
  if (id && token) {
    try { await fetch(`/api/sessions/${encodeURIComponent(id)}/leave`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, keepalive: true, cache: "no-store" }); } catch { /* close is still fail-safe */ }
  }
  endSession();
}

function closeSocket() { clearHeartbeat(); connectionEpoch.invalidate(); const active = socket; socket = null; active?.close(); }
function resetSessionView() {
  closeSocket();
  wipeLocalState();
  const cleared = clearExpiredSessionView(window.history);
  sessionId.value = cleared.sessionId;
  invitation.value = cleared.invitation;
  joinCode.value = cleared.joinCode;
  message.value = cleared.message;
  status.value = null;
  messages.value = cleared.messages;
  sendingFile.value = false;
}
function endSession() {
  resetSessionView();
  phase.value = "ended";
  scheduleReturnHome();
}
function prepareNewSession() {
  clearReturnHomeTimer();
  returnHomeAt.value = null;
  resetSessionView();
  phase.value = "home";
}
function sendKeyIfReady() {
  if (!ownKeyPacket || status.value?.state !== "LOCKED" || !status.value.peerJoined || socket?.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({ type: "key", ...ownKeyPacket }));
}
function scheduleReturnHome() {
  clearReturnHomeTimer();
  returnHomeAt.value = Date.now() + 3_000;
  returnHomeTimer = window.setTimeout(() => {
    returnHomeAt.value = null;
    phase.value = "home";
  }, 3_000);
}
function clearReturnHomeTimer() {
  if (returnHomeTimer !== undefined) window.clearTimeout(returnHomeTimer);
  returnHomeTimer = undefined;
}
function notify(message: string, kind: NotificationKind) {
  clearToastTimer();
  toast.value = { id: ++toastSequence, message, kind };
  toastTimer = window.setTimeout(() => { toast.value = null; toastTimer = undefined; }, notificationDuration);
}
function clearToastTimer() {
  if (toastTimer !== undefined) window.clearTimeout(toastTimer);
  toastTimer = undefined;
}
function startHeartbeat(epoch: number, connection: WebSocket) {
  clearHeartbeat();
  heartbeatTimer = window.setInterval(() => {
    if (!connectionEpoch.isCurrent(epoch) || socket !== connection || connection.readyState !== WebSocket.OPEN) return;
    connection.send(JSON.stringify({ type: "ping" }));
  }, 20_000);
}
function clearHeartbeat() {
  if (heartbeatTimer !== undefined) window.clearInterval(heartbeatTimer);
  heartbeatTimer = undefined;
}
function initialiseByteField() {
  const canvas = byteCanvas.value;
  if (!canvas) return;
  const context = canvas.getContext("2d");
  if (!context) return;
  const maskCanvas = document.createElement("canvas");
  const maskContext = maskCanvas.getContext("2d");
  if (!maskContext) return;
  byteMaskCanvas = maskCanvas;
  let width = 0;
  let height = 0;
  let lastMutation = 0;
  let lastMaskMove = 0;

  const setMaskPosition = () => {
    const position = (radiusRatio: number) => ({
      x: width * (.08 + Math.random() * .84),
      y: height * (-.16 + Math.random() * .58),
      radius: Math.min(width, height) * radiusRatio,
    });
    byteMasks = [position(.34), position(.24), position(.17)];
    maskContext.clearRect(0, 0, width, height);
    for (const mask of byteMasks) {
      const gradient = maskContext.createRadialGradient(mask.x, mask.y, mask.radius * .1, mask.x, mask.y, mask.radius);
      gradient.addColorStop(0, "rgba(0,0,0,1)");
      gradient.addColorStop(.5, "rgba(0,0,0,.82)");
      gradient.addColorStop(1, "rgba(0,0,0,0)");
      maskContext.fillStyle = gradient;
      maskContext.fillRect(mask.x - mask.radius, mask.y - mask.radius, mask.radius * 2, mask.radius * 2);
    }
  };
  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.ceil(width * dpr);
    canvas.height = Math.ceil(height * dpr);
    maskCanvas.width = Math.ceil(width * dpr);
    maskCanvas.height = Math.ceil(height * dpr);
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    maskContext.setTransform(dpr, 0, 0, dpr, 0, 0);
    const columns = Math.max(10, Math.ceil(width / 72));
    const rows = Math.max(10, Math.ceil(height / 43));
    byteGlyphs = Array.from({ length: columns * rows }, (_, index) => ({
      bit: Math.random() > .5 ? "1" : "0",
      x: ((index % columns) + .5) * (width / columns) + (Math.random() - .5) * 12,
      y: (Math.floor(index / columns) + .5) * (height / rows) + (Math.random() - .5) * 10,
      changedAt: performance.now() - 500,
      bright: Math.random() > .89,
    }));
    setMaskPosition();
  };
  const render = (timestamp: number) => {
    if (timestamp - lastMutation > 170) {
      const changes = Math.min(byteGlyphs.length, 18 + Math.floor(Math.random() * 22));
      for (let count = 0; count < changes; count += 1) {
        const glyph = byteGlyphs[Math.floor(Math.random() * byteGlyphs.length)];
        glyph.bit = glyph.bit === "0" ? "1" : "0";
        glyph.changedAt = timestamp;
        glyph.bright = Math.random() > .72;
      }
      lastMutation = timestamp;
    }
    if (timestamp - lastMaskMove > 1_100) { setMaskPosition(); lastMaskMove = timestamp; }
    context.clearRect(0, 0, width, height);
    context.font = "11px ui-monospace, SFMono-Regular, Menlo, monospace";
    context.textAlign = "center";
    context.textBaseline = "middle";
    for (const glyph of byteGlyphs) {
      const age = timestamp - glyph.changedAt;
      context.filter = age < 230 ? `blur(${Math.max(.2, 3 - age / 80)}px)` : "none";
      context.globalAlpha = glyph.bright ? .24 : .10;
      context.fillStyle = glyph.bright ? "#83f2d0" : "#d4eee6";
      context.fillText(glyph.bit, glyph.x, glyph.y);
    }
    if (byteMaskCanvas) {
      context.save();
      context.globalCompositeOperation = "destination-in";
      context.drawImage(byteMaskCanvas, 0, 0, width, height);
      context.restore();
    }
    context.filter = "none";
    context.globalAlpha = 1;
    if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) byteAnimationFrame = window.requestAnimationFrame(render);
  };
  byteResizeHandler = resize;
  window.addEventListener("resize", resize, { passive: true });
  resize();
  byteAnimationFrame = window.requestAnimationFrame(render);
}
function clearByteFieldTimer() {
  if (byteAnimationFrame !== undefined) window.cancelAnimationFrame(byteAnimationFrame);
  if (byteResizeHandler) window.removeEventListener("resize", byteResizeHandler);
  byteAnimationFrame = undefined;
  byteResizeHandler = undefined;
  byteGlyphs = [];
  byteMasks = [];
  byteMaskCanvas = null;
}
function wipeLocalState() { privateKey = null; sessionKey = null; ownKeyPacket = null; isSecure.value = false; clearReceivedFiles(incomingFiles); incomingFrameQueue = Promise.resolve(); participantToken.value = ""; pairingSecret.value = ""; sequence = 0; lastPeerSequence = 0; }
function failSecurely(reason: string) { notify(reason, "error"); endSession(); }
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
  <div class="app-root">
    <canvas ref="byteCanvas" class="byte-field" aria-hidden="true"></canvas>
    <main class="app-shell" :class="{ 'session-shell': phase === 'room', 'home-shell': phase === 'home' }">
    <header class="topbar">
      <a class="brand" href="/" aria-label="VeilRoom 首页"><span class="brand-mark"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5.5 9.7 18h4.6L20 5.5M8 5.5l4 8.7 4-8.7" /></svg></span><span>veilroom</span></a>
      <span class="topbar-signal" aria-hidden="true"><i></i><i></i><i></i></span>
    </header>

    <template v-if="phase === 'home'">
      <section class="hero-section">
        <div class="hero-copy">
          <p class="eyebrow"><span class="hash-cursor">01</span> PRIVATE BY DEFAULT</p>
          <h1>只属于此刻。<br><em>只属于两人。</em></h1>
          <p class="lede">创建一段会自行消隐的对话。</p>
          <div class="hero-actions"><button class="primary-action" @click="createSession"><span>创建私密会话</span><b>→</b></button><span class="action-hint">分享一把短暂的钥匙</span></div>
        </div>
        <aside class="join-card" aria-label="加入会话">
          <span class="card-index">// INVITE</span>
          <h2>已有一把钥匙</h2>
          <label class="sr-only" for="invite">邀请链接</label>
          <textarea id="invite" v-model="joinCode" placeholder="粘贴邀请链接" rows="3"></textarea>
          <button class="secondary-action" @click="useCode"><span>进入会话</span><b>↗</b></button>
        </aside>
      </section>
      <section class="home-section why-section" aria-labelledby="why-title">
        <div class="section-heading"><p class="eyebrow">02 / WHY VEILROOM</p><h2 id="why-title">把一段对话，<em>留在当下。</em></h2></div>
        <div class="principle-grid">
          <article class="principle-card"><span class="card-code">01</span><h3>不用留下身份</h3><p>没有账户，没有联系人列表。创建即开始。</p></article>
          <article class="principle-card"><span class="card-code">02</span><h3>只为两个人</h3><p>第二位参与者到达后，入口安静关闭。</p></article>
          <article class="principle-card"><span class="card-code">03</span><h3>自然地消隐</h3><p>时间走完，访问能力与本地内容一起归零。</p></article>
        </div>
      </section>
      <section class="home-section security-section" aria-labelledby="security-title">
        <div class="section-heading"><p class="eyebrow">03 / SECURITY PATH</p><h2 id="security-title">安全性，不应打断<br><em>你的表达。</em></h2></div>
        <div class="security-map" aria-label="端到端加密流程">
          <div class="security-node"><span>01</span><b>浏览器加密</b><small>内容先于传输被封存</small></div><i></i>
          <div class="security-node"><span>02</span><b>仅转发密文</b><small>服务只负责抵达</small></div><i></i>
          <div class="security-node"><span>03</span><b>内存归零</b><small>结束即不再保留</small></div>
        </div>
      </section>
    </template>

    <section v-else-if="phase === 'joining'" class="decision-panel">
      <span class="veil-icon">◌</span>
      <p class="eyebrow">Private invitation detected</p>
      <h1>准备进入这段对话？</h1>
      <p>连接后会话立即锁定，之后不会接受第三人，也不允许重新加入。</p>
      <div class="decision-actions"><button class="primary-action" @click="joinSession">安全加入</button><a href="/">取消</a></div>
    </section>

    <section v-else-if="phase === 'room'" class="room-layout">
      <aside class="room-sidebar">
        <div class="room-status-head"><span class="card-index">// SESSION</span><span class="session-hash">{{ status?.you === 'A' ? 'A/02' : 'B/02' }}</span></div>
        <div class="timer-block" :class="{ warning: isClosing }"><span>{{ isReadOnlyGrace ? '留存窗口' : '剩余时间' }}</span><strong>{{ formattedRemaining }}</strong><small>{{ isReadOnlyGrace ? '静待会话归零' : !status ? '状态同步中' : ' ' }}</small></div>
        <div class="peer-state"><span class="presence" :class="{ online: status?.peerOnline }"></span><div><b>{{ status?.peerOnline ? '已连接' : isReadOnlyGrace ? '对方已离开' : '等待连接' }}</b><p>{{ isSecure ? '密钥已确认' : '正在交换密钥' }}</p></div></div>
        <div class="room-spacer"></div>
        <div class="protocol-line"><span>⌁</span><code>{{ isSecure ? 'a9:7f:02:cc' : '············' }}</code></div>
        <button class="leave-button" @click="leaveSession"><span>离开</span><b>↗</b></button>
      </aside>
      <article class="conversation">
        <div class="conversation-head"><div><p class="eyebrow">VEIL CHANNEL</p><h2>{{ isReadOnlyGrace ? '会话将在此刻结束' : status?.you === 'A' ? '你的会话' : '受邀会话' }}</h2></div><span class="locked" :class="{ warning: isReadOnlyGrace }">{{ isReadOnlyGrace ? '留存中' : '02/02' }}</span></div>
        <div class="message-stream" aria-live="polite">
          <div v-if="messages.length === 0" class="empty-state"><div class="signal">01 01 00</div><p>{{ isReadOnlyGrace ? '这段会话正在安静留存。' : isSecure ? '安全通道已建立。' : '正在确认密钥。' }}</p></div>
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
      <section v-if="invitation" class="invite-drawer"><span class="card-index">// SHARE</span><div><code>{{ invitation }}</code><button @click="copyInvitation" aria-label="复制邀请链接">复制</button></div></section>
    </section>

    <section v-else class="decision-panel ended"><span class="veil-icon">—</span><p class="eyebrow">Session sealed</p><h1>会话已销毁</h1><p class="eyebrow">{{ returnHomeSeconds }} 秒后返回首页</p></section>

    </main>
    <Teleport to="body">
      <Transition name="toast">
        <div v-if="toast" :key="toast.id" class="global-toast" :class="toast.kind" role="status" aria-live="polite">
          <span class="toast-glyph">{{ toast.kind === 'success' ? '✓' : toast.kind === 'warning' ? '!' : '×' }}</span>
          <p>{{ toast.message }}</p>
          <i class="toast-progress"></i>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>
