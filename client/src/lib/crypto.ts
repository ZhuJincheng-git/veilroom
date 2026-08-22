export type KeyPacket = { publicKey: string; proof: string };

const encoder = new TextEncoder();
const decoder = new TextDecoder();
type CryptoBytes = Uint8Array<ArrayBuffer>;

function copyBytes(value: Uint8Array | ArrayBuffer): CryptoBytes {
  const source = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
  const copy = new Uint8Array(source.byteLength);
  copy.set(source);
  return copy;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBytes(value: string): CryptoBytes {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return copyBytes(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

export function randomSecret(): string {
  const value = new Uint8Array(32);
  crypto.getRandomValues(value);
  return bytesToBase64Url(value);
}

async function proofFor(secret: CryptoBytes, sessionId: string, publicKey: CryptoBytes): Promise<string> {
  const hmac = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prefix = encoder.encode(`veilroom:v1:${sessionId}:`);
  const payload = new Uint8Array(prefix.length + publicKey.length);
  payload.set(prefix);
  payload.set(publicKey, prefix.length);
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, payload)));
}

export async function createKeyPacket(sessionId: string, pairingSecret: string): Promise<{ privateKey: CryptoKey; packet: KeyPacket }> {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const publicKey = copyBytes(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const secret = base64UrlToBytes(pairingSecret);
  return {
    privateKey: keyPair.privateKey,
    packet: { publicKey: bytesToBase64Url(publicKey), proof: await proofFor(secret, sessionId, publicKey) },
  };
}

export async function deriveSessionKey(
  sessionId: string,
  pairingSecret: string,
  privateKey: CryptoKey,
  peer: KeyPacket,
): Promise<CryptoKey> {
  const secret = base64UrlToBytes(pairingSecret);
  const peerBytes = base64UrlToBytes(peer.publicKey);
  const expectedProof = await proofFor(secret, sessionId, peerBytes);
  if (!constantTimeEqual(expectedProof, peer.proof)) throw new Error("Invitation proof verification failed");
  const peerKey = await crypto.subtle.importKey("raw", peerBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerKey }, privateKey, 256);
  const material = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: secret, info: copyBytes(encoder.encode(`veilroom:v1:${sessionId}`)) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptJson(key: CryptoKey, value: unknown, aad: string): Promise<{ nonce: string; ciphertext: string }> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: encoder.encode(aad) }, key, encoder.encode(JSON.stringify(value)));
  return { nonce: bytesToBase64Url(nonce), ciphertext: bytesToBase64Url(new Uint8Array(cipher)) };
}

export async function decryptJson<T>(key: CryptoKey, encrypted: { nonce: string; ciphertext: string }, aad: string): Promise<T> {
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(encrypted.nonce), additionalData: encoder.encode(aad) },
    key,
    base64UrlToBytes(encrypted.ciphertext),
  );
  return JSON.parse(decoder.decode(clear)) as T;
}

export async function encryptBytes(key: CryptoKey, bytes: ArrayBuffer, aad: string): Promise<CryptoBytes> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const cipher = copyBytes(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: copyBytes(encoder.encode(aad)) }, key, bytes));
  const encrypted = new Uint8Array(nonce.length + cipher.length);
  encrypted.set(nonce);
  encrypted.set(cipher, nonce.length);
  return copyBytes(encrypted);
}

export async function decryptBytes(key: CryptoKey, bytes: ArrayBuffer, aad: string): Promise<ArrayBuffer> {
  const encrypted = copyBytes(bytes);
  if (encrypted.length <= 12) throw new Error("Encrypted file is invalid");
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: copyBytes(encrypted.slice(0, 12)), additionalData: copyBytes(encoder.encode(aad)) }, key, copyBytes(encrypted.slice(12)));
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let result = 0;
  for (let index = 0; index < left.length; index += 1) result |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return result === 0;
}
