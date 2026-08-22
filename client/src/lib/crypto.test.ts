import { describe, expect, it } from "vitest";
import { createKeyPacket, decryptBytes, decryptJson, deriveSessionKey, encryptBytes, encryptJson, randomSecret } from "./crypto";

describe("VeilRoom browser encryption", () => {
  it("derives equal non-extractable session keys only when both peers hold the invitation secret", async () => {
    const sessionId = "session-for-test";
    const secret = randomSecret();
    const first = await createKeyPacket(sessionId, secret);
    const second = await createKeyPacket(sessionId, secret);

    const firstKey = await deriveSessionKey(sessionId, secret, first.privateKey, second.packet);
    const secondKey = await deriveSessionKey(sessionId, secret, second.privateKey, first.packet);
    const encrypted = await encryptJson(firstKey, { message: "never reaches the relay in plaintext" }, "veilroom:test:A:message:1");

    await expect(decryptJson<{ message: string }>(secondKey, encrypted, "veilroom:test:A:message:1")).resolves.toEqual({
      message: "never reaches the relay in plaintext",
    });
    await expect(decryptJson(secondKey, encrypted, "veilroom:test:B:message:1")).rejects.toThrow();
    await expect(deriveSessionKey(sessionId, randomSecret(), second.privateKey, first.packet)).rejects.toThrow("Invitation proof verification failed");
  });

  it("keeps each encrypted file chunk bound to its file and index", async () => {
    const sessionId = "file-relay-test";
    const secret = randomSecret();
    const first = await createKeyPacket(sessionId, secret);
    const second = await createKeyPacket(sessionId, secret);
    const senderKey = await deriveSessionKey(sessionId, secret, first.privateKey, second.packet);
    const receiverKey = await deriveSessionKey(sessionId, secret, second.privateKey, first.packet);
    const data = new TextEncoder().encode("private file chunk").buffer;
    const encrypted = await encryptBytes(senderKey, data, "veilroom:v1:file-relay-test:A:file-chunk:2:file-1:0");

    await expect(decryptBytes(receiverKey, encrypted.buffer, "veilroom:v1:file-relay-test:A:file-chunk:2:file-1:0")).resolves.toEqual(data);
    await expect(decryptBytes(receiverKey, encrypted.buffer, "veilroom:v1:file-relay-test:A:file-chunk:2:file-1:1")).rejects.toThrow();
  });
});
