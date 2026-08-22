import { describe, expect, it } from "vitest";
import { createKeyPacket, decryptJson, deriveSessionKey, encryptJson, randomSecret } from "./crypto";

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
});
