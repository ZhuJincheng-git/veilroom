import { describe, expect, it } from "vitest";
import { formatCountdown, sessionDeadline } from "./countdown";

describe("session countdown readiness", () => {
  it("never presents an unsynchronized new session as zero seconds", () => {
    expect(sessionDeadline(null)).toBeNull();
    expect(formatCountdown(null, 100)).toBe("—:—");
  });

  it("uses the server-provided absolute expiry until a nearer destruction deadline exists", () => {
    expect(formatCountdown({ expiresAt: 610_000 }, 10_000)).toBe("10:00");
    expect(formatCountdown({ expiresAt: 610_000, destroyAt: 70_000 }, 10_000)).toBe("1:00");
  });
});
