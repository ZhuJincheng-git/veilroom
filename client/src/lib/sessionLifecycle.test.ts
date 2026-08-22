import { describe, expect, it, vi } from "vitest";
import { clearExpiredSessionView, ConnectionEpoch, resetSessionUrl } from "./sessionLifecycle";

describe("session lifecycle navigation", () => {
  it("invalidates callbacks from a destroyed session before a new one begins", () => {
    const lifecycle = new ConnectionEpoch();
    const destroyedSession = lifecycle.start();
    lifecycle.invalidate();
    const newSession = lifecycle.start();

    expect(lifecycle.isCurrent(destroyedSession)).toBe(false);
    expect(lifecycle.isCurrent(newSession)).toBe(true);
  });

  it("replaces the timed-out session address with the homepage before creation or refresh", () => {
    const replaceState = vi.fn();
    resetSessionUrl({ replaceState });
    expect(replaceState).toHaveBeenCalledWith({}, "", "/");
  });

  it("clears every visible session reference when an expiry closes the connection", () => {
    const replaceState = vi.fn();
    expect(clearExpiredSessionView({ replaceState })).toEqual({
      sessionId: "", invitation: "", joinCode: "", message: "", notice: "", messages: [],
    });
    expect(replaceState).toHaveBeenCalledWith({}, "", "/");
  });
});
