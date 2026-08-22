import { describe, expect, it, vi } from "vitest";
import { ConnectionEpoch, resetSessionUrl } from "./sessionLifecycle";

describe("session lifecycle navigation", () => {
  it("invalidates callbacks from a destroyed session before a new one begins", () => {
    const lifecycle = new ConnectionEpoch();
    const destroyedSession = lifecycle.start();
    lifecycle.invalidate();
    const newSession = lifecycle.start();

    expect(lifecycle.isCurrent(destroyedSession)).toBe(false);
    expect(lifecycle.isCurrent(newSession)).toBe(true);
  });

  it("replaces the destroyed session address with the homepage before creation", () => {
    const replaceState = vi.fn();
    resetSessionUrl({ replaceState });
    expect(replaceState).toHaveBeenCalledWith({}, "", "/");
  });
});
