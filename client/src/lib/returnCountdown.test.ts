import { describe, expect, it } from "vitest";
import { secondsUntilReturn } from "./returnCountdown";

describe("destroyed-session return countdown", () => {
  it("counts down three seconds without going negative", () => {
    expect(secondsUntilReturn(3_000, 0)).toBe(3);
    expect(secondsUntilReturn(3_000, 2_001)).toBe(1);
    expect(secondsUntilReturn(3_000, 3_001)).toBe(0);
  });
});
