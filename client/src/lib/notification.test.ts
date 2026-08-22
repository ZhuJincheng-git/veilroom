import { describe, expect, it } from "vitest";
import { notificationDuration } from "./notification";

describe("global notification timing", () => {
  it("keeps notifications visible for three seconds", () => {
    expect(notificationDuration).toBe(3_000);
  });
});
