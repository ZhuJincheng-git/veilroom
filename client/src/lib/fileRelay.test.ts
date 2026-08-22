import { describe, expect, it } from "vitest";
import { addReceivedChunk, clearReceivedFiles, createReceivedFile, isComplete } from "./fileRelay";

describe("in-memory file relay", () => {
  it("accepts each chunk once and clears all references on session destruction", () => {
    const transfer = createReceivedFile(4, 2);
    expect(addReceivedChunk(transfer, 0, new Uint8Array([1, 2]).buffer)).toBe(true);
    expect(addReceivedChunk(transfer, 0, new Uint8Array([3]).buffer)).toBe(false);
    expect(addReceivedChunk(transfer, 1, new Uint8Array([3, 4]).buffer)).toBe(true);
    expect(isComplete(transfer)).toBe(true);

    const files = new Map([["file-1", transfer]]);
    clearReceivedFiles(files);
    expect(files.size).toBe(0);
  });
});
