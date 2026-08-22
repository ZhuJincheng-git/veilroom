export type ReceivedFile = {
  size: number;
  chunks: Array<ArrayBuffer | undefined>;
  received: number;
};

export function createReceivedFile(size: number, chunkCount: number): ReceivedFile {
  return { size, chunks: new Array(chunkCount), received: 0 };
}

export function addReceivedChunk(transfer: ReceivedFile, index: number, chunk: ArrayBuffer): boolean {
  if (!Number.isSafeInteger(index) || index < 0 || index >= transfer.chunks.length || transfer.chunks[index] || chunk.byteLength === 0) return false;
  transfer.chunks[index] = chunk;
  transfer.received += 1;
  return true;
}

export function isComplete(transfer: ReceivedFile): boolean {
  return transfer.received === transfer.chunks.length && transfer.chunks.every((chunk) => chunk instanceof ArrayBuffer);
}

export function clearReceivedFiles(files: Map<string, ReceivedFile>): void {
  files.clear();
}
