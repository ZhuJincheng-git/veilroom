export class ConnectionEpoch {
  private value = 0;

  start(): number {
    this.value += 1;
    return this.value;
  }

  invalidate(): void {
    this.value += 1;
  }

  isCurrent(candidate: number): boolean {
    return candidate === this.value;
  }
}

export function resetSessionUrl(history: Pick<History, "replaceState">): void {
  history.replaceState({}, "", "/");
}
