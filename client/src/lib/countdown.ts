export type CountdownStatus = { expiresAt: number; destroyAt?: number };

export function sessionDeadline(status: CountdownStatus | null): number | null {
  if (!status || !Number.isFinite(status.expiresAt) || status.expiresAt <= 0) return null;
  return Math.min(status.expiresAt, status.destroyAt && status.destroyAt > 0 ? status.destroyAt : Number.POSITIVE_INFINITY);
}

export function formatCountdown(status: CountdownStatus | null, now: number): string {
  const deadline = sessionDeadline(status);
  if (deadline === null) return "—:—";
  const seconds = Math.max(0, Math.ceil((deadline - now) / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}
