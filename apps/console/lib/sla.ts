export interface Countdown {
  /** Milliseconds left; negative when overdue. */
  ms: number;
  label: string;
  state: "ok" | "urgent" | "overdue";
}

export function countdown(deadlineIso: string, now: number): Countdown {
  const t = Date.parse(deadlineIso);
  if (Number.isNaN(t)) return { ms: 0, label: "unknown", state: "overdue" };
  const ms = t - now;
  const abs = Math.abs(ms);
  const h = Math.floor(abs / 3_600_000);
  const m = Math.floor((abs % 3_600_000) / 60_000);
  const s = Math.floor((abs % 60_000) / 1000);
  const text = h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
  if (ms < 0) return { ms, label: `overdue by ${text}`, state: "overdue" };
  return { ms, label: `${text} left`, state: ms < 15 * 60_000 ? "urgent" : "ok" };
}
