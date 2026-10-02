import { BillingError } from "./errors.js";
import { PERIOD_RE } from "./types.js";

export type Granularity = "hour" | "day" | "month";

/** Billing period id (a UTC calendar month) of an instant. */
export function periodIdOf(t: Date): string {
  return `${String(t.getUTCFullYear()).padStart(4, "0")}-${String(t.getUTCMonth() + 1).padStart(2, "0")}`;
}

export function parsePeriod(id: string): { year: number; month: number } {
  if (!PERIOD_RE.test(id)) throw new BillingError("INVALID", "period must be YYYY-MM");
  return { year: Number(id.slice(0, 4)), month: Number(id.slice(5, 7)) };
}

/** [start, end) in UTC. */
export function periodBounds(id: string): { start: Date; end: Date } {
  const { year, month } = parsePeriod(id);
  return {
    start: new Date(Date.UTC(year, month - 1, 1)),
    end: new Date(Date.UTC(year, month, 1)),
  };
}

export function nextPeriod(id: string): string {
  return periodIdOf(periodBounds(id).end);
}

export function periodSeconds(id: string): bigint {
  const { start, end } = periodBounds(id);
  return BigInt((end.getTime() - start.getTime()) / 1000);
}

/** Start of the UTC bucket containing `t`, as an ISO string. */
export function bucketStart(t: Date, g: Granularity): string {
  const y = t.getUTCFullYear();
  const m = t.getUTCMonth();
  const d = t.getUTCDate();
  const h = t.getUTCHours();
  const ms =
    g === "hour" ? Date.UTC(y, m, d, h) : g === "day" ? Date.UTC(y, m, d) : Date.UTC(y, m, 1);
  return new Date(ms).toISOString();
}

/**
 * The period an event counts in: its own month, unless that month (or any following one) is sealed, in which case the first
 * unsealed later month. Closed periods therefore never change; a late event becomes an adjustment of the next period.
 */
export function attributePeriod(
  eventTime: Date,
  sealed: ReadonlySet<string>,
): { periodId: string; originalPeriodId: string | null } {
  const own = periodIdOf(eventTime);
  let p = own;
  while (sealed.has(p)) p = nextPeriod(p);
  return { periodId: p, originalPeriodId: p === own ? null : own };
}
