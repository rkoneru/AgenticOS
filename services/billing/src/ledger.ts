import { BillingError } from "./errors.js";
import { periodBounds, bucketStart, type Granularity } from "./periods.js";
import type { PeriodSeal, SealVerdict } from "./seal.js";
import {
  RATE_DIMENSION,
  type AdjustmentInput,
  type AppendResult,
  type ConflictReport,
  type Meter,
  type UsageEntry,
  type UsageInput,
} from "./types.js";

/** Where producers write. Implementations: PgUsageLedger, MemoryUsageLedger, FanoutSink (+ analytics sinks). */
export interface UsageSink {
  append(
    input: UsageInput | (AdjustmentInput & { entryType: "adjustment" }),
  ): Promise<AppendResult>;
}

/** One rated total: a meter, split by the dimension it is rated by (model class, tool kind), or "" when none. */
export interface TotalRow {
  meter: Meter;
  dimension: string;
  quantity: bigint;
}

export interface RollupRow {
  bucket: string;
  meter: Meter;
  quantity: bigint;
}

export interface UsageLedger extends UsageSink {
  entries(tenantId: string, filter?: { periodId?: string; meter?: Meter }): Promise<UsageEntry[]>;
  /** Totals of one billing period (adjustments included), grouped by meter and rate dimension. */
  totals(tenantId: string, periodId: string): Promise<TotalRow[]>;
  /** Totals by UTC bucket of the EVENT time (informational; billing uses periods). */
  rollup(
    tenantId: string,
    q: { granularity: Granularity; from: Date; to: Date; meter?: Meter },
  ): Promise<RollupRow[]>;
  closePeriod(tenantId: string, periodId: string): Promise<PeriodSeal>;
  seals(tenantId: string): Promise<PeriodSeal[]>;
  verifySeal(tenantId: string, periodId: string): Promise<SealVerdict>;
  conflicts(tenantId: string): Promise<ConflictReport[]>;
}

/** Folds entries into rated totals; shared by every implementation so they cannot drift. */
export function foldTotals(
  entries: Iterable<{
    meter: Meter;
    quantity: bigint;
    dimensions: Readonly<Record<string, string>>;
  }>,
): TotalRow[] {
  const acc = new Map<string, TotalRow>();
  for (const e of entries) {
    const dim = RATE_DIMENSION[e.meter];
    const dimension = dim === undefined ? "" : (e.dimensions[dim] ?? "unknown");
    const k = `${e.meter}\u0000${dimension}`;
    const cur = acc.get(k);
    if (cur) cur.quantity += e.quantity;
    else acc.set(k, { meter: e.meter, dimension, quantity: e.quantity });
  }
  return [...acc.values()].sort((a, b) =>
    a.meter === b.meter ? a.dimension.localeCompare(b.dimension) : a.meter.localeCompare(b.meter),
  );
}

export function foldRollup(
  entries: Iterable<{ meter: Meter; quantity: bigint; eventTime: Date }>,
  q: { granularity: Granularity; from: Date; to: Date; meter?: Meter },
): RollupRow[] {
  const acc = new Map<string, RollupRow>();
  for (const e of entries) {
    if (e.eventTime < q.from || e.eventTime >= q.to) continue;
    if (q.meter !== undefined && e.meter !== q.meter) continue;
    const bucket = bucketStart(e.eventTime, q.granularity);
    const k = `${bucket}\u0000${e.meter}`;
    const cur = acc.get(k);
    if (cur) cur.quantity += e.quantity;
    else acc.set(k, { bucket, meter: e.meter, quantity: e.quantity });
  }
  return [...acc.values()].sort((a, b) =>
    a.bucket === b.bucket ? a.meter.localeCompare(b.meter) : a.bucket.localeCompare(b.bucket),
  );
}

export function assertClosable(periodId: string, now: Date): void {
  if (now < periodBounds(periodId).end)
    throw new BillingError("PERIOD_NOT_CLOSABLE", "period has not ended yet");
}
