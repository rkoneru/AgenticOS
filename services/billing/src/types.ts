import { createHash } from "node:crypto";
import { canonicalize } from "@axis/contracts";
import { BillingError } from "./errors.js";

/**
 * Meters. A quantity is an INTEGER in the meter's smallest unit (no floats anywhere in the ledger):
 *   tokens_in / tokens_out   tokens
 *   runtime_seconds          milliseconds of a process in the RUNNING state
 *   tool_executions          executions (count)
 *   voice_minutes            milliseconds of call time
 *   storage_gb_hours         milli-GB-hours (1 GB = 10^9 bytes)
 *   marketplace_installs     installs (count)
 * Prices are expressed per N base units (see pricing.ts), so $0.10 per million tokens is exact.
 */
export const METERS = [
  "tokens_in",
  "tokens_out",
  "runtime_seconds",
  "tool_executions",
  "voice_minutes",
  "storage_gb_hours",
  "marketplace_installs",
] as const;
export type Meter = (typeof METERS)[number];

export const METER_UNITS: Readonly<Record<Meter, string>> = {
  tokens_in: "token",
  tokens_out: "token",
  runtime_seconds: "ms",
  tool_executions: "execution",
  voice_minutes: "ms",
  storage_gb_hours: "milli-GB-hour",
  marketplace_installs: "install",
};

/** The dimension a meter is RATED by (price differs per value). Other dimensions are for analysis only. */
export const RATE_DIMENSION: Readonly<Partial<Record<Meter, string>>> = {
  tokens_in: "model_class",
  tokens_out: "model_class",
  tool_executions: "tool_kind",
};

export const MAX_QUANTITY = BigInt(Number.MAX_SAFE_INTEGER);
export const MAX_FUTURE_SKEW_MS = 5 * 60_000;

export type Dimensions = Readonly<Record<string, string>>;
export type EntryType = "usage" | "adjustment";

export interface UsageInput {
  tenantId: string;
  /** Unique per (tenant, source event). A replay with the same key and payload is a no-op. */
  idempotencyKey: string;
  meter: Meter;
  /** Non-negative integer, at most 2^53-1. */
  quantity: bigint;
  /** When the usage happened (UTC). Never in the future beyond a small skew. */
  eventTime: Date;
  dimensions?: Dimensions;
  /** Free label of the producer, e.g. `runtime`, `storage-sampler`. */
  source: string;
}

/** A compensating entry. The original is never touched; the correction is a new signed entry with a reason. */
export interface AdjustmentInput extends Omit<UsageInput, "quantity"> {
  /** Signed, non-zero. */
  quantity: bigint;
  reason: string;
  actor: string;
  correctsKey?: string;
}

export interface UsageEntry {
  tenantId: string;
  id: string;
  idempotencyKey: string;
  payloadHash: string;
  entryType: EntryType;
  meter: Meter;
  quantity: bigint;
  eventTime: Date;
  recordedAt: Date;
  /** Billing period (UTC month, `YYYY-MM`) the entry counts in. */
  periodId: string;
  /** Set when the event time falls in a sealed period: the entry counts in a later one. */
  originalPeriodId: string | null;
  dimensions: Dimensions;
  source: string;
  reason: string | null;
  actor: string | null;
  correctsKey: string | null;
}

export interface ConflictReport {
  tenantId: string;
  idempotencyKey: string;
  existingPayloadHash: string;
  offeredPayloadHash: string;
  source: string;
  detectedAt: Date;
}

export type AppendResult =
  | { status: "inserted"; entry: UsageEntry }
  | { status: "duplicate"; entry: UsageEntry }
  | { status: "conflict"; conflict: ConflictReport };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIM_KEY_RE = /^[a-z][a-z0-9_]{0,31}$/;
export const PERIOD_RE = /^\d{4}-(0[1-9]|1[0-2])$/;

export const isMeter = (v: unknown): v is Meter =>
  typeof v === "string" && (METERS as readonly string[]).includes(v);

export function assertTenant(id: unknown): asserts id is string {
  if (typeof id !== "string" || !UUID_RE.test(id))
    throw new BillingError("INVALID", "tenantId must be a UUID");
}

function assertText(v: unknown, what: string, min: number, max: number): asserts v is string {
  if (typeof v !== "string" || v.length < min || v.length > max || v.includes("\u0000"))
    throw new BillingError("INVALID", `${what} must be a string of ${min}..${max} characters`);
}

export function normalizeDimensions(d: unknown): Dimensions {
  if (d === undefined) return {};
  if (typeof d !== "object" || d === null || Array.isArray(d))
    throw new BillingError("INVALID", "dimensions must be an object");
  const entries = Object.entries(d as Record<string, unknown>);
  if (entries.length > 8) throw new BillingError("INVALID", "at most 8 dimensions");
  const out: Record<string, string> = {};
  for (const [k, v] of entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!DIM_KEY_RE.test(k)) throw new BillingError("INVALID", `bad dimension key ${k}`);
    assertText(v, `dimension ${k}`, 1, 128);
    out[k] = v;
  }
  return out;
}

export type AnyInput =
  (UsageInput & { entryType?: "usage" }) | (AdjustmentInput & { entryType: "adjustment" });

export interface ValidInput {
  tenantId: string;
  idempotencyKey: string;
  entryType: EntryType;
  meter: Meter;
  quantity: bigint;
  eventTime: Date;
  dimensions: Dimensions;
  source: string;
  reason: string | null;
  actor: string | null;
  correctsKey: string | null;
}

/** Validates one ledger input. Throws BillingError("INVALID"). `now` bounds the event time from above. */
export function validateInput(input: AnyInput, now: Date): ValidInput {
  assertTenant(input.tenantId);
  assertText(input.idempotencyKey, "idempotencyKey", 1, 512);
  assertText(input.source, "source", 1, 64);
  if (!isMeter(input.meter)) throw new BillingError("INVALID", "unknown meter");
  if (typeof input.quantity !== "bigint")
    throw new BillingError("INVALID", "quantity must be a bigint integer");
  if (input.quantity > MAX_QUANTITY || input.quantity < -MAX_QUANTITY)
    throw new BillingError("INVALID", "quantity exceeds 2^53-1");
  if (!(input.eventTime instanceof Date) || Number.isNaN(input.eventTime.getTime()))
    throw new BillingError("INVALID", "eventTime must be a valid Date");
  if (input.eventTime.getTime() > now.getTime() + MAX_FUTURE_SKEW_MS)
    throw new BillingError("INVALID", "eventTime is in the future");
  const dimensions = normalizeDimensions(input.dimensions);
  if (input.entryType === "adjustment") {
    if (input.quantity === 0n) throw new BillingError("INVALID", "an adjustment must be non-zero");
    assertText(input.reason, "reason", 3, 1000);
    assertText(input.actor, "actor", 1, 256);
    if (input.correctsKey !== undefined) assertText(input.correctsKey, "correctsKey", 1, 512);
    return {
      tenantId: input.tenantId,
      idempotencyKey: input.idempotencyKey,
      entryType: "adjustment",
      meter: input.meter,
      quantity: input.quantity,
      eventTime: input.eventTime,
      dimensions,
      source: input.source,
      reason: input.reason,
      actor: input.actor,
      correctsKey: input.correctsKey ?? null,
    };
  }
  if (input.quantity < 0n)
    throw new BillingError("INVALID", "usage quantity must not be negative; use an adjustment");
  return {
    tenantId: input.tenantId,
    idempotencyKey: input.idempotencyKey,
    entryType: "usage",
    meter: input.meter,
    quantity: input.quantity,
    eventTime: input.eventTime,
    dimensions,
    source: input.source,
    reason: null,
    actor: null,
    correctsKey: null,
  };
}

/** Hash of everything that defines the event (never the receipt time or the period it landed in). */
export function payloadHash(v: ValidInput): string {
  return createHash("sha256")
    .update(
      canonicalize({
        tenant: v.tenantId,
        key: v.idempotencyKey,
        type: v.entryType,
        meter: v.meter,
        quantity: v.quantity.toString(),
        time: v.eventTime.toISOString(),
        dimensions: v.dimensions,
        source: v.source,
        reason: v.reason,
        actor: v.actor,
        corrects: v.correctsKey,
      }),
      "utf8",
    )
    .digest("hex");
}
