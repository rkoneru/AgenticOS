import { BillingError } from "./errors.js";
import { allocate, mulDivRound, prorate } from "./money.js";
import { periodBounds, periodSeconds } from "./periods.js";
import type { TotalRow } from "./ledger.js";
import { isMeter, type Meter } from "./types.js";

/** `amountMicro` micro-currency per `perUnits` base units of the meter. */
export interface Price {
  amountMicro: bigint;
  perUnits: bigint;
}

/** Graduated tier: applies to the quantity up to the cumulative bound `upTo` (null = unbounded). Bounds strictly increase. */
export interface Tier {
  upTo: bigint | null;
  price: Price;
}

/** `dimension` is the value of the meter's rate dimension (model class, tool kind); "" matches any value (fallback). */
export interface RateCard {
  meter: Meter;
  dimension: string;
  tiers: readonly Tier[];
}

export interface PriceBook {
  id: string;
  version: number;
  currency: string;
  /** Prefix rules mapping a model name to a price class; used by the emitters. */
  modelClasses: readonly { prefix: string; class: string }[];
  rates: readonly RateCard[];
}

export interface Plan {
  id: string;
  name: string;
  priceBook: { id: string; version: number };
  /** Flat fee per full billing period, micro-currency. */
  baseFeeMicro: bigint;
  /** Included quantity per "meter" or "meter:dimension", consumed before any charge. */
  included: Readonly<Record<string, bigint>>;
  /** Minimum usage charge per period; the shortfall is billed as a commit true-up. 0 = none. */
  commitMicro: bigint;
}

export interface PlanWindow {
  /** The plan is active in [from, to). */
  from: Date;
  to: Date;
}

export interface Credit {
  id: string;
  remainingMicro: bigint;
}

export type LineKind = "base" | "usage" | "commit_true_up";

export interface InvoiceLine {
  kind: LineKind;
  description: string;
  meter: Meter | null;
  dimension: string;
  /** Base units billed on this line (after the included allowance and tier split). */
  quantity: bigint;
  amountMicro: bigint;
  creditAppliedMicro: bigint;
  netMicro: bigint;
}

export interface Invoice {
  tenantId: string;
  periodId: string;
  planId: string;
  priceBook: { id: string; version: number };
  currency: string;
  lines: InvoiceLine[];
  subtotalMicro: bigint;
  creditsAppliedMicro: bigint;
  creditsConsumed: { id: string; amountMicro: bigint }[];
  /** Tax is a placeholder (NEEDS): always 0 until a tax engine is attached. */
  taxMicro: bigint;
  totalMicro: bigint;
  warnings: string[];
}

export function rateKey(meter: Meter, dimension: string): string {
  return dimension === "" ? meter : `${meter}:${dimension}`;
}

export function validatePriceBook(pb: PriceBook): void {
  if (!/^[A-Z]{3}$/.test(pb.currency))
    throw new BillingError("INVALID", "currency must be ISO 4217");
  if (!Number.isInteger(pb.version) || pb.version < 1)
    throw new BillingError("INVALID", "bad price book version");
  const seen = new Set<string>();
  for (const r of pb.rates) {
    if (!isMeter(r.meter)) throw new BillingError("INVALID", "unknown meter in price book");
    const k = rateKey(r.meter, r.dimension);
    if (seen.has(k)) throw new BillingError("INVALID", `duplicate rate ${k}`);
    seen.add(k);
    if (r.tiers.length === 0) throw new BillingError("INVALID", `rate ${k} has no tiers`);
    let prev = 0n;
    r.tiers.forEach((t, i) => {
      if (t.price.amountMicro < 0n || t.price.perUnits <= 0n)
        throw new BillingError("INVALID", `rate ${k} has a bad price`);
      const last = i === r.tiers.length - 1;
      if (last !== (t.upTo === null))
        throw new BillingError("INVALID", `rate ${k}: only the last tier is unbounded`);
      if (t.upTo !== null) {
        if (t.upTo <= prev)
          throw new BillingError("INVALID", `rate ${k}: tier bounds must increase`);
        prev = t.upTo;
      }
    });
  }
}

function findRate(pb: PriceBook, meter: Meter, dimension: string): RateCard | undefined {
  return (
    pb.rates.find((r) => r.meter === meter && r.dimension === dimension && dimension !== "") ??
    pb.rates.find((r) => r.meter === meter && r.dimension === "")
  );
}

/** Charges for `qty` base units through graduated tiers; one entry per tier that applies. A negative qty (net credit) uses tier 1. */
export function tierCharges(
  card: RateCard,
  qty: bigint,
): { quantity: bigint; amountMicro: bigint }[] {
  const first = card.tiers[0] as Tier;
  if (qty < 0n)
    return [
      {
        quantity: qty,
        amountMicro: mulDivRound(qty, first.price.amountMicro, first.price.perUnits),
      },
    ];
  const out: { quantity: bigint; amountMicro: bigint }[] = [];
  let lower = 0n;
  for (const t of card.tiers) {
    if (qty <= lower) break;
    const upper = t.upTo === null || t.upTo > qty ? qty : t.upTo;
    const q = upper - lower;
    out.push({ quantity: q, amountMicro: mulDivRound(q, t.price.amountMicro, t.price.perUnits) });
    lower = upper;
  }
  return out;
}

export interface RateInput {
  tenantId: string;
  periodId: string;
  totals: readonly TotalRow[];
  plan: Plan;
  priceBook: PriceBook;
  /** When the plan was active inside the period; default the whole period. Several windows are summed (proration). */
  windows?: readonly PlanWindow[];
  credits?: readonly Credit[];
}

/**
 * rate(period usage, plan) -> invoice. Deterministic and pure; integer micro-currency only. Invariants (property-tested):
 *   sum(line.amountMicro) === subtotalMicro;  sum(line.netMicro) + taxMicro === totalMicro;
 *   sum(line.creditAppliedMicro) === creditsAppliedMicro === sum(creditsConsumed);  creditsApplied <= max(subtotal, 0).
 */
export function rate(input: RateInput): Invoice {
  const { plan, priceBook: pb, totals } = input;
  validatePriceBook(pb);
  if (plan.priceBook.id !== pb.id || plan.priceBook.version !== pb.version)
    throw new BillingError("INVALID", "plan is bound to a different price book version");
  if (plan.baseFeeMicro < 0n || plan.commitMicro < 0n)
    throw new BillingError("INVALID", "fees must not be negative");
  const bounds = periodBounds(input.periodId);
  const warnings: string[] = [];
  const lines: InvoiceLine[] = [];
  const mk = (l: Omit<InvoiceLine, "creditAppliedMicro" | "netMicro">): void => {
    lines.push({ ...l, creditAppliedMicro: 0n, netMicro: l.amountMicro });
  };

  // Base fee, prorated by the seconds the plan was active in the period (R2). Overlapping windows are rejected.
  const windows = input.windows ?? [{ from: bounds.start, to: bounds.end }];
  let active = 0n;
  const sorted = [...windows].sort((a, b) => a.from.getTime() - b.from.getTime());
  let prevEnd = 0;
  for (const w of sorted) {
    const from = Math.max(w.from.getTime(), bounds.start.getTime());
    const to = Math.min(w.to.getTime(), bounds.end.getTime());
    if (w.to <= w.from) throw new BillingError("INVALID", "plan window must end after it starts");
    if (from < prevEnd) throw new BillingError("INVALID", "plan windows overlap");
    if (to > from) active += BigInt(Math.floor((to - from) / 1000));
    prevEnd = Math.max(prevEnd, to);
  }
  const whole = periodSeconds(input.periodId);
  if (plan.baseFeeMicro > 0n && active > 0n)
    mk({
      kind: "base",
      description: `${plan.name} base fee${active === whole ? "" : ` (prorated ${active}/${whole} s)`}`,
      meter: null,
      dimension: "",
      quantity: 1n,
      amountMicro: active === whole ? plan.baseFeeMicro : prorate(plan.baseFeeMicro, active, whole),
    });

  // Usage. Included allowance first (per rate key), then graduated tiers.
  let usageCharges = 0n;
  const meterPool = new Map<Meter, bigint>(); // remaining meter-wide allowance per meter
  for (const row of totals) {
    const key = rateKey(row.meter, row.dimension);
    const card = findRate(pb, row.meter, row.dimension);
    if (!card) {
      if (row.quantity !== 0n) warnings.push(`unpriced usage: ${key} quantity ${row.quantity}`);
      continue;
    }
    // A key-specific allowance belongs to that row. A meter-wide one is ONE pool shared by every row of the meter (consumed in row
    // order): applied per row it would be granted again for each model class / tool kind.
    const own = plan.included[key];
    const pooled = own === undefined ? (plan.included[row.meter] ?? 0n) : 0n;
    const allowance = own ?? meterPool.get(row.meter) ?? pooled;
    let billable = row.quantity;
    if (row.quantity > 0n) {
      const used = row.quantity > allowance ? allowance : row.quantity;
      billable = row.quantity - used;
      if (own === undefined) meterPool.set(row.meter, allowance - used);
    }
    for (const c of tierCharges(card, billable)) {
      mk({
        kind: "usage",
        description: `${key}${allowance > 0n ? ` (after ${allowance} included)` : ""}`,
        meter: row.meter,
        dimension: row.dimension,
        quantity: c.quantity,
        amountMicro: c.amountMicro,
      });
      usageCharges += c.amountMicro;
    }
  }
  if (plan.commitMicro > usageCharges && active > 0n) {
    mk({
      kind: "commit_true_up",
      description: `committed use minimum ${plan.commitMicro}`,
      meter: null,
      dimension: "",
      quantity: 1n,
      amountMicro: plan.commitMicro - usageCharges,
    });
  }

  const subtotal = lines.reduce((s, l) => s + l.amountMicro, 0n);

  // Credits: applied FIFO up to the positive subtotal, then spread over the positive lines (R3) so each line has an exact net.
  const consumed: { id: string; amountMicro: bigint }[] = [];
  let remaining = subtotal > 0n ? subtotal : 0n;
  for (const c of input.credits ?? []) {
    if (c.remainingMicro < 0n) throw new BillingError("INVALID", "credit must not be negative");
    if (remaining === 0n) break;
    const use = c.remainingMicro < remaining ? c.remainingMicro : remaining;
    if (use > 0n) consumed.push({ id: c.id, amountMicro: use });
    remaining -= use;
  }
  const applied = consumed.reduce((s, c) => s + c.amountMicro, 0n);
  if (applied > 0n) {
    const idx = lines.map((l, i) => (l.amountMicro > 0n ? i : -1)).filter((i) => i >= 0);
    const shares = allocate(
      applied,
      idx.map((i) => (lines[i] as InvoiceLine).amountMicro),
    );
    idx.forEach((li, k) => {
      const l = lines[li] as InvoiceLine;
      const s = shares[k] as bigint;
      l.creditAppliedMicro = s;
      l.netMicro = l.amountMicro - s;
    });
  }
  const tax = 0n;
  return {
    tenantId: input.tenantId,
    periodId: input.periodId,
    planId: plan.id,
    priceBook: { id: pb.id, version: pb.version },
    currency: pb.currency,
    lines,
    subtotalMicro: subtotal,
    creditsAppliedMicro: applied,
    creditsConsumed: consumed,
    taxMicro: tax,
    totalMicro: lines.reduce((s, l) => s + l.netMicro, 0n) + tax,
    warnings,
  };
}
