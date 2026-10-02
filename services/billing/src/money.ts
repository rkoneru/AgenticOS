import { BillingError } from "./errors.js";

/**
 * Money is an INTEGER number of micro-currency units (1 USD = 1_000_000). No floats, no Number arithmetic on amounts.
 *
 * Rounding rules (docs/spec/billing.md):
 *  R1  A price is `amountMicro` per `perUnits` base units. A charge is round(quantity * amountMicro / perUnits).
 *  R2  round = half away from zero (ties go to the larger magnitude). Charges are rounded once, per invoice line, never per record.
 *  R3  Splitting an amount over weights uses the largest-remainder method: shares sum EXACTLY to the total, ties go to the lower index.
 *  R4  Converting lines to the currency's minor unit (cents) uses cumulative rounding, so the minor lines sum to round(total) exactly.
 */
export function divRound(n: bigint, d: bigint): bigint {
  if (d <= 0n) throw new BillingError("INVALID", "divisor must be positive");
  const neg = n < 0n;
  const a = neg ? -n : n;
  const q = (2n * a + d) / (2n * d); // floor(a/d + 1/2)
  return neg ? -q : q;
}

export function mulDivRound(q: bigint, amount: bigint, per: bigint): bigint {
  return divRound(q * amount, per);
}

/** Splits `total` (any sign) over non-negative `weights` so the shares sum exactly to `total` (largest remainder, R3). */
export function allocate(total: bigint, weights: readonly bigint[]): bigint[] {
  if (weights.some((w) => w < 0n))
    throw new BillingError("INVALID", "weights must not be negative");
  const sum = weights.reduce((s, w) => s + w, 0n);
  if (weights.length === 0) {
    if (total !== 0n)
      throw new BillingError("INVALID", "cannot allocate a non-zero total over nothing");
    return [];
  }
  if (sum === 0n) {
    if (total !== 0n) throw new BillingError("INVALID", "cannot allocate over zero total weight");
    return weights.map(() => 0n);
  }
  const neg = total < 0n;
  const t = neg ? -total : total;
  const shares = weights.map((w) => (t * w) / sum);
  let rest = t - shares.reduce((s, x) => s + x, 0n);
  const order = weights
    .map((w, i) => ({ i, rem: (t * w) % sum }))
    .sort((a, b) => (a.rem === b.rem ? a.i - b.i : a.rem > b.rem ? -1 : 1));
  for (const { i } of order) {
    if (rest === 0n) break;
    shares[i] = (shares[i] as bigint) + 1n;
    rest -= 1n;
  }
  return neg ? shares.map((s) => -s) : shares;
}

/** Proportional share round(amount * part / whole), R2. */
export function prorate(amount: bigint, part: bigint, whole: bigint): bigint {
  if (whole <= 0n) throw new BillingError("INVALID", "whole must be positive");
  if (part < 0n || part > whole) throw new BillingError("INVALID", "part must be within 0..whole");
  return mulDivRound(part, amount, whole);
}

export const MICRO_PER_MINOR = 10_000n; // 1 cent = 10_000 micro-USD

/** Minor-unit amounts per line by cumulative rounding (R4): sum(result) === divRound(sum(micro), 10_000). */
export function toMinorUnits(microLines: readonly bigint[]): bigint[] {
  let cum = 0n;
  let prev = 0n;
  return microLines.map((m) => {
    cum += m;
    const r = divRound(cum, MICRO_PER_MINOR);
    const out = r - prev;
    prev = r;
    return out;
  });
}
