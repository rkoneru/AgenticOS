import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  BillingError,
  DEV_PLAN,
  DEV_PRICE_BOOK,
  allocate,
  divRound,
  prorate,
  rate,
  tierCharges,
  toMinorUnits,
  validatePriceBook,
  type Plan,
  type PriceBook,
  type TotalRow,
} from "../src/index.js";

const T = "11111111-1111-4111-8111-111111111111";
const base = { tenantId: T, periodId: "2026-09", priceBook: DEV_PRICE_BOOK };
const row = (meter: TotalRow["meter"], dimension: string, quantity: bigint): TotalRow => ({
  meter,
  dimension,
  quantity,
});
const plan = (o: Partial<Plan> = {}): Plan => ({ ...DEV_PLAN, ...o });

describe("rounding", () => {
  it("rounds half away from zero", () => {
    expect(divRound(5n, 10n)).toBe(1n);
    expect(divRound(4n, 10n)).toBe(0n);
    expect(divRound(-5n, 10n)).toBe(-1n);
    expect(divRound(-4n, 10n)).toBe(0n);
    expect(divRound(15n, 10n)).toBe(2n);
    expect(() => divRound(1n, 0n)).toThrow(BillingError);
  });
  it("allocates exactly with lowest-index tie-break and handles empties and signs", () => {
    expect(allocate(10n, [1n, 1n, 1n])).toEqual([4n, 3n, 3n]);
    expect(allocate(-10n, [1n, 1n, 1n])).toEqual([-4n, -3n, -3n]);
    expect(allocate(0n, [])).toEqual([]);
    expect(allocate(0n, [0n, 0n])).toEqual([0n, 0n]);
    expect(() => allocate(1n, [])).toThrow(BillingError);
    expect(() => allocate(1n, [0n])).toThrow(BillingError);
    expect(() => allocate(1n, [-1n, 2n])).toThrow(BillingError);
  });
  it("prorates within bounds", () => {
    expect(prorate(100n, 1n, 3n)).toBe(33n);
    expect(prorate(100n, 2n, 3n)).toBe(67n);
    expect(() => prorate(1n, 0n, 0n)).toThrow(BillingError);
    expect(() => prorate(1n, 4n, 3n)).toThrow(BillingError);
  });
  it("property: allocation and minor-unit conversion never create or lose a micro-unit", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: -(10n ** 15n), max: 10n ** 15n }),
        fc.array(fc.bigInt({ min: 0n, max: 10n ** 12n }), { minLength: 1, maxLength: 12 }),
        (total, weights) => {
          fc.pre(weights.some((w) => w > 0n));
          const shares = allocate(total, weights);
          expect(shares.reduce((s, x) => s + x, 0n)).toBe(total);
          shares.forEach((s, i) => {
            const w = weights[i] as bigint;
            if (w === 0n) expect(s).toBe(0n); // zero weight gets nothing
          });
          // each share is within 1 of the exact proportion
          const sum = weights.reduce((s, w) => s + w, 0n);
          shares.forEach((s, i) => {
            const exactTimesSum = total * (weights[i] as bigint);
            const diff = s * sum - exactTimesSum;
            expect((diff < 0n ? -diff : diff) < sum).toBe(true);
          });
        },
      ),
    );
    fc.assert(
      fc.property(
        fc.array(fc.bigInt({ min: -(10n ** 12n), max: 10n ** 12n }), { maxLength: 20 }),
        (lines) => {
          const minor = toMinorUnits(lines);
          expect(minor.reduce((s, x) => s + x, 0n)).toBe(
            divRound(
              lines.reduce((s, x) => s + x, 0n),
              10_000n,
            ),
          );
        },
      ),
    );
  });
});

describe("price book validation", () => {
  const ok = DEV_PRICE_BOOK;
  const bad =
    (rates: PriceBook["rates"], over: Partial<PriceBook> = {}) =>
    () =>
      validatePriceBook({ ...ok, ...over, rates });
  const p = { amountMicro: 1n, perUnits: 1n };
  it("accepts the dev book and rejects malformed ones", () => {
    expect(() => validatePriceBook(ok)).not.toThrow();
    expect(bad([], { currency: "usd" })).toThrow(BillingError);
    expect(bad([], { version: 0 })).toThrow(BillingError);
    expect(
      bad([{ meter: "nope" as never, dimension: "", tiers: [{ upTo: null, price: p }] }]),
    ).toThrow(BillingError);
    expect(bad([{ meter: "tokens_in", dimension: "", tiers: [] }])).toThrow(/no tiers/);
    const card = { meter: "tokens_in" as const, dimension: "" };
    expect(
      bad([
        { ...card, tiers: [{ upTo: null, price: p }] },
        { ...card, tiers: [{ upTo: null, price: p }] },
      ]),
    ).toThrow(/duplicate/);
    expect(
      bad([{ ...card, tiers: [{ upTo: null, price: { amountMicro: -1n, perUnits: 1n } }] }]),
    ).toThrow(/bad price/);
    expect(
      bad([{ ...card, tiers: [{ upTo: null, price: { amountMicro: 1n, perUnits: 0n } }] }]),
    ).toThrow(/bad price/);
    expect(bad([{ ...card, tiers: [{ upTo: 5n, price: p }] }])).toThrow(/unbounded/);
    expect(
      bad([
        {
          ...card,
          tiers: [
            { upTo: null, price: p },
            { upTo: null, price: p },
          ],
        },
      ]),
    ).toThrow(/unbounded/);
    expect(
      bad([
        {
          ...card,
          tiers: [
            { upTo: 5n, price: p },
            { upTo: 5n, price: p },
            { upTo: null, price: p },
          ],
        },
      ]),
    ).toThrow(/increase/);
  });
});

describe("rating", () => {
  it("rates graduated tiers exactly", () => {
    const card = {
      meter: "tool_executions" as const,
      dimension: "",
      tiers: [
        { upTo: 100n, price: { amountMicro: 10n, perUnits: 1n } },
        { upTo: 1000n, price: { amountMicro: 5n, perUnits: 1n } },
        { upTo: null, price: { amountMicro: 1n, perUnits: 1n } },
      ],
    };
    expect(tierCharges(card, 0n)).toEqual([]);
    expect(tierCharges(card, 50n)).toEqual([{ quantity: 50n, amountMicro: 500n }]);
    expect(tierCharges(card, 1500n)).toEqual([
      { quantity: 100n, amountMicro: 1000n },
      { quantity: 900n, amountMicro: 4500n },
      { quantity: 500n, amountMicro: 500n },
    ]);
    expect(tierCharges(card, -3n)).toEqual([{ quantity: -3n, amountMicro: -30n }]);
  });

  it("rates a month: base fee, included tokens, per-class prices, per-kind tools", () => {
    const inv = rate({
      ...base,
      plan: DEV_PLAN,
      totals: [
        row("tokens_in", "frontier", 1_500_000n), // 1M included, 500k billed at $15/M = $7.50
        row("tokens_out", "standard", 100_000n), // under the 200k allowance
        row("tool_executions", "code", 10n),
        row("voice_minutes", "", 150_000n), // 2.5 min at $0.09 = $0.225
        row("runtime_seconds", "", 12_345n), // 12.345 s at $0.0001/s = 1234.5 -> 1235 micro
      ],
    });
    const by = (m: string, d: string) => inv.lines.find((l) => l.meter === m && l.dimension === d);
    expect(by("tokens_in", "frontier")?.amountMicro).toBe(7_500_000n);
    expect(by("tokens_out", "standard")).toBeUndefined();
    expect(by("tool_executions", "code")?.amountMicro).toBe(20_000n);
    expect(by("voice_minutes", "")?.amountMicro).toBe(225_000n);
    expect(by("runtime_seconds", "")?.amountMicro).toBe(1_235n);
    expect(inv.lines[0]?.kind).toBe("base");
    expect(inv.subtotalMicro).toBe(99_000_000n + 7_500_000n + 20_000n + 225_000n + 1_235n);
    expect(inv.totalMicro).toBe(inv.subtotalMicro);
    expect(inv.taxMicro).toBe(0n);
  });

  it("falls back to the any-dimension rate, warns on unpriced usage", () => {
    const inv = rate({
      ...base,
      plan: plan({ baseFeeMicro: 0n, included: {} }),
      totals: [row("tool_executions", "weird", 3n), row("tokens_in", "x", 0n)],
    });
    expect(inv.lines.map((l) => l.amountMicro)).toEqual([3_000n]);
    const pb = {
      ...DEV_PRICE_BOOK,
      rates: DEV_PRICE_BOOK.rates.filter((r) => r.meter !== "tool_executions"),
    };
    const inv2 = rate({
      ...base,
      priceBook: pb,
      plan: plan({ baseFeeMicro: 0n }),
      totals: [row("tool_executions", "code", 3n), row("tool_executions", "", 0n)],
    });
    expect(inv2.lines).toEqual([]);
    expect(inv2.warnings).toEqual(["unpriced usage: tool_executions:code quantity 3"]);
  });

  it("uses a key-specific allowance before the meter-wide one; net-negative usage becomes a credit line", () => {
    const p = plan({
      baseFeeMicro: 0n,
      included: { "tokens_in:small": 1_000_000n, tokens_in: 0n },
    });
    const inv = rate({
      ...base,
      plan: p,
      totals: [row("tokens_in", "small", 2_000_000n), row("tokens_in", "standard", -1000n)],
    });
    expect(inv.lines.map((l) => [l.dimension, l.quantity, l.amountMicro])).toEqual([
      ["small", 1_000_000n, 250_000n],
      ["standard", -1000n, -3000n],
    ]);
    expect(inv.totalMicro).toBe(247_000n);
  });

  it("prorates the base fee over plan windows and rejects bad windows", () => {
    const full = rate({ ...base, plan: DEV_PLAN, totals: [] });
    expect(full.lines[0]?.amountMicro).toBe(99_000_000n);
    const half = rate({
      ...base,
      plan: DEV_PLAN,
      totals: [],
      windows: [{ from: new Date("2026-09-16T00:00:00Z"), to: new Date("2026-12-01T00:00:00Z") }],
    });
    expect(half.lines[0]?.amountMicro).toBe(prorate(99_000_000n, 15n * 86400n, 30n * 86400n));
    expect(half.lines[0]?.description).toMatch(/prorated/);
    const none = rate({
      ...base,
      plan: DEV_PLAN,
      totals: [],
      windows: [{ from: new Date("2026-10-05T00:00:00Z"), to: new Date("2026-11-01T00:00:00Z") }],
    });
    expect(none.lines).toEqual([]);
    const win = (a: string, b: string) => ({ from: new Date(a), to: new Date(b) });
    expect(() =>
      rate({
        ...base,
        plan: DEV_PLAN,
        totals: [],
        windows: [win("2026-09-02T00:00:00Z", "2026-09-01T00:00:00Z")],
      }),
    ).toThrow(/end after/);
    expect(() =>
      rate({
        ...base,
        plan: DEV_PLAN,
        totals: [],
        windows: [
          win("2026-09-01T00:00:00Z", "2026-09-20T00:00:00Z"),
          win("2026-09-10T00:00:00Z", "2026-09-30T00:00:00Z"),
        ],
      }),
    ).toThrow(/overlap/);
    // two adjacent windows of the same plan sum to the whole month
    const two = rate({
      ...base,
      plan: DEV_PLAN,
      totals: [],
      windows: [
        win("2026-09-01T00:00:00Z", "2026-09-11T00:00:00Z"),
        win("2026-09-11T00:00:00Z", "2026-10-01T00:00:00Z"),
      ],
    });
    expect(two.lines).toHaveLength(1);
    expect(two.lines[0]?.amountMicro).toBe(99_000_000n);
  });

  it("bills a committed-use true-up for the shortfall only", () => {
    const p = plan({ baseFeeMicro: 0n, included: {}, commitMicro: 10_000_000n });
    expect(
      rate({ ...base, plan: p, totals: [row("tool_executions", "code", 100n)] }).lines.map((l) => [
        l.kind,
        l.amountMicro,
      ]),
    ).toEqual([
      ["usage", 200_000n],
      ["commit_true_up", 9_800_000n],
    ]);
    expect(
      rate({ ...base, plan: p, totals: [row("marketplace_installs", "", 20n)] }).lines.map(
        (l) => l.kind,
      ),
    ).toEqual(["usage"]);
    expect(
      rate({
        ...base,
        plan: p,
        totals: [],
        windows: [{ from: new Date("2027-01-01T00:00:00Z"), to: new Date("2027-02-01T00:00:00Z") }],
      }).lines,
    ).toEqual([]);
  });

  it("applies credits FIFO up to the subtotal and spreads them exactly over lines", () => {
    const totals = [row("tool_executions", "code", 3n), row("tool_executions", "browser", 1n)];
    const p = plan({ baseFeeMicro: 1_000_001n, included: {} });
    const inv = rate({
      ...base,
      plan: p,
      totals,
      credits: [
        { id: "c1", remainingMicro: 400_000n },
        { id: "c2", remainingMicro: 0n },
        { id: "c3", remainingMicro: 10n ** 12n },
      ],
    });
    expect(inv.creditsConsumed).toEqual([
      { id: "c1", amountMicro: 400_000n },
      { id: "c3", amountMicro: inv.subtotalMicro - 400_000n },
    ]);
    expect(inv.totalMicro).toBe(0n);
    expect(inv.lines.reduce((s, l) => s + l.creditAppliedMicro, 0n)).toBe(inv.subtotalMicro);
    const partial = rate({ ...base, plan: p, totals, credits: [{ id: "c1", remainingMicro: 7n }] });
    expect(partial.totalMicro).toBe(partial.subtotalMicro - 7n);
    expect(() =>
      rate({ ...base, plan: p, totals, credits: [{ id: "bad", remainingMicro: -1n }] }),
    ).toThrow(BillingError);
    const none = rate({
      ...base,
      plan: plan({ baseFeeMicro: 0n }),
      totals: [],
      credits: [{ id: "c", remainingMicro: 5n }],
    });
    expect(none.creditsConsumed).toEqual([]);
  });

  it("rejects a plan bound to a different price book version or with negative fees", () => {
    expect(() =>
      rate({ ...base, plan: plan({ priceBook: { id: "axis-dev", version: 2 } }), totals: [] }),
    ).toThrow(/different price book/);
    expect(() => rate({ ...base, plan: plan({ baseFeeMicro: -1n }), totals: [] })).toThrow(
      BillingError,
    );
  });

  it("property: line items always sum to the invoice total; credits never exceed the subtotal; deterministic", () => {
    const totalsArb = fc.array(
      fc.record({
        meter: fc.constantFrom(
          "tokens_in",
          "tokens_out",
          "tool_executions",
          "voice_minutes",
          "runtime_seconds",
          "storage_gb_hours",
          "marketplace_installs",
        ),
        dimension: fc.constantFrom("", "small", "standard", "frontier", "code", "browser", "other"),
        quantity: fc.bigInt({
          min: -1000n,
          max: Number.MAX_SAFE_INTEGER > 0 ? 9_000_000_000_000_000n : 0n,
        }),
      }),
      { maxLength: 10 },
    );
    fc.assert(
      fc.property(
        totalsArb,
        fc.array(fc.bigInt({ min: 0n, max: 10n ** 12n }), { maxLength: 4 }),
        fc.bigInt({ min: 0n, max: 10n ** 9n }),
        fc.bigInt({ min: 0n, max: 10n ** 9n }),
        (totals, creds, fee, commit) => {
          const p = plan({ baseFeeMicro: fee, commitMicro: commit });
          const credits = creds.map((c, i) => ({ id: `c${i}`, remainingMicro: c }));
          const inv = rate({ ...base, plan: p, totals, credits });
          expect(inv.lines.reduce((s, l) => s + l.amountMicro, 0n)).toBe(inv.subtotalMicro);
          expect(inv.lines.reduce((s, l) => s + l.netMicro, 0n) + inv.taxMicro).toBe(
            inv.totalMicro,
          );
          expect(inv.lines.reduce((s, l) => s + l.creditAppliedMicro, 0n)).toBe(
            inv.creditsAppliedMicro,
          );
          expect(inv.creditsConsumed.reduce((s, c) => s + c.amountMicro, 0n)).toBe(
            inv.creditsAppliedMicro,
          );
          expect(inv.creditsAppliedMicro <= (inv.subtotalMicro > 0n ? inv.subtotalMicro : 0n)).toBe(
            true,
          );
          for (const l of inv.lines)
            if (l.creditAppliedMicro > 0n) expect(l.creditAppliedMicro <= l.amountMicro).toBe(true);
          expect(rate({ ...base, plan: p, totals, credits })).toEqual(inv);
        },
      ),
      { numRuns: 200 },
    );
  });
});
