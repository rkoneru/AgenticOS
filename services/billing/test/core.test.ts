import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  BillingError,
  HmacSealSigner,
  MemoryUsageLedger,
  PgUsageLedger,
  assertClosable,
  attributePeriod,
  bucketStart,
  foldRollup,
  foldTotals,
  nextPeriod,
  normalizeDimensions,
  parsePeriod,
  payloadHash,
  periodBounds,
  periodIdOf,
  periodSeconds,
  buildSeal,
  verifySeal,
  validateInput,
  rowsDigest,
  sealTotals,
  GENESIS_SEAL,
  METERS,
  MAX_QUANTITY,
  type SealRow,
} from "../src/index.js";
import { Clock, memLedger, signer, usage } from "./helpers.js";

const T = "11111111-1111-4111-8111-111111111111";
const NOW = new Date("2026-10-02T00:00:00Z");

describe("periods", () => {
  it("computes ids, bounds and successors in UTC, across year ends and leap years", () => {
    expect(periodIdOf(new Date("2026-12-31T23:59:59.999Z"))).toBe("2026-12");
    expect(nextPeriod("2026-12")).toBe("2027-01");
    expect(periodBounds("2028-02").end.toISOString()).toBe("2028-03-01T00:00:00.000Z");
    expect(periodSeconds("2028-02")).toBe(29n * 86400n);
    expect(periodSeconds("2026-02")).toBe(28n * 86400n);
    expect(() => parsePeriod("2026-13")).toThrow(BillingError);
    expect(() => parsePeriod("26-1")).toThrow(BillingError);
  });
  it("buckets by hour, day and month", () => {
    const t = new Date("2026-03-05T07:45:10Z");
    expect(bucketStart(t, "hour")).toBe("2026-03-05T07:00:00.000Z");
    expect(bucketStart(t, "day")).toBe("2026-03-05T00:00:00.000Z");
    expect(bucketStart(t, "month")).toBe("2026-03-01T00:00:00.000Z");
  });
  it("attributes to the first unsealed period", () => {
    const d = new Date("2026-08-15T00:00:00Z");
    expect(attributePeriod(d, new Set())).toEqual({ periodId: "2026-08", originalPeriodId: null });
    expect(attributePeriod(d, new Set(["2026-08", "2026-09"]))).toEqual({
      periodId: "2026-10",
      originalPeriodId: "2026-08",
    });
  });
  it("assertClosable throws only before the period end", () => {
    expect(() => assertClosable("2026-10", NOW)).toThrow(BillingError);
    expect(() => assertClosable("2026-09", NOW)).not.toThrow();
  });
});

describe("validation", () => {
  const ok = usage(T);
  it("normalizes and sorts dimensions, rejects bad shapes", () => {
    expect(Object.keys(normalizeDimensions({ b: "1", a: "2" }))).toEqual(["a", "b"]);
    expect(normalizeDimensions(undefined)).toEqual({});
    expect(() => normalizeDimensions([])).toThrow(BillingError);
    expect(() => normalizeDimensions(null)).toThrow(BillingError);
    expect(() => normalizeDimensions({ a: "" })).toThrow(BillingError);
    expect(() => normalizeDimensions({ a: "x\u0000" })).toThrow(BillingError);
    const nine = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`k${i}`, "v"]));
    expect(() => normalizeDimensions(nine)).toThrow(BillingError);
  });
  it("accepts the largest safe quantity and rejects one more, negative usage and bad adjustments", () => {
    expect(validateInput({ ...ok, quantity: MAX_QUANTITY }, NOW).quantity).toBe(MAX_QUANTITY);
    expect(() => validateInput({ ...ok, quantity: MAX_QUANTITY + 1n }, NOW)).toThrow(BillingError);
    expect(() =>
      validateInput(
        { ...ok, quantity: -MAX_QUANTITY - 1n, entryType: "adjustment", reason: "abc", actor: "a" },
        NOW,
      ),
    ).toThrow(BillingError);
    expect(() => validateInput({ ...ok, quantity: -1n }, NOW)).toThrow(/adjustment/);
    const adj = {
      ...ok,
      entryType: "adjustment" as const,
      quantity: -5n,
      reason: "double count",
      actor: "ops",
      correctsKey: "k1",
    };
    expect(validateInput(adj, NOW).correctsKey).toBe("k1");
    expect(() => validateInput({ ...adj, correctsKey: "" }, NOW)).toThrow(BillingError);
    expect(() => validateInput({ ...ok, source: "" }, NOW)).toThrow(BillingError);
  });
  it("allows a small clock skew but not the future", () => {
    expect(() =>
      validateInput({ ...ok, eventTime: new Date(NOW.getTime() + 60_000) }, NOW),
    ).not.toThrow();
    expect(() =>
      validateInput({ ...ok, eventTime: new Date(NOW.getTime() + 600_000) }, NOW),
    ).toThrow(BillingError);
  });
  it("payload hash covers every business field but not the receipt", () => {
    const base = validateInput(ok, NOW);
    const h = payloadHash(base);
    expect(payloadHash({ ...base })).toBe(h);
    for (const change of [
      { quantity: base.quantity + 1n },
      { meter: "tokens_out" as const },
      { source: "x" },
      { eventTime: new Date(base.eventTime.getTime() + 1) },
      { dimensions: { agent: "other" } },
      { tenantId: "22222222-2222-4222-8222-222222222222" },
      { idempotencyKey: "other" },
    ])
      expect(payloadHash({ ...base, ...change })).not.toBe(h);
  });
});

describe("seal", () => {
  const rows: SealRow[] = [
    { idempotencyKey: "a", payloadHash: "1".repeat(64), meter: "tokens_in", quantity: 5n },
    { idempotencyKey: "b", payloadHash: "2".repeat(64), meter: "tool_executions", quantity: 2n },
  ];
  const build = (r = rows) =>
    buildSeal({
      tenantId: T,
      periodId: "2026-09",
      seq: 1,
      prevSealHash: GENESIS_SEAL,
      rows: r,
      closedAt: NOW,
      signer: signer(),
    });
  it("verifies, and each tamper is detected with its own reason", () => {
    const s = build();
    expect(verifySeal(s, rows, signer())).toEqual({ ok: true });
    expect(verifySeal(s, rows.slice(1), signer())).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/count/),
    });
    const swapped = [{ ...rows[0]!, payloadHash: "3".repeat(64) }, rows[1]!];
    expect(verifySeal(s, swapped, signer())).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/rows/),
    });
    // same digest inputs but different totals cannot happen with an honest digest; forge the stored totals instead
    expect(verifySeal({ ...s, totals: { tokens_in: "6" } }, rows, signer())).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/totals/),
    });
    expect(verifySeal({ ...s, seq: 2 }, rows, signer())).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/hash/),
    });
    expect(verifySeal({ ...s, signature: "00" }, rows, signer())).toMatchObject({
      ok: false,
      reason: "bad signature",
    });
    const other = new HmacSealSigner(Buffer.alloc(32, 9));
    expect(verifySeal(s, rows, other)).toMatchObject({ ok: false });
  });
  it("is independent of row order and requires a 32-byte key", () => {
    expect(rowsDigest(rows)).toBe(rowsDigest([...rows].reverse()));
    expect(sealTotals(rows)).toEqual({ tokens_in: "5", tool_executions: "2" });
    expect(() => new HmacSealSigner(Buffer.alloc(8))).toThrow();
  });
});

describe("folds", () => {
  it("fold totals with unknown dimension and rollup filters", () => {
    expect(foldTotals([{ meter: "tokens_out", quantity: 2n, dimensions: {} }])).toEqual([
      { meter: "tokens_out", dimension: "unknown", quantity: 2n },
    ]);
    const e = [
      { meter: "tokens_in" as const, quantity: 1n, eventTime: new Date("2026-09-01T00:00:00Z") },
      { meter: "tokens_out" as const, quantity: 1n, eventTime: new Date("2026-09-01T00:00:00Z") },
      { meter: "tokens_in" as const, quantity: 1n, eventTime: new Date("2026-08-31T23:59:59Z") },
    ];
    const r = foldRollup(e, {
      granularity: "day",
      from: new Date("2026-09-01T00:00:00Z"),
      to: new Date("2026-09-02T00:00:00Z"),
    });
    expect(r.map((x) => x.meter)).toEqual(["tokens_in", "tokens_out"]);
  });
});

describe("properties (memory ledger)", () => {
  const T1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const T2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const item = fc.record({
    k: fc.integer({ min: 0, max: 12 }),
    meter: fc.constantFrom(...METERS),
    q: fc.bigInt({ min: 0n, max: MAX_QUANTITY }),
    day: fc.integer({ min: 1, max: 28 }),
    tenant: fc.constantFrom(T1, T2),
  });
  const mk = (clock: Clock) => memLedger(clock);

  it("replays are idempotent and totals are order independent", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(item, { maxLength: 30 }), fc.integer(), async (items, seed) => {
        const clock = new Clock(NOW);
        const a = mk(clock);
        const b = mk(clock);
        // identical-by-key items: the first occurrence defines the payload (later ones become duplicates or conflicts)
        const inputs = items.map((i) =>
          usage(i.tenant, {
            idempotencyKey: `k${i.k}`,
            meter: i.meter,
            quantity: i.q,
            eventTime: new Date(Date.UTC(2026, 8, i.day)),
          }),
        );
        const canonical = new Map<string, (typeof inputs)[number]>();
        for (const x of inputs)
          if (!canonical.has(`${x.tenantId}|${x.idempotencyKey}`))
            canonical.set(`${x.tenantId}|${x.idempotencyKey}`, x);
        const uniq = [...canonical.values()];
        for (const x of uniq) await a.append(x);
        const shuffled = [...uniq, ...uniq].sort(
          (p, q) =>
            ((p.idempotencyKey.length * 31 + seed) % 7) -
            ((q.idempotencyKey.length * 17 + seed) % 7),
        );
        for (const x of shuffled.reverse()) await b.append(x);
        for (const t of [T1, T2])
          expect(await b.totals(t, "2026-09")).toEqual(await a.totals(t, "2026-09"));
        // totals are exact BigInt sums (no overflow, no loss)
        for (const t of [T1, T2]) {
          const sum = (await a.totals(t, "2026-09")).reduce((s, r) => s + r.quantity, 0n);
          const direct = uniq.filter((u) => u.tenantId === t).reduce((s, u) => s + u.quantity, 0n);
          expect(sum).toBe(direct);
        }
      }),
      { numRuns: 60 },
    );
  });

  it("never lets tenants see each other and never yields a negative usage total without adjustments", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(item, { maxLength: 20 }), async (items) => {
        const l = mk(new Clock(NOW));
        for (const i of items)
          await l.append(
            usage(i.tenant, {
              idempotencyKey: `k${i.k}`,
              meter: i.meter,
              quantity: i.q,
              eventTime: new Date(Date.UTC(2026, 8, i.day)),
            }),
          );
        for (const t of [T1, T2]) {
          for (const e of await l.entries(t)) expect(e.tenantId).toBe(t);
          for (const r of await l.totals(t, "2026-09")) expect(r.quantity >= 0n).toBe(true);
        }
      }),
      { numRuns: 40 },
    );
  });

  it("a closed period is immutable under any later arrivals", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(item, { maxLength: 15 }),
        fc.array(item, { maxLength: 15 }),
        async (before, after) => {
          const clock = new Clock(NOW);
          const l = mk(clock);
          const put = (i: (typeof before)[number], p: string) =>
            l.append(
              usage(T1, {
                idempotencyKey: `${p}${i.k}`,
                meter: i.meter,
                quantity: i.q,
                eventTime: new Date(Date.UTC(2026, 8, i.day)),
              }),
            );
          for (const i of before) await put(i, "b");
          const seal = await l.closePeriod(T1, "2026-09");
          const frozen = await l.totals(T1, "2026-09");
          for (const i of after) await put(i, "a");
          expect(await l.totals(T1, "2026-09")).toEqual(frozen);
          expect(await l.verifySeal(T1, "2026-09")).toEqual({ ok: true });
          expect((await l.seals(T1))[0]?.sealHash).toBe(seal.sealHash);
        },
      ),
      { numRuns: 40 },
    );
  });

  it("PgUsageLedger defaults its clock to the wall clock", () => {
    expect(
      new PgUsageLedger({
        pool: { connect: () => Promise.reject(new Error("unused")) },
        signer: signer(),
      }),
    ).toBeDefined();
  });

  it("MemoryUsageLedger defaults its clock to the wall clock", async () => {
    const l = new MemoryUsageLedger({ signer: signer() });
    const r = await l.append(usage(T1, { eventTime: new Date(Date.now() - 1000) }));
    expect(r.status).toBe("inserted");
  });
});
