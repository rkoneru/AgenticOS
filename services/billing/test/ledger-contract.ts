import { describe, expect, it } from "vitest";
import type { UsageLedger, UsageInput } from "../src/index.js";
import { BillingError } from "../src/index.js";
import { usage, type Clock } from "./helpers.js";

export interface Rig {
  ledger: UsageLedger;
  clock: Clock;
  tenant: () => Promise<string>;
}

const adj = (tenantId: string, over: Record<string, unknown> = {}) => ({
  entryType: "adjustment" as const,
  tenantId,
  idempotencyKey: `adj-${Math.random()}`,
  meter: "tokens_in" as const,
  quantity: -40n,
  eventTime: new Date("2026-09-10T12:00:00Z"),
  source: "admin",
  reason: "refund of a double count",
  actor: "ops@example.com",
  dimensions: { model_class: "standard" },
  ...over,
});

/** The behaviour every UsageLedger implementation must have. Run against the in-memory and the Postgres ledger. */
export function ledgerContract(name: string, make: () => Promise<Rig>): void {
  describe(`ledger contract: ${name}`, () => {
    const setup = async () => {
      const rig = await make();
      rig.clock.set("2026-10-02T00:00:00Z");
      return { ...rig, t1: await rig.tenant(), t2: await rig.tenant() };
    };

    it("inserts once; an identical replay is a no-op returning the original entry", async () => {
      const { ledger, t1 } = await setup();
      const u = usage(t1);
      const a = await ledger.append(u);
      const b = await ledger.append({ ...u });
      expect(a.status).toBe("inserted");
      expect(b.status).toBe("duplicate");
      if (a.status === "inserted" && b.status === "duplicate") expect(b.entry.id).toBe(a.entry.id);
      expect(await ledger.entries(t1)).toHaveLength(1);
    });

    it("rejects and reports a replay of the same key with a different payload", async () => {
      const { ledger, t1 } = await setup();
      const u = usage(t1, { quantity: 5n });
      await ledger.append(u);
      const r = await ledger.append({ ...u, quantity: 6n });
      expect(r.status).toBe("conflict");
      const again = await ledger.append({ ...u, quantity: 6n });
      expect(again.status).toBe("conflict");
      const c = await ledger.conflicts(t1);
      expect(c).toHaveLength(1);
      expect(c[0]?.idempotencyKey).toBe(u.idempotencyKey);
      const e = await ledger.entries(t1);
      expect(e).toHaveLength(1);
      expect(e[0]?.quantity).toBe(5n);
    });

    it("scopes the idempotency key to the tenant", async () => {
      const { ledger, t1, t2 } = await setup();
      const key = "shared-key";
      expect((await ledger.append(usage(t1, { idempotencyKey: key }))).status).toBe("inserted");
      expect((await ledger.append(usage(t2, { idempotencyKey: key }))).status).toBe("inserted");
      expect(await ledger.entries(t1)).toHaveLength(1);
      expect(await ledger.entries(t2)).toHaveLength(1);
    });

    it("keeps tenants isolated in totals, entries, seals and conflicts", async () => {
      const { ledger, t1, t2 } = await setup();
      await ledger.append(usage(t1, { quantity: 7n }));
      expect(await ledger.totals(t2, "2026-09")).toEqual([]);
      expect((await ledger.entries(t2)).length).toBe(0);
      expect(await ledger.seals(t2)).toEqual([]);
    });

    it("validates inputs", async () => {
      const { ledger, t1 } = await setup();
      const bad: Partial<UsageInput>[] = [
        { quantity: -1n },
        { quantity: BigInt(Number.MAX_SAFE_INTEGER) + 1n },
        { quantity: 1.5 as unknown as bigint },
        { meter: "nope" as never },
        { idempotencyKey: "" },
        { eventTime: new Date("2026-10-03T00:00:00Z") },
        { eventTime: new Date("nope") },
        { dimensions: { "Bad Key": "x" } },
        { tenantId: "not-a-uuid" },
      ];
      for (const b of bad) await expect(ledger.append(usage(t1, b))).rejects.toBeInstanceOf(BillingError);
      expect(await ledger.entries(t1)).toHaveLength(0);
    });

    it("totals include adjustments and split by rate dimension", async () => {
      const { ledger, t1 } = await setup();
      await ledger.append(usage(t1, { quantity: 100n }));
      await ledger.append(usage(t1, { quantity: 50n, dimensions: { model_class: "frontier" } }));
      await ledger.append(usage(t1, { meter: "tool_executions", quantity: 3n, dimensions: { tool_kind: "code" } }));
      await ledger.append(usage(t1, { meter: "voice_minutes", quantity: 60_000n, dimensions: {} }));
      const ad = await ledger.append(adj(t1));
      expect(ad.status).toBe("inserted");
      const t = await ledger.totals(t1, "2026-09");
      expect(t).toEqual([
        { meter: "tokens_in", dimension: "frontier", quantity: 50n },
        { meter: "tokens_in", dimension: "standard", quantity: 60n },
        { meter: "tool_executions", dimension: "code", quantity: 3n },
        { meter: "voice_minutes", dimension: "", quantity: 60_000n },
      ]);
    });

    it("requires a reason and an actor for an adjustment and forbids a zero one", async () => {
      const { ledger, t1 } = await setup();
      await expect(ledger.append(adj(t1, { reason: "x" }))).rejects.toBeInstanceOf(BillingError);
      await expect(ledger.append(adj(t1, { actor: "" }))).rejects.toBeInstanceOf(BillingError);
      await expect(ledger.append(adj(t1, { quantity: 0n }))).rejects.toBeInstanceOf(BillingError);
    });

    it("rolls up by hour, day and month in UTC by event time", async () => {
      const { ledger, t1 } = await setup();
      await ledger.append(usage(t1, { quantity: 1n, eventTime: new Date("2026-09-10T12:10:00Z") }));
      await ledger.append(usage(t1, { quantity: 2n, eventTime: new Date("2026-09-10T12:50:00Z") }));
      await ledger.append(usage(t1, { quantity: 4n, eventTime: new Date("2026-09-10T23:59:59Z") }));
      await ledger.append(usage(t1, { quantity: 8n, eventTime: new Date("2026-09-11T00:00:00Z") }));
      const q = { from: new Date("2026-09-01T00:00:00Z"), to: new Date("2026-10-01T00:00:00Z") };
      const hour = await ledger.rollup(t1, { ...q, granularity: "hour" });
      expect(hour.map((r) => [r.bucket, r.quantity])).toEqual([
        ["2026-09-10T12:00:00.000Z", 3n],
        ["2026-09-10T23:00:00.000Z", 4n],
        ["2026-09-11T00:00:00.000Z", 8n],
      ]);
      const day = await ledger.rollup(t1, { ...q, granularity: "day", meter: "tokens_in" });
      expect(day.map((r) => r.quantity)).toEqual([7n, 8n]);
      const month = await ledger.rollup(t1, { ...q, granularity: "month" });
      expect(month).toEqual([{ bucket: "2026-09-01T00:00:00.000Z", meter: "tokens_in", quantity: 15n }]);
      expect(await ledger.rollup(t1, { ...q, granularity: "day", meter: "tokens_out" })).toEqual([]);
    });

    it("cannot close a period that has not ended; closes once; chains seals", async () => {
      const { ledger, clock, t1 } = await setup();
      await ledger.append(usage(t1, { quantity: 10n }));
      await expect(ledger.closePeriod(t1, "2026-10")).rejects.toMatchObject({ code: "PERIOD_NOT_CLOSABLE" });
      const s1 = await ledger.closePeriod(t1, "2026-09");
      expect(s1.seq).toBe(1);
      expect(s1.eventCount).toBe(1);
      expect(s1.totals).toEqual({ tokens_in: "10" });
      await expect(ledger.closePeriod(t1, "2026-09")).rejects.toMatchObject({ code: "PERIOD_ALREADY_CLOSED" });
      clock.set("2026-11-02T00:00:00Z");
      const s2 = await ledger.closePeriod(t1, "2026-10");
      expect(s2.seq).toBe(2);
      expect(s2.prevSealHash).toBe(s1.sealHash);
      expect(await ledger.verifySeal(t1, "2026-09")).toEqual({ ok: true });
      expect((await ledger.seals(t1)).map((s) => s.periodId)).toEqual(["2026-09", "2026-10"]);
      await expect(ledger.verifySeal(t1, "2026-08")).rejects.toMatchObject({ code: "PERIOD_NOT_SEALED" });
    });

    it("lands a late event for a closed period in the next period and never changes the closed one", async () => {
      const { ledger, t1 } = await setup();
      await ledger.append(usage(t1, { quantity: 10n }));
      const seal = await ledger.closePeriod(t1, "2026-09");
      const late = await ledger.append(usage(t1, { quantity: 99n, eventTime: new Date("2026-09-15T00:00:00Z") }));
      expect(late.status).toBe("inserted");
      if (late.status === "inserted") {
        expect(late.entry.periodId).toBe("2026-10");
        expect(late.entry.originalPeriodId).toBe("2026-09");
      }
      expect(await ledger.totals(t1, "2026-09")).toEqual([{ meter: "tokens_in", dimension: "standard", quantity: 10n }]);
      expect(await ledger.totals(t1, "2026-10")).toEqual([{ meter: "tokens_in", dimension: "standard", quantity: 99n }]);
      expect(await ledger.verifySeal(t1, "2026-09")).toEqual({ ok: true });
      expect((await ledger.seals(t1))[0]?.sealHash).toBe(seal.sealHash);
      // a replay of the late event stays a duplicate and does not move
      const again = await ledger.append(usage(t1, { quantity: 99n, eventTime: new Date("2026-09-15T00:00:00Z"), idempotencyKey: late.status === "inserted" ? late.entry.idempotencyKey : "" }));
      expect(again.status).toBe("duplicate");
    });

    it("skips every sealed month when attributing a late event", async () => {
      const { ledger, clock, t1 } = await setup();
      await ledger.closePeriod(t1, "2026-08");
      await ledger.closePeriod(t1, "2026-09");
      clock.set("2026-12-02T00:00:00Z");
      await ledger.closePeriod(t1, "2026-10");
      const late = await ledger.append(usage(t1, { eventTime: new Date("2026-08-15T00:00:00Z") }));
      expect(late.status === "inserted" && late.entry.periodId).toBe("2026-11");
    });

    it("is order independent for out-of-order arrival", async () => {
      const a = await setup();
      const b = await setup();
      const items = [1n, 2n, 3n, 4n, 5n].map((q, i) =>
        usage("", { idempotencyKey: `k${i}`, quantity: q, eventTime: new Date(Date.UTC(2026, 8, 10 - i)) }),
      );
      for (const i of items) await a.ledger.append({ ...i, tenantId: a.t1 });
      for (const i of [...items].reverse()) await b.ledger.append({ ...i, tenantId: b.t1 });
      expect(await a.ledger.totals(a.t1, "2026-09")).toEqual(await b.ledger.totals(b.t1, "2026-09"));
    });

    it("handles concurrent identical appends as one insert", async () => {
      const { ledger, t1 } = await setup();
      const u = usage(t1);
      const rs = await Promise.all(Array.from({ length: 8 }, () => ledger.append({ ...u })));
      expect(rs.filter((r) => r.status === "inserted")).toHaveLength(1);
      expect(rs.filter((r) => r.status === "duplicate")).toHaveLength(7);
    });
  });
}
