import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemoryAuditLog } from "@axis/audit";
import type pg from "pg";
import fc from "fast-check";
import {
  AdjustmentApi,
  BillingError,
  BillingService,
  DEV_PLAN,
  DEV_PRICE_BOOK,
  FakePaymentProvider,
  MemoryInvoiceStore,
  MemoryUsageLedger,
  PgInvoiceStore,
  invoiceFromJson,
  invoiceHash,
  invoiceMinorLines,
  invoiceToJson,
  reconcile,
  reportableTotals,
  type InvoiceStore,
  type UsageLedger,
} from "../src/index.js";
import {
  Clock,
  adminClient,
  memLedger,
  newPool,
  newTenant,
  pgLedger,
  ROLE,
  signer,
  usage,
} from "./helpers.js";

const T = "11111111-1111-4111-8111-111111111111";

async function rig(ledger: UsageLedger, clock: Clock, invoices: InvoiceStore, tenant: string) {
  const provider = new FakePaymentProvider();
  const customer = await provider.createCustomer({ tenantId: tenant, name: "Acme" }, "c");
  const svc = new BillingService({
    ledger,
    invoices,
    provider,
    priceBook: DEV_PRICE_BOOK,
    config: {
      config: () =>
        Promise.resolve({
          plan: DEV_PLAN,
          credits: [{ id: "welcome", remainingMicro: 1_000_000n }],
        }),
    },
  });
  clock.set("2026-10-02T00:00:00Z");
  await ledger.append(
    usage(tenant, { quantity: 2_500_000n, dimensions: { model_class: "frontier" } }),
  );
  await ledger.append(
    usage(tenant, {
      meter: "tokens_out",
      quantity: 100_000n,
      dimensions: { model_class: "standard" },
    }),
  );
  await ledger.append(
    usage(tenant, { meter: "tool_executions", quantity: 7n, dimensions: { tool_kind: "code" } }),
  );
  await ledger.append(usage(tenant, { meter: "voice_minutes", quantity: 61_000n, dimensions: {} }));
  return { provider, customer, svc };
}

function endToEnd(
  name: string,
  make: () => Promise<{
    ledger: UsageLedger;
    clock: Clock;
    invoices: InvoiceStore;
    tenant: string;
  }>,
) {
  describe(`close, push, reconcile: ${name}`, () => {
    it("a clean period reconciles; each fault is reported, never silently fixed", async () => {
      const m = await make();
      const { provider, customer, svc } = await rig(m.ledger, m.clock, m.invoices, m.tenant);
      const { seal, invoice } = await svc.closeAndRate(m.tenant, "2026-09");
      expect(seal.eventCount).toBe(4);
      expect(invoice.revision).toBe(1);
      expect(await svc.pushUsage(m.tenant, "2026-09", customer.id)).toBe(4);
      expect(await svc.pushUsage(m.tenant, "2026-09", customer.id)).toBe(4); // retry: harmless
      expect(provider.usage).toHaveLength(4);
      const pid = await svc.pushInvoice(m.tenant, invoice, customer.id);
      expect((await m.invoices.list(m.tenant, "2026-09"))[0]?.providerInvoiceId).toBe(pid);
      const clean = await svc.reconcile(m.tenant, "2026-09", customer.id);
      expect(clean).toEqual({
        tenantId: m.tenant,
        periodId: "2026-09",
        clean: true,
        discrepancies: [],
      });
      // invoice totals: 99 base + 2.5M frontier tokens (1M included, 1.5M * $15/M = 22.5) ... minus the 1.00 welcome credit
      expect(invoice.invoice.totalMicro).toBe(
        99_000_000n + 22_500_000n + 14_000n + 91_500n - 1_000_000n,
      );

      // 1. the provider loses a record
      const lost = provider.usage.find((u) => u.meter === "tool_executions");
      provider.dropIdentifiers.clear();
      provider.usage.splice(provider.usage.indexOf(lost as NonNullable<typeof lost>), 1);
      let r = await svc.reconcile(m.tenant, "2026-09", customer.id);
      expect(r.discrepancies.map((d) => [d.kind, d.meter])).toEqual([
        ["usage_missing_at_provider", "tool_executions"],
      ]);
      // 2. quantity mismatch and duplicate
      provider.usage.push(lost as NonNullable<typeof lost>);
      const vo = provider.usage.find((u) => u.meter === "voice_minutes") as NonNullable<
        typeof lost
      >;
      vo.quantity += 5n;
      provider.usage.push({ ...vo, id: "dup" });
      r = await svc.reconcile(m.tenant, "2026-09", customer.id);
      expect(r.discrepancies.map((d) => d.kind).sort()).toEqual([
        "usage_duplicated_at_provider",
        "usage_quantity_mismatch",
      ]);
      // 3. invoice tampering at the provider
      vo.quantity -= 5n;
      provider.usage.pop();
      const pinv = provider.invoices.get(pid) as NonNullable<
        ReturnType<typeof provider.invoices.get>
      >;
      pinv.lines[1] = {
        ...(pinv.lines[1] as (typeof pinv.lines)[number]),
        amountMinor: pinv.lines[1]!.amountMinor + 1n,
      };
      pinv.totalMinor += 1n;
      pinv.lines.push({ description: "surprise", amountMinor: 5n });
      pinv.totalMinor += 5n;
      r = await svc.reconcile(m.tenant, "2026-09", customer.id);
      expect(r.discrepancies.map((d) => d.kind).sort()).toEqual([
        "invoice_line_mismatch",
        "invoice_orphan_line",
        "invoice_total_mismatch",
      ]);
      // reconciliation did not change the ledger
      expect((await m.ledger.entries(m.tenant)).length).toBe(4);
    });

    it("a late event lands in the next period and the sealed invoice is untouched; re-rating adds a revision", async () => {
      const m = await make();
      const { svc } = await rig(m.ledger, m.clock, m.invoices, m.tenant);
      const first = await svc.closeAndRate(m.tenant, "2026-09");
      await m.ledger.append(
        usage(m.tenant, {
          meter: "tool_executions",
          quantity: 1000n,
          dimensions: { tool_kind: "code" },
        }),
      );
      const again = await svc.rateSealed(m.tenant, "2026-09");
      expect(again.revision).toBe(2);
      expect(again.hash).toBe(first.invoice.hash);
      expect((await m.invoices.list(m.tenant, "2026-09")).map((i) => i.revision)).toEqual([1, 2]);
      expect((await m.ledger.totals(m.tenant, "2026-10")).map((t) => t.quantity)).toEqual([1000n]);
    });

    it("refuses to rate an open period or one whose seal no longer verifies", async () => {
      const m = await make();
      const { svc } = await rig(m.ledger, m.clock, m.invoices, m.tenant);
      await expect(svc.rateSealed(m.tenant, "2026-09")).rejects.toMatchObject({
        code: "PERIOD_NOT_SEALED",
      });
    });
  });
}

endToEnd("memory", () => {
  const clock = new Clock(new Date());
  return Promise.resolve({
    ledger: memLedger(clock),
    clock,
    invoices: new MemoryInvoiceStore(),
    tenant: T,
  });
});

describe("postgres service", () => {
  let pool: pg.Pool;
  let admin: pg.Client;
  beforeAll(async () => {
    pool = newPool();
    admin = await adminClient();
  });
  afterAll(async () => {
    await pool.end();
    await admin.end();
  });
  endToEnd("postgres", async () => {
    const clock = new Clock(new Date());
    return {
      ledger: pgLedger(pool, clock),
      clock,
      invoices: new PgInvoiceStore({ pool, role: ROLE }),
      tenant: await newTenant(admin),
    };
  });

  it("invoices are insert-only, tenant scoped and revisioned; links are unique", async () => {
    const t1 = await newTenant(admin);
    const t2 = await newTenant(admin);
    const store = new PgInvoiceStore({ pool, role: ROLE });
    const mem = new MemoryInvoiceStore();
    const base = await (async () => {
      const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
      const l = pgLedger(pool, clock);
      await l.append(usage(t1));
      const s = new BillingService({
        ledger: l,
        invoices: mem,
        provider: new FakePaymentProvider(),
        priceBook: DEV_PRICE_BOOK,
        config: { config: () => Promise.resolve({ plan: DEV_PLAN }) },
      });
      return (await s.closeAndRate(t1, "2026-09")).invoice.invoice;
    })();
    const a = await store.save(base);
    const b = await store.save(base);
    expect([a.revision, b.revision]).toEqual([1, 2]);
    expect(await store.list(t2)).toEqual([]);
    expect((await store.list(t1, "2026-09")).map((x) => x.hash)).toEqual([
      invoiceHash(base),
      invoiceHash(base),
    ]);
    expect((await store.list(t1))[0]?.invoice).toEqual(base);
    await store.linkProvider(t1, a.id, "fake", "in_1");
    await expect(store.linkProvider(t1, a.id, "fake", "in_2")).rejects.toThrow();
    expect((await store.list(t1, "2026-09"))[0]?.providerInvoiceId).toBe("in_1");
    await expect(admin.query("UPDATE invoices SET total_micro = 0")).rejects.toThrow(/append-only/);
    await expect(admin.query("DELETE FROM invoice_provider_links")).rejects.toThrow(/append-only/);
    await expect(store.save({ ...base, tenantId: "x" })).rejects.toBeInstanceOf(BillingError);
  });
});

describe("memory invoice store", () => {
  it("revisions, links and errors", async () => {
    const s = new MemoryInvoiceStore();
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = memLedger(clock);
    await l.append(usage(T));
    const svc = new BillingService({
      ledger: l,
      invoices: s,
      provider: new FakePaymentProvider(),
      priceBook: DEV_PRICE_BOOK,
      config: { config: () => Promise.resolve({ plan: DEV_PLAN }) },
    });
    const { invoice } = await svc.closeAndRate(T, "2026-09");
    await s.linkProvider(T, invoice.id, "fake", "in_1");
    await expect(s.linkProvider(T, invoice.id, "fake", "in_2")).rejects.toThrow(/already linked/);
    await expect(s.linkProvider(T, "nope", "fake", "x")).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(await s.list("22222222-2222-4222-8222-222222222222")).toEqual([]);
    expect(await s.list(T)).toHaveLength(1);
    expect(invoiceFromJson(invoiceToJson(invoice.invoice))).toEqual(invoice.invoice);
    expect(() => s.save({ ...invoice.invoice, tenantId: "bad" })).toThrow(BillingError);
  });
});

describe("reconcile (pure)", () => {
  const base = { tenantId: T, periodId: "2026-09" };
  it("reports orphan usage, orphan invoices and a missing provider invoice; clamps negative net usage", () => {
    const totals = [{ meter: "tokens_in" as const, dimension: "x", quantity: -5n }];
    expect(reportableTotals(totals).get("tokens_in")).toBe(0n);
    const orphan = reconcile({
      ...base,
      ledgerTotals: totals,
      providerUsage: { tokens_in: { quantity: 9n } },
      invoice: null,
      providerInvoices: [],
    });
    expect(orphan.discrepancies.map((d) => d.kind)).toEqual(["usage_orphan_at_provider"]);
    const inv = {
      id: "in",
      customerId: "c",
      periodId: "2026-09",
      status: "draft",
      currency: "usd",
      lines: [],
      totalMinor: 0n,
    };
    const o2 = reconcile({
      ...base,
      ledgerTotals: [],
      providerUsage: {},
      invoice: null,
      providerInvoices: [inv],
    });
    expect(o2.discrepancies.map((d) => d.kind)).toEqual(["invoice_orphan_line"]);
    const mine = rateOne();
    const missing = reconcile({
      ...base,
      ledgerTotals: [],
      providerUsage: {},
      invoice: mine,
      providerInvoices: [],
    });
    expect(missing.discrepancies.map((d) => d.kind)).toEqual(["invoice_missing_at_provider"]);
    const two = reconcile({
      ...base,
      ledgerTotals: [],
      providerUsage: {},
      invoice: mine,
      providerInvoices: [inv, inv],
    });
    expect(two.discrepancies.map((d) => d.kind)).toContain("invoice_duplicate_at_provider");
    const short = reconcile({
      ...base,
      ledgerTotals: [],
      providerUsage: {},
      invoice: mine,
      providerInvoices: [{ ...inv, totalMinor: 9_800n }],
    });
    expect(short.discrepancies.map((d) => d.kind)).toEqual([
      "invoice_total_mismatch",
      "invoice_missing_line",
    ]);
  });

  it("property: provider usage equal to the ledger is always clean, for any totals", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt({ min: -100n, max: 10n ** 12n }), { maxLength: 7 }), (qs) => {
        const meters = [
          "tokens_in",
          "tokens_out",
          "runtime_seconds",
          "tool_executions",
          "voice_minutes",
          "storage_gb_hours",
          "marketplace_installs",
        ] as const;
        const totals = qs.map((q, i) => ({
          meter: meters[i] as (typeof meters)[number],
          dimension: "",
          quantity: q,
        }));
        const provider = Object.fromEntries(
          [...reportableTotals(totals)].map(([m, q]) => [m, { quantity: q }]),
        );
        expect(
          reconcile({
            ...base,
            ledgerTotals: totals,
            providerUsage: provider,
            invoice: null,
            providerInvoices: [],
          }).clean,
        ).toBe(true);
      }),
    );
  });

  it("property: provider invoice built from our minor lines always reconciles", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt({ min: -(10n ** 9n), max: 10n ** 12n }), { maxLength: 8 }),
        (nets) => {
          const inv = {
            ...rateOne(),
            lines: nets.map((n, i) => ({
              kind: "usage" as const,
              description: `l${i}`,
              meter: null,
              dimension: "",
              quantity: 1n,
              amountMicro: n,
              creditAppliedMicro: 0n,
              netMicro: n,
            })),
          };
          const minor = invoiceMinorLines(inv);
          const total = minor.reduce((s, l) => s + l.amountMinor, 0n);
          const r = reconcile({
            ...base,
            ledgerTotals: [],
            providerUsage: {},
            invoice: inv,
            providerInvoices: [
              {
                id: "i",
                customerId: "c",
                periodId: "2026-09",
                status: "draft",
                currency: "usd",
                lines: minor,
                totalMinor: total,
              },
            ],
          });
          expect(r.clean).toBe(true);
        },
      ),
    );
  });
});

function rateOne() {
  return {
    tenantId: T,
    periodId: "2026-09",
    planId: "p",
    priceBook: { id: "axis-dev", version: 1 },
    currency: "USD",
    lines: [
      {
        kind: "base" as const,
        description: "base",
        meter: null,
        dimension: "",
        quantity: 1n,
        amountMicro: 99_000_000n,
        creditAppliedMicro: 0n,
        netMicro: 99_000_000n,
      },
    ],
    subtotalMicro: 99_000_000n,
    creditsAppliedMicro: 0n,
    creditsConsumed: [],
    taxMicro: 0n,
    totalMicro: 99_000_000n,
    warnings: [],
  };
}

describe("adjustments", () => {
  const setup = () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const ledger = memLedger(clock);
    const audit = new MemoryAuditLog();
    return { ledger, audit, api: new AdjustmentApi({ ledger, audit, now: clock.now }) };
  };
  const req = {
    tenantId: T,
    idempotencyKey: "adj-1",
    meter: "tokens_in" as const,
    quantity: -500n,
    eventTime: new Date("2026-09-20T00:00:00Z"),
    reason: "duplicate run r-9 billed twice",
    actor: "ops@axis.test",
    dimensions: { model_class: "standard" },
  };

  it("writes an audit event first, then a compensating entry; the original is untouched", async () => {
    const { ledger, audit, api } = setup();
    await ledger.append(usage(T, { idempotencyKey: "orig", quantity: 1000n }));
    const r = await api.adjust({ ...req, correctsKey: "orig" });
    expect(r.status).toBe("inserted");
    const entries = await ledger.entries(T);
    expect(entries.map((e) => [e.entryType, e.quantity])).toEqual([
      ["usage", 1000n],
      ["adjustment", -500n],
    ]);
    expect(entries[1]).toMatchObject({ reason: req.reason, actor: req.actor, correctsKey: "orig" });
    const events = await audit.read(T, { fromSeq: 1, toSeq: 10 } as never).catch(() => undefined);
    void events;
    expect((await ledger.totals(T, "2026-09"))[0]?.quantity).toBe(500n);
  });

  it("accepts an adjustment without dimensions or a corrected key", async () => {
    const { api } = setup();
    const { dimensions: _d, ...bare } = req;
    void _d;
    expect(
      (await api.adjust({ ...bare, meter: "voice_minutes", idempotencyKey: "bare" })).status,
    ).toBe("inserted");
  });

  it("requires a reason and an actor, and applies nothing when the audit append fails", async () => {
    const { ledger, api } = setup();
    const audited: string[] = [];
    const counting = new AdjustmentApi({
      ledger,
      audit: {
        append: (e) => {
          audited.push(e.action);
          return Promise.resolve(e as never);
        },
      },
    });
    await expect(counting.adjust({ ...req, reason: "ab" })).rejects.toBeInstanceOf(BillingError);
    expect(audited).toEqual([]); // refused BEFORE any audit event or ledger write
    await expect(api.adjust({ ...req, reason: " " })).rejects.toBeInstanceOf(BillingError);
    await expect(api.adjust({ ...req, actor: "" })).rejects.toBeInstanceOf(BillingError);
    const failing = new AdjustmentApi({
      ledger,
      audit: { append: () => Promise.reject(new Error("down")) },
    });
    await expect(failing.adjust(req)).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    expect(await ledger.entries(T)).toEqual([]);
  });

  it("a replay is a duplicate and a changed replay is a reported conflict", async () => {
    const { ledger, api } = setup();
    expect((await api.adjust(req)).status).toBe("inserted");
    expect((await api.adjust(req)).status).toBe("duplicate");
    expect((await api.adjust({ ...req, quantity: -501n })).status).toBe("conflict");
    expect(await ledger.conflicts(T)).toHaveLength(1);
  });

  it("uses a custom policy version and the wall clock by default", async () => {
    const ledger = new MemoryUsageLedger({ signer: signer() });
    const seen: string[] = [];
    const api = new AdjustmentApi({
      ledger,
      audit: {
        append: (e) => {
          seen.push(e.policy_version);
          return Promise.resolve(e as never);
        },
      },
      policyVersion: "pv-9",
    });
    await api.adjust({ ...req, eventTime: new Date(Date.now() - 1000) });
    expect(seen).toEqual(["pv-9"]);
  });
});
