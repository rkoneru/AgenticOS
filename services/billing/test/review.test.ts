// Independent Phase 6 review: regression tests for defects found by the adversarial reviewer.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import type pg from "pg";
import {
  BillingService,
  DEV_PLAN,
  DEV_PRICE_BOOK,
  FakePaymentProvider,
  MemoryInvoiceStore,
  StripeWebhookProcessor,
  stripeSignature,
} from "../src/index.js";
import { Clock, adminClient, memLedger, newPool, newTenant, pgLedger, usage } from "./helpers.js";

describe("review: webhook retry after a failed handler", () => {
  const secret = "whsec_test";
  const NOW = 1_700_000_000_000;
  const body = JSON.stringify({ id: "evt_r1", type: "invoice.paid", data: { object: {} } });
  const hdr = `t=${NOW / 1000},v1=${stripeSignature(secret, NOW / 1000, body)}`;

  it("a handler that throws must not burn the event id: the provider's retry is processed", async () => {
    let calls = 0;
    const proc = new StripeWebhookProcessor({
      secret,
      now: () => NOW,
      handlers: {
        "invoice.paid": () => {
          calls++;
          return calls === 1 ? Promise.reject(new Error("db down")) : Promise.resolve();
        },
      },
    });
    await expect(proc.handle(body, hdr)).rejects.toThrow("db down");
    // Stripe redelivers the same event; it must be handled now, not acknowledged as a duplicate and lost.
    expect(await proc.handle(body, hdr)).toBe("processed");
    expect(calls).toBe(2);
    expect(await proc.handle(body, hdr)).toBe("duplicate");
  });
});

describe("review: provider usage push needs a sealed period", () => {
  it("refuses to push an open period (a later push would be deduplicated by identifier and under-bill)", async () => {
    const clock = new Clock(new Date("2026-09-20T00:00:00Z"));
    const ledger = memLedger(clock);
    const t = randomUUID();
    await ledger.append(usage(t, { quantity: 10n }));
    const provider = new FakePaymentProvider();
    const cust = await provider.createCustomer({ tenantId: t, name: "x" }, "c");
    const svc = new BillingService({
      ledger,
      invoices: new MemoryInvoiceStore(),
      provider,
      priceBook: DEV_PRICE_BOOK,
      config: { config: () => Promise.resolve({ plan: DEV_PLAN }) },
    });
    await expect(svc.pushUsage(t, "2026-09", cust.id)).rejects.toMatchObject({
      code: "PERIOD_NOT_SEALED",
    });
    expect(provider.usage).toHaveLength(0);
  });
});

describe("review: tenant id spelling must not change locking or identity (postgres)", () => {
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

  it("closePeriod with an upper-case UUID still waits for an in-flight insert of the same tenant", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t = await newTenant(admin);
    await l.append(usage(t, { eventTime: new Date("2026-09-10T12:00:00Z") }));
    // An in-flight insert holds the shared lock the trigger takes (lower-case canonical text of the uuid).
    const holder = await pool.connect();
    try {
      await holder.query("BEGIN");
      await holder.query("SELECT pg_advisory_xact_lock_shared(727280, hashtext($1))", [t]);
      let done = false;
      const closing = l.closePeriod(t.toUpperCase(), "2026-09").then((s) => {
        done = true;
        return s;
      });
      await new Promise((r) => setTimeout(r, 500));
      expect(done).toBe(false); // the sealer must be excluded by the inserter
      await holder.query("COMMIT");
      await closing;
    } finally {
      holder.release();
    }
  });

  it("the same event under an upper-case tenant id is a duplicate, not a conflict", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t = await newTenant(admin);
    const u = usage(t, { idempotencyKey: "same-key" });
    expect((await l.append(u)).status).toBe("inserted");
    expect((await l.append({ ...u, tenantId: t.toUpperCase() })).status).toBe("duplicate");
  });
});
