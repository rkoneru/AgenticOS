import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { randomUUID } from "node:crypto";
import { BillingError } from "../src/index.js";
import { ledgerContract } from "./ledger-contract.js";
import { Clock, adminClient, memLedger, newPool, newTenant, pgLedger, usage } from "./helpers.js";

ledgerContract("memory", () => {
  const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
  return Promise.resolve({ ledger: memLedger(clock), clock, tenant: () => Promise.resolve(randomUUID()) });
});

describe("postgres", () => {
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
  ledgerContract("postgres", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    return { ledger: pgLedger(pool, clock), clock, tenant: () => newTenant(admin) };
  });

  it("is insert-only for the app role and for the owner (triggers)", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t = await newTenant(admin);
    await l.append(usage(t));
    await expect(admin.query("UPDATE usage_events SET quantity = 1 WHERE tenant_id = $1", [t])).rejects.toThrow(/append-only/);
    await expect(admin.query("DELETE FROM usage_events WHERE tenant_id = $1", [t])).rejects.toThrow(/append-only/);
    await expect(admin.query("TRUNCATE usage_events")).rejects.toThrow(/append-only/);
  });

  it("denies UPDATE/DELETE to axis_app by privilege and hides other tenants (forced RLS)", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t1 = await newTenant(admin);
    const t2 = await newTenant(admin);
    await l.append(usage(t1));
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      await c.query("SELECT axis.set_tenant($1::uuid)", [t2]);
      expect((await c.query("SELECT * FROM usage_events")).rowCount).toBe(0);
      await expect(c.query("UPDATE usage_events SET quantity = 0")).rejects.toThrow(/permission denied/);
      await c.query("ROLLBACK");
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      await c.query("SELECT axis.set_tenant($1::uuid)", [t2]);
      // inserting for another tenant violates the policy
      await expect(
        c.query(
          `INSERT INTO usage_events (tenant_id, idempotency_key, payload_hash, entry_type, meter, quantity, event_time, period_id, source)
           VALUES ($1, 'x', $2, 'usage', 'tokens_in', 1, now(), '2026-10', 's')`,
          [t1, "a".repeat(64)],
        ),
      ).rejects.toThrow(/row-level security/);
      await c.query("ROLLBACK");
      // no tenant set: nothing visible
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      expect((await c.query("SELECT * FROM usage_events")).rowCount).toBe(0);
      await c.query("ROLLBACK");
    } finally {
      c.release();
    }
  });

  it("refuses an insert into a sealed period even if the caller computed the period itself (DB trigger)", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t = await newTenant(admin);
    await l.append(usage(t));
    await l.closePeriod(t, "2026-09");
    await expect(
      admin.query(
        `INSERT INTO usage_events (tenant_id, idempotency_key, payload_hash, entry_type, meter, quantity, event_time, period_id, source)
         VALUES ($1, 'sneak', $2, 'usage', 'tokens_in', 1, now(), '2026-09', 's')`,
        [t, "a".repeat(64)],
      ),
    ).rejects.toThrow(/sealed/);
    await expect(admin.query("UPDATE billing_period_seals SET event_count = 0")).rejects.toThrow(/append-only/);
  });

  it("detects tampering with a sealed period (owner bypassing triggers)", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t = await newTenant(admin);
    await l.append(usage(t, { quantity: 10n }));
    await l.closePeriod(t, "2026-09");
    await admin.query("ALTER TABLE usage_events DISABLE TRIGGER USER");
    await admin.query("UPDATE usage_events SET quantity = 11 WHERE tenant_id = $1", [t]);
    await admin.query("ALTER TABLE usage_events ENABLE TRIGGER USER");
    const v = await l.verifySeal(t, "2026-09");
    expect(v.ok).toBe(false);
  });

  it("seal verification fails on a forged signature or hash", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t = await newTenant(admin);
    await l.append(usage(t));
    await l.closePeriod(t, "2026-09");
    await admin.query("ALTER TABLE billing_period_seals DISABLE TRIGGER USER");
    await admin.query("UPDATE billing_period_seals SET signature = $2 WHERE tenant_id = $1", [t, "00"]);
    await admin.query("ALTER TABLE billing_period_seals ENABLE TRIGGER USER");
    expect(await l.verifySeal(t, "2026-09")).toEqual({ ok: false, reason: "bad signature" });
  });

  it("rejects a bad tenant id without touching the database", async () => {
    const l = pgLedger(pool, new Clock(new Date()));
    await expect(l.entries("nope")).rejects.toBeInstanceOf(BillingError);
  });

  it("a concurrent close and insert never lands an entry in the sealed period", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const l = pgLedger(pool, clock);
    const t = await newTenant(admin);
    await l.append(usage(t, { quantity: 1n }));
    const ops = [l.closePeriod(t, "2026-09") as Promise<unknown>];
    for (let i = 0; i < 10; i++) ops.push(l.append(usage(t, { quantity: 1n })));
    await Promise.all(ops);
    expect(await l.verifySeal(t, "2026-09")).toEqual({ ok: true });
  });
});
