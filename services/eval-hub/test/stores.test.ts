import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  DocConflict,
  DocForbidden,
  MemoryDocStore,
  PgDocStore,
  type DocStore,
} from "../src/index.js";
import {
  HASH_A,
  HASH_B,
  adminClient,
  newPool,
  newTenantRow,
  registerRunner,
  runWithScore,
  seedSuite,
  world,
  bp,
} from "./helpers.js";

let admin: pg.Client;
let pool: pg.Pool;
let tenantA: string;
let tenantB: string;

beforeAll(async () => {
  admin = await adminClient();
  pool = newPool();
  tenantA = await newTenantRow(admin);
  tenantB = await newTenantRow(admin);
});
afterAll(async () => {
  await pool.end();
  await admin.end();
});

const stores: [string, () => DocStore][] = [
  ["memory", () => new MemoryDocStore()],
  ["postgres (forced RLS, axis_app)", () => new PgDocStore({ pool, role: "axis_app" })],
];

describe.each(stores)("DocStore contract: %s", (_n, mk) => {
  it("insert / get / find with isolation between tenants", async () => {
    const s = mk();
    const k = `k-${randomUUID()}`;
    const d = await s.insert(tenantA, "suites", k, { a: 1, tag: "x" });
    expect(d).toMatchObject({
      tenantId: tenantA,
      coll: "suites",
      key: k,
      rev: 1,
      data: { a: 1, tag: "x" },
    });
    expect((await s.get(tenantA, "suites", k))?.data).toEqual({ a: 1, tag: "x" });
    await expect(s.insert(tenantA, "suites", k, {})).rejects.toBeInstanceOf(DocConflict);
    expect(await s.get(tenantB, "suites", k)).toBeUndefined();
    expect((await s.find(tenantA, "suites", { tag: "x" })).map((x) => x.key)).toContain(k);
    expect(await s.find(tenantB, "suites", { tag: "x" })).toEqual([]);
    // the same key can exist in another tenant
    await s.insert(tenantB, "suites", k, { a: 2 });
    expect((await s.get(tenantB, "suites", k))?.data).toEqual({ a: 2 });
    expect((await s.get(tenantA, "suites", k))?.data).toEqual({ a: 1, tag: "x" });
  });

  it("append-only collections reject updates", async () => {
    const s = mk();
    for (const coll of ["datasets", "suites", "baselines", "online", "events"]) {
      const k = `k-${randomUUID()}`;
      await s.insert(tenantA, coll, k, { v: 1 });
      await expect(s.update(tenantA, coll, k, 1, { v: 2 })).rejects.toBeInstanceOf(DocForbidden);
      expect((await s.get(tenantA, coll, k))?.data).toEqual({ v: 1 });
    }
  });

  it("optimistic revisions: a stale update conflicts; a missing document is forbidden", async () => {
    const s = mk();
    const k = `k-${randomUUID()}`;
    await s.insert(tenantA, "sampling", k, { v: 1 });
    expect((await s.update(tenantA, "sampling", k, 1, { v: 2 })).rev).toBe(2);
    await expect(s.update(tenantA, "sampling", k, 1, { v: 3 })).rejects.toBeInstanceOf(DocConflict);
    await expect(s.update(tenantA, "sampling", `nope-${k}`, 1, { v: 3 })).rejects.toBeInstanceOf(
      DocForbidden,
    );
    // another tenant cannot update it
    await expect(s.update(tenantB, "sampling", k, 2, { v: 9 })).rejects.toBeInstanceOf(
      DocForbidden,
    );
    expect((await s.get(tenantA, "sampling", k))?.data).toEqual({ v: 2 });
  });

  it("a finished run, a revoked runner and a resolved task are frozen; open ones are not", async () => {
    const s = mk();
    const open = `r-${randomUUID()}`;
    await s.insert(tenantA, "runs", open, { status: "running" });
    await s.update(tenantA, "runs", open, 1, { status: "passed" });
    await expect(s.update(tenantA, "runs", open, 2, { status: "failed" })).rejects.toBeInstanceOf(
      DocForbidden,
    );
    const rn = `rn-${randomUUID()}`;
    await s.insert(tenantA, "runners", rn, { revoked_at: null });
    await s.update(tenantA, "runners", rn, 1, { revoked_at: "2026-10-08T00:00:00Z" });
    await expect(s.update(tenantA, "runners", rn, 2, { revoked_at: null })).rejects.toBeInstanceOf(
      DocForbidden,
    );
    const t = `t-${randomUUID()}`;
    await s.insert(tenantA, "tasks", t, { state: "open" });
    await s.update(tenantA, "tasks", t, 1, { state: "resolved" });
    await expect(s.update(tenantA, "tasks", t, 2, { state: "open" })).rejects.toBeInstanceOf(
      DocForbidden,
    );
  });

  it("find returns documents ordered by key", async () => {
    const s = mk();
    const tag = randomUUID();
    for (const k of ["b", "a", "c"]) await s.insert(tenantA, "events", `${tag}-${k}`, { tag });
    expect((await s.find(tenantA, "events", { tag })).map((d) => d.key)).toEqual([
      `${tag}-a`,
      `${tag}-b`,
      `${tag}-c`,
    ]);
  });
});

describe("Postgres row level security", () => {
  it("is enabled and forced, and a query without a tenant sees nothing", async () => {
    const r = await admin.query(
      "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'eval_hub_docs'",
    );
    expect(r.rows[0]).toEqual({ relrowsecurity: true, relforcerowsecurity: true });
    const s = new PgDocStore({ pool, role: "axis_app" });
    await s.insert(tenantA, "suites", `rls-${randomUUID()}`, {});
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      expect((await c.query("SELECT count(*)::int AS n FROM eval_hub_docs")).rows[0].n).toBe(0);
      await expect(
        c.query(
          "INSERT INTO eval_hub_docs (tenant_id, coll, key, rev, data) VALUES ($1,'suites','x',1,'{}')",
          [tenantA],
        ),
      ).rejects.toMatchObject({ code: "42501" });
      await c.query("ROLLBACK");
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      await c.query("SELECT axis.set_tenant($1::uuid)", [tenantB]);
      // tenant B cannot write a row for tenant A, and cannot delete anything
      await expect(
        c.query(
          "INSERT INTO eval_hub_docs (tenant_id, coll, key, rev, data) VALUES ($1,'suites','y',1,'{}')",
          [tenantA],
        ),
      ).rejects.toMatchObject({ code: "42501" });
      await c.query("ROLLBACK");
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      await c.query("SELECT axis.set_tenant($1::uuid)", [tenantA]);
      await expect(c.query("DELETE FROM eval_hub_docs")).rejects.toMatchObject({ code: "42501" });
    } finally {
      await c.query("ROLLBACK");
      c.release();
    }
  });

  it("the database itself refuses to alter a finished run (not just the service)", async () => {
    const id = randomUUID();
    await admin.query(
      "INSERT INTO eval_hub_docs (tenant_id, coll, key, rev, data) VALUES ($1,'runs',$2,1,'{\"status\":\"passed\"}')",
      [tenantA, id],
    );
    await expect(
      admin.query(
        'UPDATE eval_hub_docs SET rev = 2, data = \'{"status":"failed"}\' WHERE key = $1',
        [id],
      ),
    ).rejects.toMatchObject({ code: "42501" });
    await expect(
      admin.query("DELETE FROM eval_hub_docs WHERE key = $1", [id]),
    ).rejects.toMatchObject({ code: "42501" });
  });
});

describe("the whole hub on Postgres", () => {
  it("runs the dataset -> suite -> run -> baseline -> gate flow on the Postgres store, isolated per tenant", async () => {
    const tenant = await newTenantRow(admin);
    const other = await newTenantRow(admin);
    const w = world({ docs: new PgDocStore({ pool, role: "axis_app" }), tenant });
    await seedSuite(w);
    await registerRunner(w);
    const good = await runWithScore(w, { hash: HASH_A, score: 0.95 });
    await w.hub.baselines.set(w.admin, { run_id: good.id });
    w.clock.advance(1000);
    await runWithScore(w, { hash: HASH_B, score: 0.5 });
    const ok = await w.hub.gate.check(w.builder, {
      blueprint: bp(HASH_A),
      suites: [{ ref: "smoke@1.0.0", threshold: 0.8 }],
    });
    const bad = await w.hub.gate.check(w.builder, {
      blueprint: bp(HASH_B),
      suites: [{ ref: "smoke@1.0.0", threshold: 0.8 }],
    });
    expect(ok.allowed).toBe(true);
    expect(bad.allowed).toBe(false);
    expect(bad.reasons.map((r) => r.code).sort()).toEqual(["below_threshold", "regression"]);
    const w2 = world({ docs: new PgDocStore({ pool, role: "axis_app" }), tenant: other });
    expect((await w2.hub.runs.list(w2.admin)).items).toEqual([]);
    expect(
      (
        await w2.hub.gate.check(w2.builder, {
          blueprint: bp(HASH_A),
          suites: [{ ref: "smoke@1.0.0" }],
        })
      ).reasons[0]?.code,
    ).toBe("suite_not_found");
    expect((await w.hub.runs.list(w.admin)).items).toHaveLength(2);
  });
});
