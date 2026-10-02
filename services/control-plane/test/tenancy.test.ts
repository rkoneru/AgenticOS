import { withTenant } from "@axis/db";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, inject } from "vitest";
import { CpError, MemoryControlPlaneStore, PgControlPlaneStore, RegionGuard, TenantRouter, routerFromStore, type PoolLike } from "../src/index.js";
import { ROLE } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : "other";
  }
};

describe("tenancy tiers: TenantRouter over two real Postgres databases", () => {
  let shared: pg.Pool;
  let dedicated: pg.Pool;
  let adminShared: pg.Client;
  let adminDedicated: pg.Client;
  let store: PgControlPlaneStore;
  const A = randomUUID(); // shared_rls
  const B = randomUUID(); // dedicated_db
  const C = randomUUID(); // single_tenant_vpc, pool not configured

  async function seedTenant(c: pg.Client, id: string, slug: string): Promise<void> {
    await c.query("INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')", [id, slug]);
  }

  beforeAll(async () => {
    shared = new pg.Pool({ connectionString: inject("dbUrl"), max: 4 });
    dedicated = new pg.Pool({ connectionString: inject("dbUrl2"), max: 4 });
    adminShared = new pg.Client({ connectionString: inject("dbUrl") });
    adminDedicated = new pg.Client({ connectionString: inject("dbUrl2") });
    await adminShared.connect();
    await adminDedicated.connect();
    store = new PgControlPlaneStore({ pool: shared, role: ROLE });
    // control plane metadata (placements) lives in the shared control database for every tier
    for (const [id, slug] of [[A, "route-a"], [B, "route-b"], [C, "route-c"]] as const) await seedTenant(adminShared, id, slug);
    await seedTenant(adminDedicated, B, "route-b"); // the dedicated database has its own tenants row for B
    await store.putPlacement({ tenantId: A, isolationTier: "shared_rls" });
    await store.putPlacement({ tenantId: B, isolationTier: "dedicated_db", poolKey: "ded-1" });
    await store.putPlacement({ tenantId: C, isolationTier: "single_tenant_vpc", poolKey: "vpc-9" });
  });
  afterAll(async () => {
    await shared.end();
    await dedicated.end();
    await adminShared.end();
    await adminDedicated.end();
  });

  const router = () => routerFromStore(store, shared, { "ded-1": dedicated });

  async function writeBudget(pool: PoolLike, tenant: string, marker: number): Promise<void> {
    const c = await pool.connect();
    try {
      await withTenant(c, tenant, (x) => x.query("INSERT INTO budgets (tenant_id, scope, metric, period, hard) VALUES ($1,'tenant','tokens','day',$2)", [tenant, marker]), { role: ROLE });
    } finally {
      c.release();
    }
  }
  const count = async (admin: pg.Client, tenant: string): Promise<number> => Number((await admin.query("SELECT count(*) AS n FROM budgets WHERE tenant_id = $1", [tenant])).rows[0].n);

  it("routes shared tenants to the shared pool and dedicated tenants to their own database; data lands only where it is routed", async () => {
    const ra = await router().resolve(A);
    const rb = await router().resolve(B);
    expect(ra).toMatchObject({ tier: "shared_rls" });
    expect(ra.pool).toBe(shared);
    expect(rb).toMatchObject({ tier: "dedicated_db", poolKey: "ded-1" });
    expect(rb.pool).toBe(dedicated);
    await writeBudget(ra.pool, A, 111);
    await writeBudget(rb.pool, B, 222);
    expect(await count(adminShared, A)).toBe(1);
    expect(await count(adminDedicated, A)).toBe(0);
    expect(await count(adminDedicated, B)).toBe(1);
    expect(await count(adminShared, B)).toBe(0);
  });

  it("isolation holds at both layers: RLS inside a database, separate databases across tiers", async () => {
    const readAs = async (pool: PoolLike, asTenant: string) => {
      const c = await pool.connect();
      try {
        return (await withTenant(c, asTenant, (x) => x.query("SELECT hard FROM budgets"), { role: ROLE })).rows.map((r) => Number((r as { hard: string }).hard));
      } finally {
        c.release();
      }
    };
    expect(await readAs(shared, A)).toEqual([111]);
    expect(await readAs(dedicated, B)).toEqual([222]);
    expect(await readAs(shared, B)).toEqual([]); // B's data is not in the shared database, and RLS would hide it anyway
    expect(await readAs(dedicated, A)).toEqual([]);
    // RLS in the shared database: tenant A cannot read tenant B's tenant row even by id
    const c = await shared.connect();
    try {
      const r = await withTenant(c, A, (x) => x.query("SELECT id FROM tenants WHERE id = $1", [B]), { role: ROLE });
      expect(r.rows).toEqual([]);
    } finally {
      c.release();
    }
  });

  it("fails closed: no placement, unconfigured pool, a dedicated tenant is never answered with the shared pool", async () => {
    expect(await code(router().resolve(randomUUID()))).toBe("unavailable");
    expect(await code(router().resolve(C))).toBe("unavailable"); // single_tenant_vpc with no pool configured
    const noDed = new TenantRouter({ placements: store, shared });
    expect(await code(noDed.resolve(B))).toBe("unavailable");
    const aliased = new TenantRouter({ placements: store, shared, dedicated: { "ded-1": shared } });
    expect(await code(aliased.resolve(B))).toBe("unavailable");
    const broken = new TenantRouter({ placements: { getPlacement: () => Promise.reject(new Error("db down")) }, shared, dedicated: { "ded-1": dedicated } });
    expect(await code(broken.resolve(B))).toBe("unavailable");
    expect(await code(broken.resolve(A))).toBe("unavailable");
    // a configured VPC pool resolves with its tier
    const vpc = new TenantRouter({ placements: store, shared, dedicated: { "vpc-9": dedicated } });
    expect(await vpc.resolve(C)).toMatchObject({ tier: "single_tenant_vpc", poolKey: "vpc-9" });
  });

  it("placement rows are tenant-scoped and constrained", async () => {
    await expect(adminShared.query("INSERT INTO tenant_placements (tenant_id, isolation_tier) VALUES ($1, 'dedicated_db')", [randomUUID()])).rejects.toThrow();
    const mem = new MemoryControlPlaneStore();
    expect(await mem.getPlacement(A)).toBeUndefined();
    const r = new TenantRouter({ placements: mem, shared });
    await mem.putPlacement({ tenantId: A, isolationTier: "shared_rls" });
    expect((await r.resolve(A)).pool).toBe(shared);
  });

  it("RegionGuard refuses writes for other regions and unknown tenants", async () => {
    const mem = new MemoryControlPlaneStore();
    const g = new RegionGuard("us-east-1", mem);
    expect(await code(g.assertWritable(randomUUID()))).toBe("not_found");
    const id = randomUUID();
    await mem.provisionTenant({
      tenantId: id, slug: "rg", name: "rg", region: "eu-west-1", phiMode: false, owner: { id: randomUUID(), userRef: "u", email: "a@a.test" },
      packs: [], budgets: [], settings: { retentionAuditDays: 365, retentionTranscriptDays: 1, retentionMemoryDays: 1 }, placement: { isolationTier: "shared_rls" },
    });
    expect(await code(g.assertWritable(id))).toBe("region_mismatch");
    expect(await code(new RegionGuard("eu-west-1", mem).assertWritable(id))).toBe("ok");
  });
});
