import { PgAuditLog } from "@axis/audit";
import { randomUUID } from "node:crypto";
import type { UnsealedEvent } from "@axis/contracts";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { inject } from "vitest";
import { MemoryControlPlaneStore, RoutedAuditLog, TenantRouter } from "../src/index.js";

const ROLE = "axis_app";

describe("RoutedAuditLog over two real Postgres databases", () => {
  let shared: pg.Pool;
  let dedicated: pg.Pool;
  let adminShared: pg.Client;
  let adminDedicated: pg.Client;
  const store = new MemoryControlPlaneStore();
  const A = randomUUID();
  const B = randomUUID();
  const NOPLACE = randomUUID();

  const ev = (tenant: string): UnsealedEvent => ({
    schema_version: 1,
    id: randomUUID(),
    tenant_id: tenant,
    ts: new Date().toISOString(),
    trace_id: randomUUID().replaceAll("-", ""),
    actor: { type: "human", id: "x" },
    blueprint: { name: "control-plane", version: "1" },
    policy_version: "v1",
    enforcement_point: "admin",
    action: "t.test",
    decision: "ALLOW",
    reason: "k=v",
    inputs_hash: "0".repeat(64),
    outputs_hash: "0".repeat(64),
  });
  const count = async (c: pg.Client, t: string): Promise<number> =>
    Number(
      (await c.query("SELECT count(*) AS n FROM audit_events WHERE tenant_id = $1", [t])).rows[0].n,
    );

  beforeAll(async () => {
    shared = new pg.Pool({ connectionString: inject("dbUrl"), max: 4 });
    dedicated = new pg.Pool({ connectionString: inject("dbUrl2"), max: 4 });
    adminShared = new pg.Client({ connectionString: inject("dbUrl") });
    adminDedicated = new pg.Client({ connectionString: inject("dbUrl2") });
    await adminShared.connect();
    await adminDedicated.connect();
    for (const [c, id, slug] of [
      [adminShared, A, "ra-a"],
      [adminShared, B, "ra-b"],
      [adminDedicated, B, "ra-b"],
    ] as const)
      await c.query(
        "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')",
        [id, slug],
      );
    await store.putPlacement({ tenantId: A, isolationTier: "shared_rls" });
    await store.putPlacement({ tenantId: B, isolationTier: "dedicated_db", poolKey: "ded-1" });
  });
  afterAll(async () => {
    await shared.end();
    await dedicated.end();
    await adminShared.end();
    await adminDedicated.end();
  });

  const log = (): RoutedAuditLog =>
    new RoutedAuditLog({
      router: new TenantRouter({ placements: store, shared, dedicated: { "ded-1": dedicated } }),
      open: (pool) => new PgAuditLog({ pool: pool as pg.Pool, role: ROLE }),
    });

  it("a dedicated tenant's events land only in its own database, a shared tenant's only in the shared one, and reads follow", async () => {
    const l = log();
    await l.append(ev(A));
    await l.append(ev(B));
    await l.append(ev(B));
    expect([await count(adminShared, A), await count(adminDedicated, A)]).toEqual([1, 0]);
    expect([await count(adminShared, B), await count(adminDedicated, B)]).toEqual([0, 2]);
    expect((await l.listEvents(B, { limit: 10 })).map((e) => e.seq)).toEqual([1, 2]);
    expect(await l.listEvents(A, { limit: 10 })).toHaveLength(1);
  });

  it("fails closed: no placement, or a dedicated tenant whose pool is not configured, is never written to the shared database", async () => {
    await expect(log().append(ev(NOPLACE))).rejects.toMatchObject({ code: "unavailable" });
    const noPool = new RoutedAuditLog({
      router: new TenantRouter({ placements: store, shared }),
      open: (pool) => new PgAuditLog({ pool: pool as pg.Pool, role: ROLE }),
    });
    await expect(noPool.append(ev(B))).rejects.toMatchObject({ code: "unavailable" });
    expect(await count(adminShared, B)).toBe(0);
    expect(await count(adminShared, NOPLACE)).toBe(0);
  });
});
