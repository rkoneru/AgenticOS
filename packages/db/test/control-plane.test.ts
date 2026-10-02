import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { withTenant } from "../src/index.js";
import { connect, seedTenant } from "./helpers.js";

const A = "c0c0c0c0-0000-4000-8000-c0c0c0c0c0c0";
const B = "d0d0d0d0-0000-4000-8000-d0d0d0d0d0d0";

const ROLE = "axis_app";
let c: pg.Client;
beforeAll(async () => {
  c = await connect();
  await seedTenant(c, A, "cpa");
  await seedTenant(c, B, "cpb");
});
afterAll(async () => {
  await c.end();
});

async function lookup(table: string, settings: Record<string, string>): Promise<number> {
  await c.query("BEGIN");
  try {
    await c.query(`SET LOCAL ROLE ${ROLE}`);
    for (const [k, v] of Object.entries(settings))
      await c.query("SELECT set_config($1, $2, true)", [k, v]);
    return (await c.query(`SELECT 1 FROM ${table}`)).rowCount ?? 0;
  } finally {
    await c.query("ROLLBACK");
  }
}

describe("0008 control plane schema", () => {
  it("api key lookup releases a row only for the exact prefix and hash", async () => {
    const hash = "01";
    expect(await lookup("api_keys", {})).toBe(0);
    expect(await lookup("api_keys", { "axis.lookup_prefix": "pre_cpa" })).toBe(0);
    expect(
      await lookup("api_keys", { "axis.lookup_prefix": "pre_cpa", "axis.lookup_hash": hash }),
    ).toBe(1);
    expect(
      await lookup("api_keys", { "axis.lookup_prefix": "pre_cpa", "axis.lookup_hash": "02" }),
    ).toBe(0);
  });

  it("scim token and idp org lookups are exact-match only", async () => {
    expect(await lookup("directories", {})).toBe(0);
    expect(await lookup("identity_connections", {})).toBe(0);
    expect(await lookup("identity_connections", { "axis.lookup_idp_org": "org_cpa" })).toBe(1);
    expect(await lookup("identity_connections", { "axis.lookup_idp_org": "org_" })).toBe(0);
  });

  it("provision_tenant creates a tenant under FORCED RLS for the app role and rejects slug reuse", async () => {
    const id = randomUUID();
    await c.query("BEGIN");
    await c.query(`SET LOCAL ROLE ${ROLE}`);
    await c.query("SELECT axis.provision_tenant($1, 'cp-new-tenant', 'N', 'us-east-1', false)", [
      id,
    ]);
    await c.query("COMMIT");
    const seen = await withTenant(c, id, (cl) => cl.query("SELECT slug FROM tenants"), {
      role: ROLE,
    });
    expect(seen.rows).toEqual([{ slug: "cp-new-tenant" }]);
    await c.query("BEGIN");
    await c.query(`SET LOCAL ROLE ${ROLE}`);
    await expect(
      c.query("SELECT axis.provision_tenant($1, 'cp-new-tenant', 'N', 'us-east-1', false)", [
        randomUUID(),
      ]),
    ).rejects.toThrow(/duplicate key/);
    await c.query("ROLLBACK");
  });

  it("members role is a closed set and the last-email unique index is case-insensitive", async () => {
    await expect(
      c.query(
        "INSERT INTO members (tenant_id, user_ref, email, role) VALUES ($1, 'x', 'x@x.io', 'god')",
        [A],
      ),
    ).rejects.toThrow(/members_role_known/);
    await expect(
      c.query(
        "INSERT INTO members (tenant_id, user_ref, email, role) VALUES ($1, 'y', 'CPA@X.IO', 'viewer')",
        [A],
      ),
    ).rejects.toThrow(/duplicate key/);
  });

  it("a domain verifies for at most one tenant", async () => {
    await c.query(
      "UPDATE verified_domains SET status='verified', verified_at=now() WHERE tenant_id=$1",
      [A],
    );
    await c.query(
      "INSERT INTO verified_domains (tenant_id, domain) VALUES ($1, 'cpa.example.com')",
      [B],
    );
    await expect(
      c.query(
        "UPDATE verified_domains SET status='verified', verified_at=now() WHERE tenant_id=$1 AND domain='cpa.example.com'",
        [B],
      ),
    ).rejects.toThrow(/duplicate key/);
  });
});
