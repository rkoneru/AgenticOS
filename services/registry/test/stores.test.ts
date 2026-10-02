import { afterAll, describe, expect, it } from "vitest";
import { MemoryRegistryStore } from "../src/index.js";
import { adminClient, rid, newPool, newTenant, pgStore, ROLE } from "./helpers.js";
import { storeContract } from "./store-contract.js";
import { randomUUID } from "node:crypto";

storeContract("memory", async () => {
  const store = new MemoryRegistryStore();
  return { store, tenants: () => Promise.resolve(randomUUID()) };
});

const pool = newPool();
afterAll(() => pool.end());

storeContract("postgres (forced RLS)", async () => {
  const admin = await adminClient();
  try {
    return { store: pgStore(pool), tenants: () => newTenant(admin) };
  } finally {
    // tenants() is called later; keep the client open until the process ends
    void admin;
  }
});

describe("Postgres RLS, directly", () => {
  it("axis_app sees nothing without a tenant and only its own rows with one; versions cannot be updated or deleted", async () => {
    const admin = await adminClient();
    const [a, b] = [await newTenant(admin), await newTenant(admin)];
    const store = pgStore(pool);
    const ns = `rls-${rid(6)}`;
    const T = new Date();
    await store.claimNamespace({
      namespace: ns,
      tenantId: a,
      normalized: ns.replace(/-/g, ""),
      createdAt: T,
      createdBy: "u",
    });
    await store.insertVersion(
      {
        namespace: ns,
        name: "agent-one",
        version: "1.0.0",
        tenantId: a,
        abl: "{}",
        contentHash: "a".repeat(64),
        riskLevel: "minimal",
        signature: { keyId: "k", signedAt: "x", sig: "s" },
        provenance: { payloadType: "t", payload: "p", signatures: [] },
        publishedAt: T,
        publishedBy: "u",
      },
      "agentone",
    );
    const as = async (tenant: string | null, sql: string): Promise<{ rowCount: number | null }> => {
      const c = await admin.query("BEGIN");
      void c;
      try {
        await admin.query(`SET LOCAL ROLE ${ROLE}`);
        if (tenant) await admin.query("SELECT axis.set_tenant($1::uuid)", [tenant]);
        return await admin.query(sql);
      } finally {
        await admin.query("ROLLBACK");
      }
    };
    expect(
      (await as(null, `SELECT * FROM registry_versions WHERE namespace = '${ns}'`)).rowCount,
    ).toBe(0);
    expect(
      (await as(b, `SELECT * FROM registry_versions WHERE namespace = '${ns}'`)).rowCount,
    ).toBe(0);
    expect(
      (await as(a, `SELECT * FROM registry_versions WHERE namespace = '${ns}'`)).rowCount,
    ).toBe(1);
    await expect(
      as(a, `UPDATE registry_versions SET abl = '{"evil":1}' WHERE namespace = '${ns}'`),
    ).rejects.toThrow(/append-only|forbidden|permission denied/);
    await expect(as(a, `DELETE FROM registry_versions WHERE namespace = '${ns}'`)).rejects.toThrow(
      /append-only|forbidden|permission denied/,
    );
    await expect(as(a, `DELETE FROM registry_names WHERE namespace = '${ns}'`)).rejects.toThrow();
    await expect(
      as(
        b,
        `INSERT INTO registry_versions (namespace,name,version,tenant_id,abl,content_hash,risk_level,signature,provenance,published_at,published_by) VALUES ('${ns}','agent-one','9.9.9','${b}','{}','${"a".repeat(64)}','minimal','{}','{}',now(),'x')`,
      ),
    ).rejects.toThrow();
    // a private namespace's own row is invisible to other tenants and to anonymous readers
    expect(
      (await as(b, `SELECT * FROM registry_namespaces WHERE namespace = '${ns}'`)).rowCount,
    ).toBe(0);
    expect(
      (await as(null, `SELECT * FROM registry_namespaces WHERE namespace = '${ns}'`)).rowCount,
    ).toBe(0);
    expect(
      (await as(a, `SELECT * FROM registry_namespaces WHERE namespace = '${ns}'`)).rowCount,
    ).toBe(1);
    // an unlisted namespace never leaks, whatever the query
    expect((await as(b, `SELECT * FROM registry_keys WHERE namespace = '${ns}'`)).rowCount).toBe(0);
    // even the table owner / superuser cannot rewrite or delete a published version (trigger, not just missing grants)
    await expect(
      admin.query(`UPDATE registry_versions SET abl = '{"evil":1}' WHERE namespace = '${ns}'`),
    ).rejects.toThrow(/append-only/);
    await expect(
      admin.query(`DELETE FROM registry_versions WHERE namespace = '${ns}'`),
    ).rejects.toThrow(/append-only/);
    await admin.end();
  });
});
