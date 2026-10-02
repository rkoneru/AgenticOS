import { randomUUID } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import {
  CATALOG,
  DocConflict,
  DocForbidden,
  MemoryDocStore,
  PLATFORM,
  PgDocStore,
  tenantScope,
  type DocStore,
} from "../src/index.js";
import { ROLE, adminClient, newPool, newTenant } from "./helpers.js";

const pool = newPool();
afterAll(() => pool.end());

const stores: [string, () => Promise<{ docs: DocStore; tenants: () => Promise<string> }>][] = [
  [
    "memory",
    () =>
      Promise.resolve({ docs: new MemoryDocStore(), tenants: () => Promise.resolve(randomUUID()) }),
  ],
  [
    "postgres",
    async () => {
      const admin = await adminClient();
      return { docs: new PgDocStore({ pool, role: ROLE }), tenants: () => newTenant(admin) };
    },
  ],
];

describe.each(stores)("DocStore contract (%s)", (_n, mk) => {
  it("tenant scope: own rows only; insert conflicts; optimistic concurrency; append-only collections", async () => {
    const { docs, tenants } = await mk();
    const [a, b] = [await tenants(), await tenants()];
    const sa = tenantScope(a);
    const sb = tenantScope(b);
    const d = await docs.insert(sa, a, "reviews", "k1", { state: "x", n: 1 });
    expect(d.rev).toBe(1);
    await expect(docs.insert(sa, a, "reviews", "k1", {})).rejects.toBeInstanceOf(DocConflict);
    await expect(docs.insert(sb, a, "reviews", "k2", {})).rejects.toBeInstanceOf(DocForbidden);
    expect(await docs.get(sb, a, "reviews", "k1")).toBeUndefined();
    expect((await docs.get(sa, a, "reviews", "k1"))?.data).toEqual({ state: "x", n: 1 });
    expect(await docs.find(sb, "reviews")).toEqual([]);
    expect(await docs.find(sa, "reviews", { state: "x" })).toHaveLength(1);
    expect(await docs.find(sa, "reviews", { state: "y" })).toHaveLength(0);
    const u = await docs.update(sa, a, "reviews", "k1", 1, { state: "y" });
    expect(u.rev).toBe(2);
    await expect(docs.update(sa, a, "reviews", "k1", 1, { state: "z" })).rejects.toBeInstanceOf(
      DocConflict,
    );
    await expect(docs.update(sb, a, "reviews", "k1", 2, { state: "z" })).rejects.toBeInstanceOf(
      DocForbidden,
    );
    await expect(docs.update(sa, a, "reviews", "nope", 1, {})).rejects.toBeInstanceOf(DocForbidden);
    for (const coll of ["events", "evidence", "takedowns"]) {
      await docs.insert(sa, a, coll, "e1", { a: 1 });
      await expect(docs.update(sa, a, coll, "e1", 1, { a: 2 })).rejects.toBeInstanceOf(
        DocForbidden,
      );
    }
  });
  it("platform scope sees and writes every tenant; catalog scope sees only listed listings and writes nothing", async () => {
    const { docs, tenants } = await mk();
    const [a, b] = [await tenants(), await tenants()];
    const tag = randomUUID().slice(0, 8);
    await docs.insert(tenantScope(a), a, "listings", `l-${tag}`, {
      status: "listed",
      namespace: tag,
      name: "x",
    });
    await docs.insert(tenantScope(a), a, "listings", `d-${tag}`, {
      status: "draft",
      namespace: tag,
      name: "y",
    });
    await docs.insert(tenantScope(b), b, "reviews", `r-${tag}`, {
      state: "in_review",
      namespace: tag,
    });
    expect((await docs.find(CATALOG, "listings", { namespace: tag })).map((x) => x.key)).toEqual([
      `l-${tag}`,
    ]);
    expect(await docs.find(CATALOG, "reviews", { namespace: tag })).toEqual([]);
    expect(await docs.get(CATALOG, a, "listings", `d-${tag}`)).toBeUndefined();
    expect(await docs.get(CATALOG, a, "listings", `l-${tag}`)).toBeDefined();
    await expect(docs.insert(CATALOG, a, "listings", "z", {})).rejects.toBeInstanceOf(DocForbidden);
    expect(await docs.find(PLATFORM, "reviews", { namespace: tag })).toHaveLength(1);
    expect(await docs.find(PLATFORM, "listings", { namespace: tag })).toHaveLength(2);
    expect(await docs.find(PLATFORM, "listings", { namespace: tag }, b)).toHaveLength(0);
    const r = (await docs.find(PLATFORM, "reviews", { namespace: tag }))[0]!;
    const up = await docs.update(PLATFORM, r.tenantId, "reviews", r.key, r.rev, {
      state: "approved",
      namespace: tag,
    });
    expect(up.data).toMatchObject({ state: "approved" });
    // another tenant's scope cannot see the platform-updated row
    expect(await docs.get(tenantScope(a), b, "reviews", r.key)).toBeUndefined();
  });
});

describe("marketplace_docs RLS and guards, directly in SQL", () => {
  it("no tenant/platform context sees nothing but listed listings; deletes and identity changes are impossible", async () => {
    const admin = await adminClient();
    const [a, b] = [await newTenant(admin), await newTenant(admin)];
    const docs = new PgDocStore({ pool, role: ROLE });
    const tag = randomUUID().slice(0, 8);
    await docs.insert(tenantScope(a), a, "reviews", `r-${tag}`, { state: "in_review", tag });
    await docs.insert(tenantScope(a), a, "listings", `l-${tag}`, { status: "listed", tag });
    await docs.insert(tenantScope(a), a, "events", `e-${tag}`, { tag });
    const as = async (
      ctx: { tenant?: string; platform?: boolean },
      sql: string,
    ): Promise<{ rowCount: number | null }> => {
      await admin.query("BEGIN");
      try {
        await admin.query(`SET LOCAL ROLE ${ROLE}`);
        if (ctx.tenant) await admin.query("SELECT axis.set_tenant($1::uuid)", [ctx.tenant]);
        if (ctx.platform) await admin.query("SELECT axis.set_platform(true)");
        return await admin.query(sql);
      } finally {
        await admin.query("ROLLBACK");
      }
    };
    const q = `SELECT * FROM marketplace_docs WHERE data->>'tag' = '${tag}'`;
    expect((await as({}, q)).rowCount).toBe(1); // the listed listing only
    expect((await as({ tenant: b }, q)).rowCount).toBe(1);
    expect((await as({ tenant: a }, q)).rowCount).toBe(3);
    expect((await as({ platform: true }, q)).rowCount).toBe(3);
    await expect(
      as({ tenant: a }, `DELETE FROM marketplace_docs WHERE data->>'tag' = '${tag}'`),
    ).rejects.toThrow(/permission denied|forbidden/);
    await expect(
      as({ tenant: a }, `UPDATE marketplace_docs SET data = '{}'::jsonb WHERE key = 'e-${tag}'`),
    ).rejects.toThrow();
    await expect(
      as(
        { tenant: b },
        `INSERT INTO marketplace_docs (tenant_id, coll, key, rev, data) VALUES ('${a}', 'reviews', 'x-${tag}', 1, '{}')`,
      ),
    ).rejects.toThrow();
    await expect(
      as(
        {},
        `INSERT INTO marketplace_docs (tenant_id, coll, key, rev, data) VALUES ('${a}', 'reviews', 'y-${tag}', 1, '{}')`,
      ),
    ).rejects.toThrow();
    // even the superuser cannot delete, rewrite an append-only row, or skip a revision
    await expect(
      admin.query(`DELETE FROM marketplace_docs WHERE key = 'r-${tag}'`),
    ).rejects.toThrow(/forbidden/);
    await expect(
      admin.query(`UPDATE marketplace_docs SET data = '{}'::jsonb WHERE key = 'e-${tag}'`),
    ).rejects.toThrow(/append-only/);
    await expect(
      admin.query(
        `UPDATE marketplace_docs SET data = '{}'::jsonb, rev = rev + 5 WHERE key = 'r-${tag}'`,
      ),
    ).rejects.toThrow(/stale|identity/);
    await admin.end();
  });
});
