import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import {
  aclAllows,
  canonicalAcl,
  MemoryError,
  type Acl,
  type PgMemoryService,
  type Principal,
} from "../src/index.js";
import { adminClient, newPool, newService, newTenant, ROLE, who } from "./helpers.js";

const ALICE = who("alice", "eng");
const BOB = who("bob", "sales");
const ALL = { query: "quarterly revenue forecast numbers", limit: 50 };

describe("tenant isolation and ACL", () => {
  let pool: pg.Pool;
  let admin: pg.Client;
  let svc: PgMemoryService;
  beforeAll(async () => {
    pool = newPool();
    admin = await adminClient();
    svc = newService(pool);
  });
  afterAll(async () => {
    await pool.end();
    await admin.end();
  });

  it("every read path is tenant-scoped: tenant B never sees tenant A's rows, even with A's ids and identical principals", async () => {
    const a = await newTenant(admin);
    const b = await newTenant(admin);
    await svc.write(a, {
      scope: "tenant",
      content: "quarterly revenue forecast numbers A",
      acl: { tenant: true },
      principal: ALICE,
    });
    const doc = await svc.ingestDocument(a, {
      kb: "fin",
      content: "quarterly revenue forecast numbers doc A",
      acl: { tenant: true },
      principal: ALICE,
    });
    await svc.write(b, {
      scope: "tenant",
      content: "quarterly revenue forecast numbers B",
      acl: { tenant: true },
      principal: ALICE,
    });
    expect((await svc.search(b, ALICE, ALL)).map((h) => h.content)).toEqual([
      "quarterly revenue forecast numbers B",
    ]);
    expect((await svc.recall(b, ALICE, { scope: "tenant" })).map((e) => e.content)).toEqual([
      "quarterly revenue forecast numbers B",
    ]);
    expect(await svc.search(b, ALICE, { ...ALL, kbs: ["fin"] })).toEqual([]);
    // mutating paths cannot reach A's rows through B
    await expect(svc.deleteDocument(b, doc.documentId)).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(svc.setDocumentAcl(b, doc.documentId, { tenant: true })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(await svc.forgetSubject(b, "anything")).toEqual({ chunks: 0, documents: 0 });
    expect((await svc.search(a, ALICE, ALL)).length).toBe(2);
  });

  it("FORCE row level security is on for every memory table and the app role cannot bypass it", async () => {
    const r = await admin.query(
      `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c
        WHERE c.relname IN ('memory_chunks', 'memory_documents', 'knowledge_bases') ORDER BY 1`,
    );
    expect(r.rows).toEqual([
      { relname: "knowledge_bases", relrowsecurity: true, relforcerowsecurity: true },
      { relname: "memory_chunks", relrowsecurity: true, relforcerowsecurity: true },
      { relname: "memory_documents", relrowsecurity: true, relforcerowsecurity: true },
    ]);
    const role = await admin.query(
      "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1",
      [ROLE],
    );
    expect(role.rows[0]).toEqual({ rolsuper: false, rolbypassrls: false });
  });

  describe("raw SQL as the app role (RLS alone, no service code)", () => {
    const asApp = async <T>(
      tenant: string | null,
      fn: (c: pg.Client) => Promise<T>,
    ): Promise<T> => {
      await admin.query("BEGIN");
      try {
        await admin.query(`SET LOCAL ROLE ${ROLE}`);
        if (tenant) await admin.query("SELECT axis.set_tenant($1::uuid)", [tenant]);
        return await fn(admin);
      } finally {
        await admin.query("ROLLBACK");
      }
    };
    it("sees only its own tenant's rows, nothing without a tenant, and cannot write across tenants", async () => {
      const a = await newTenant(admin);
      const b = await newTenant(admin);
      await svc.write(a, {
        scope: "tenant",
        content: "A secret",
        acl: { tenant: true },
        principal: ALICE,
      });
      await svc.ingestDocument(a, {
        kb: "kb-a",
        content: "A doc",
        acl: { tenant: true },
        principal: ALICE,
      });
      for (const tbl of ["memory_chunks", "memory_documents", "knowledge_bases"]) {
        const count = (t: string | null, id: string) =>
          asApp(t, async (c) =>
            Number(
              (await c.query(`SELECT count(*) FROM ${tbl} WHERE tenant_id = $1`, [id])).rows[0]
                .count,
            ),
          );
        expect(await count(a, a)).toBeGreaterThan(0);
        expect(await count(b, a)).toBe(0);
        expect(await count(null, a)).toBe(0);
      }
      await expect(
        asApp(b, (c) =>
          c.query(
            `INSERT INTO memory_chunks (tenant_id, scope, content) VALUES ($1, 'tenant', 'x')`,
            [a],
          ),
        ),
      ).rejects.toThrow(/row-level security/);
      const del = await asApp(b, (c) =>
        c.query(`DELETE FROM memory_chunks WHERE tenant_id = $1`, [a]),
      );
      expect(del.rowCount).toBe(0);
    });

    it("mutation check: with RLS disabled the same raw query DOES leak, so the assertions above are able to fail", async () => {
      const a = await newTenant(admin);
      const b = await newTenant(admin);
      await svc.write(a, {
        scope: "tenant",
        content: "A secret",
        acl: { tenant: true },
        principal: ALICE,
      });
      await admin.query("ALTER TABLE memory_chunks NO FORCE ROW LEVEL SECURITY");
      await admin.query("ALTER TABLE memory_chunks DISABLE ROW LEVEL SECURITY");
      try {
        const leaked = await asApp(b, async (c) =>
          Number(
            (await c.query(`SELECT count(*) FROM memory_chunks WHERE tenant_id = $1`, [a])).rows[0]
              .count,
          ),
        );
        expect(leaked).toBe(1);
      } finally {
        await admin.query("ALTER TABLE memory_chunks ENABLE ROW LEVEL SECURITY");
        await admin.query("ALTER TABLE memory_chunks FORCE ROW LEVEL SECURITY");
      }
    });
  });

  describe("ACL: documents and chunks a principal cannot read are never returned, counted or scored", () => {
    it("is invisible: results equal a world where the restricted rows do not exist (ids aside)", async () => {
      const withSecret = await newTenant(admin);
      const control = await newTenant(admin);
      const pub = "quarterly revenue forecast numbers public summary";
      const secret = "quarterly revenue forecast numbers CONFIDENTIAL layoffs plan";
      for (const t of [withSecret, control])
        await svc.ingestDocument(t, {
          kb: "fin",
          content: pub,
          acl: { tenant: true },
          metadata: { k: "pub" },
          principal: ALICE,
        });
      await svc.ingestDocument(withSecret, {
        kb: "fin",
        content: secret,
        acl: { users: ["alice"] },
        metadata: { k: "secret" },
        principal: ALICE,
      });
      await svc.write(withSecret, {
        scope: "agent",
        ownerRef: "bot",
        content: secret + " note",
        acl: { roles: ["eng"] },
        principal: ALICE,
      });

      const shape = (hs: { content: string; score: number; metadata: unknown }[]) =>
        hs.map((h) => [h.content, h.score, h.metadata]);
      for (const limit of [1, 2, 50]) {
        const got = await svc.search(withSecret, BOB, { ...ALL, limit });
        const want = await svc.search(control, BOB, { ...ALL, limit });
        expect(shape(got)).toEqual(shape(want)); // same results, scores, and sizes: no count/score side channel
        expect(JSON.stringify(got)).not.toMatch(/CONFIDENTIAL|layoffs/);
      }
      // the best match (by similarity) is the secret one; limit 1 still yields the best READABLE row, not an empty page
      expect((await svc.search(withSecret, BOB, { ...ALL, limit: 1 }))[0]?.content).toBe(pub);
      // metadata / scope / kb / minScore probes cannot distinguish "filtered out" from "no such row"
      const probe = (over: object) => svc.search(withSecret, BOB, { ...ALL, ...over });
      expect(await probe({ metadata: { k: "secret" } })).toEqual(
        await probe({ metadata: { k: "nonexistent" } }),
      );
      expect(await probe({ scopes: ["agent"] })).toEqual([]);
      expect(await probe({ ownerRef: "bot" })).toEqual([]);
      expect(await svc.recall(withSecret, BOB, { scope: "agent", ownerRef: "bot" })).toEqual([]);
      // the readers do see it
      expect((await svc.search(withSecret, ALICE, ALL)).map((h) => h.content)).toContain(secret);
    });

    it("re-ingesting restricted content cannot reveal it, and gives no access to the existing copy", async () => {
      const t = await newTenant(admin);
      const text = "quarterly revenue forecast numbers CONFIDENTIAL";
      const mine = await svc.ingestDocument(t, {
        kb: "fin",
        content: text,
        acl: { users: ["alice"] },
        principal: ALICE,
      });
      const bobs = await svc.ingestDocument(t, {
        kb: "fin",
        content: text,
        acl: { users: ["bob"] },
        principal: BOB,
      });
      expect(bobs.deduped).toBe(false);
      expect(bobs.documentId).not.toBe(mine.documentId);
      expect((await svc.search(t, BOB, ALL)).map((h) => h.documentId)).toEqual([bobs.documentId]);
    });

    it("property: SQL ACL predicate agrees with the reference oracle for random ACLs and principals (no leak, no loss)", async () => {
      const ids = ["u1", "u2", "u3"];
      const groups = ["g1", "g2", "g3"];
      const aclArb = fc.record(
        { users: fc.subarray(ids), roles: fc.subarray(groups), tenant: fc.boolean() },
        { requiredKeys: [] },
      );
      const principalArb = fc.record({
        id: fc.constantFrom(...ids, "stranger"),
        groups: fc.subarray([...groups, "other"]),
      });
      await fc.assert(
        fc.asyncProperty(
          fc.array(aclArb, { minLength: 1, maxLength: 8 }),
          fc.array(principalArb, { minLength: 1, maxLength: 4 }),
          async (acls, principals) => {
            const t = await newTenant(admin);
            const writer: Principal = who("writer");
            const stored = new Map<string, Acl>();
            for (const [i, acl] of acls.entries()) {
              const w = await svc.write(t, {
                scope: "tenant",
                content: `quarterly revenue forecast entry ${i}`,
                acl,
                principal: writer,
              });
              stored.set(w.id, acl);
            }
            for (const p of principals) {
              const expected = [...stored]
                .filter(([, acl]) => aclAllows(canonicalAcl(acl), p))
                .map(([id]) => id)
                .sort();
              const hits = await svc.search(t, p, ALL);
              const recalled = await svc.recall(t, p, { scope: "tenant", limit: 200 });
              expect(hits.map((h) => h.id).sort()).toEqual(expected);
              expect(recalled.map((h) => h.id).sort()).toEqual(expected);
            }
          },
        ),
        { numRuns: 25 },
      );
    });

    it("reference oracle semantics", () => {
      const c = canonicalAcl;
      expect(aclAllows(c({}), who("a", "g"))).toBe(false);
      expect(aclAllows(c({ tenant: true }), who("a"))).toBe(true);
      expect(aclAllows(c({ users: ["a"] }), who("a"))).toBe(true);
      expect(aclAllows(c({ users: ["a"] }), who("b", "a"))).toBe(false); // a group named like a user grants nothing
      expect(aclAllows(c({ roles: ["g"] }), who("g"))).toBe(false); // an id named like a role grants nothing
      expect(aclAllows(c({ roles: ["g"] }), who("b", "x", "g"))).toBe(true);
    });
  });

  it("a thrown error never echoes content or foreign tenant data", async () => {
    const a = await newTenant(admin);
    const b = await newTenant(admin);
    const d = await svc.ingestDocument(a, {
      kb: "fin",
      content: "CONFIDENTIAL layoffs",
      acl: {},
      principal: ALICE,
    });
    const err = await svc.deleteDocument(b, d.documentId).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MemoryError);
    expect(String((err as Error).message)).not.toMatch(/CONFIDENTIAL|layoffs/);
    expect(String((err as Error).message)).not.toContain(a);
  });
});
