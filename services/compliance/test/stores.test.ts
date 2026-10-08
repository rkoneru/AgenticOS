import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import {
  DocConflict,
  DocForbidden,
  MemoryDocStore,
  PgDocStore,
  reviewerIndependent,
  type DocStore,
} from "../src/index.js";
import { adminClient, input, newPool, newTenantRow, user, world } from "./helpers.js";

function contract(
  name: string,
  make: () => Promise<{ store: DocStore; t1: string; t2: string }>,
): void {
  describe(`${name} document store`, () => {
    let store: DocStore;
    let t1: string;
    let t2: string;
    beforeAll(async () => {
      ({ store, t1, t2 } = await make());
    });

    it("inserts, reads, updates with an optimistic revision and filters", async () => {
      const d = await store.insert(t1, "systems", "s1", { name: "a", risk_level: "high" });
      expect(d.rev).toBe(1);
      await expect(store.insert(t1, "systems", "s1", { name: "dup" })).rejects.toBeInstanceOf(
        DocConflict,
      );
      const u = await store.update(t1, "systems", "s1", 1, { name: "b", risk_level: "high" });
      expect(u.rev).toBe(2);
      await expect(store.update(t1, "systems", "s1", 1, { name: "c" })).rejects.toBeInstanceOf(
        DocConflict,
      );
      await expect(store.update(t1, "systems", "nope", 1, { name: "c" })).rejects.toBeInstanceOf(
        DocForbidden,
      );
      await store.insert(t1, "systems", "s2", { name: "x", risk_level: "low" });
      expect((await store.find(t1, "systems", { risk_level: "high" })).map((x) => x.key)).toEqual([
        "s1",
      ]);
      expect((await store.find(t1, "systems")).map((x) => x.key)).toEqual(["s1", "s2"]);
      expect((await store.get(t1, "systems", "s1"))?.data).toEqual({
        name: "b",
        risk_level: "high",
      });
      expect(await store.get(t1, "systems", "zzz")).toBeUndefined();
    });

    it("is tenant-isolated for get, find and update", async () => {
      await store.insert(t1, "systems", "iso-1", { name: "mine" });
      expect(await store.get(t2, "systems", "iso-1")).toBeUndefined();
      expect((await store.find(t2, "systems")).map((x) => x.key)).not.toContain("iso-1");
      await expect(
        store.update(t2, "systems", "iso-1", 1, { name: "hijack" }),
      ).rejects.toBeInstanceOf(DocForbidden);
      expect((await store.get(t1, "systems", "iso-1"))?.data).toEqual({ name: "mine" });
      // the same key in another tenant is a different document
      await store.insert(t2, "systems", "iso-1", { name: "theirs" });
      expect((await store.get(t2, "systems", "iso-1"))?.data).toEqual({ name: "theirs" });
    });

    it("append-only collections never change", async () => {
      for (const coll of ["system_versions", "documents"]) {
        await store.insert(t1, coll, "k1", { a: 1 });
        await expect(store.update(t1, coll, "k1", 1, { a: 2 })).rejects.toBeInstanceOf(
          DocForbidden,
        );
      }
    });

    it("assessments are updatable until reviewed, then frozen; the reviewer must be independent", async () => {
      const base = {
        author: "alice",
        contributors: ["alice"],
        state: "draft",
        assessment_id: "a1",
      };
      await store.insert(t1, "assessments", "a1@1", base);
      await store.update(t1, "assessments", "a1@1", 1, { ...base, state: "in_review" });
      // the author cannot approve; nor a contributor; nor an empty reviewer
      for (const reviewer of ["alice", "", undefined])
        await expect(
          store.update(t1, "assessments", "a1@1", 2, {
            ...base,
            state: "approved",
            reviewed_by: reviewer,
          }),
        ).rejects.toBeInstanceOf(DocForbidden);
      await expect(
        store.update(t1, "assessments", "a1@1", 2, {
          ...base,
          contributors: ["alice", "carol"],
          state: "rejected",
          reviewed_by: "carol",
        }),
      ).rejects.toBeInstanceOf(DocForbidden);
      const done = await store.update(t1, "assessments", "a1@1", 2, {
        ...base,
        state: "approved",
        reviewed_by: "bob",
      });
      expect(done.rev).toBe(3);
      await expect(
        store.update(t1, "assessments", "a1@1", 3, {
          ...base,
          state: "approved",
          reviewed_by: "bob",
          title: "changed",
        }),
      ).rejects.toBeInstanceOf(DocForbidden);
      // an assessment inserted already approved by its author is refused too
      await expect(
        store.insert(t1, "assessments", "a2@1", {
          ...base,
          assessment_id: "a2",
          state: "approved",
          reviewed_by: "alice",
        }),
      ).rejects.toBeInstanceOf(DocForbidden);
    });
  });
}

contract("memory", () => Promise.resolve({ store: new MemoryDocStore(), t1: "t-1", t2: "t-2" }));

describe("independence predicate", () => {
  it("applies to approved and rejected states only", () => {
    expect(reviewerIndependent({ state: "draft", author: "a" })).toBe(true);
    expect(reviewerIndependent({ state: "in_review", author: "a", reviewed_by: "a" })).toBe(true);
    expect(
      reviewerIndependent({
        state: "approved",
        author: "a",
        reviewed_by: "b",
        contributors: ["a"],
      }),
    ).toBe(true);
    expect(reviewerIndependent({ state: "approved", author: "a", reviewed_by: "b" })).toBe(true);
    expect(reviewerIndependent({ state: "approved", author: "a", reviewed_by: "a" })).toBe(false);
    expect(
      reviewerIndependent({
        state: "rejected",
        author: "a",
        reviewed_by: "c",
        contributors: ["c"],
      }),
    ).toBe(false);
    expect(reviewerIndependent({ state: "rejected", author: "a" })).toBe(false);
  });
  it("the memory store refuses documents in an unknown collection", async () => {
    await expect(new MemoryDocStore().insert("t", "other", "k", {})).rejects.toBeInstanceOf(
      DocForbidden,
    );
  });
});

describe("Postgres", () => {
  let admin: pg.Client;
  let pool: pg.Pool;
  let t1: string;
  let t2: string;
  let store: PgDocStore;
  beforeAll(async () => {
    admin = await adminClient();
    pool = newPool();
    t1 = await newTenantRow(admin);
    t2 = await newTenantRow(admin);
    store = new PgDocStore({ pool, role: "axis_app" });
  });
  afterAll(async () => {
    await pool.end();
    await admin.end();
  });

  // The contract suite on the real database, as the application role (forced RLS applies).
  contract("postgres", async () => {
    const a = await adminClient();
    const p = newPool();
    const x = await newTenantRow(a);
    const y = await newTenantRow(a);
    await a.end();
    return { store: new PgDocStore({ pool: p, role: "axis_app" }), t1: x, t2: y };
  });

  it("the table has forced row-level security and no DELETE grant", async () => {
    const r = await admin.query(
      "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'compliance_docs'",
    );
    expect(r.rows[0]).toEqual({ relrowsecurity: true, relforcerowsecurity: true });
    const g = await admin.query(
      "SELECT privilege_type FROM information_schema.role_table_grants WHERE table_name = 'compliance_docs' AND grantee = 'axis_app' ORDER BY 1",
    );
    expect(g.rows.map((x) => x.privilege_type)).toEqual(["INSERT", "SELECT", "UPDATE"]);
  });

  it("without a tenant in the session no row is visible, and a row for another tenant cannot be written", async () => {
    await store.insert(t1, "systems", "rls-1", { name: "secret" });
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE axis_app");
      const none = await c.query("SELECT count(*)::int AS n FROM compliance_docs");
      expect(none.rows[0].n).toBe(0);
      await c.query("SELECT axis.set_tenant($1::uuid)", [t2]);
      await expect(
        c.query(
          "INSERT INTO compliance_docs (tenant_id, coll, key, rev, data) VALUES ($1,'systems','x',1,'{}')",
          [t1],
        ),
      ).rejects.toMatchObject({ code: "42501" });
      await c.query("ROLLBACK");
    } finally {
      c.release();
    }
    expect(await store.get(t2, "systems", "rls-1")).toBeUndefined();
  });

  it("the database refuses DELETE, an unknown collection and a non-object body, even for the table owner path", async () => {
    await store.insert(t1, "systems", "del-1", { name: "x" });
    await expect(
      admin.query("DELETE FROM compliance_docs WHERE key = 'del-1'"),
    ).rejects.toMatchObject({ code: "42501" });
    await expect(
      admin.query(
        "INSERT INTO compliance_docs (tenant_id, coll, key, rev, data) VALUES ($1,'bogus','k',1,'{}')",
        [t1],
      ),
    ).rejects.toMatchObject({ code: "23514" });
    await expect(
      admin.query(
        "INSERT INTO compliance_docs (tenant_id, coll, key, rev, data) VALUES ($1,'systems','k',1,'[]')",
        [t1],
      ),
    ).rejects.toMatchObject({ code: "23514" });
  });

  it("the database enforces reviewer independence by itself (a service bug cannot approve your own work)", async () => {
    await admin.query(
      "INSERT INTO compliance_docs (tenant_id, coll, key, rev, data) VALUES ($1,'assessments','raw@1',1,$2)",
      [t1, JSON.stringify({ state: "in_review", author: "alice", contributors: ["alice"] })],
    );
    await expect(
      admin.query(
        "UPDATE compliance_docs SET rev = 2, data = $2 WHERE tenant_id = $1 AND key = 'raw@1'",
        [
          t1,
          JSON.stringify({
            state: "approved",
            author: "alice",
            contributors: ["alice"],
            reviewed_by: "alice",
          }),
        ],
      ),
    ).rejects.toMatchObject({ code: "23514" });
    const ok = await admin.query(
      "UPDATE compliance_docs SET rev = 2, data = $2 WHERE tenant_id = $1 AND key = 'raw@1' RETURNING rev",
      [
        t1,
        JSON.stringify({
          state: "approved",
          author: "alice",
          contributors: ["alice"],
          reviewed_by: "bob",
        }),
      ],
    );
    expect(ok.rows[0].rev).toBe(2);
    await expect(
      admin.query(
        "UPDATE compliance_docs SET rev = 3, data = '{\"state\":\"approved\"}' WHERE tenant_id = $1 AND key = 'raw@1'",
        [t1],
      ),
    ).rejects.toMatchObject({ code: "42501" });
  });

  it("the whole service works on Postgres: inventory, assessment workflow, documents, per-tenant isolation", async () => {
    const w = world({ docs: store });
    const owner = user(t1, "owner", "olivia");
    const builder = user(t1, "builder", "bob");
    const auditor = user(t1, "auditor", "alice");
    const sys = await w.svc.systems.create(builder, input.system({ system_id: "claims-triage" }));
    await w.svc.systems.update(builder, sys.system_id, 1, { lifecycle_stage: "deployed" });
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    await expect(
      w.svc.assessments.review(builder, a.assessment_id, 1, "approve", ""),
    ).rejects.toMatchObject({ code: "forbidden" });
    const done = await w.svc.assessments.review(auditor, a.assessment_id, 1, "approve", "ok");
    expect(done.state).toBe("approved");
    const v2 = await w.svc.assessments.revise(owner, a.assessment_id, 1, {
      risk_rating: "critical",
    });
    expect(v2.version).toBe(2);
    expect((await w.svc.assessments.list(auditor)).map((x) => x.version)).toEqual([2]);
    const doc = await w.svc.documents.generate(owner, { name: "claims-triage", version: "2.3.1" });
    expect(doc.created).toBe(true);
    expect(
      (await w.svc.documents.get(auditor, doc.document.meta.document_id)).verification.ok,
    ).toBe(true);
    expect(
      (await w.svc.documents.generate(owner, { name: "claims-triage", version: "2.3.1" })).created,
    ).toBe(false);
    const other = user(t2, "owner", "mallory");
    expect(await w.svc.systems.list(other)).toEqual([]);
    expect(await w.svc.assessments.list(other)).toEqual([]);
    expect(await w.svc.documents.list(other)).toEqual([]);
    await expect(w.svc.documents.get(other, doc.document.meta.document_id)).rejects.toMatchObject({
      code: "not_found",
    });
  });
});
