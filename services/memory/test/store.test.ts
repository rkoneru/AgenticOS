import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { MemoryError, PgMemoryService, type Embedder, type SearchHit } from "../src/index.js";
import { adminClient, newPool, newService, newTenant, SpyEmbedder, who } from "./helpers.js";

const ALICE = who("alice", "eng");
const rejects = async (
  p: Promise<unknown>,
  code: MemoryError["code"] = "INVALID",
): Promise<void> => {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(MemoryError);
  expect((err as MemoryError).code).toBe(code);
};

describe("PgMemoryService", () => {
  let pool: pg.Pool;
  let admin: pg.Client;
  let svc: PgMemoryService;
  let now = new Date("2030-01-01T00:00:00.000Z");
  beforeAll(async () => {
    pool = newPool();
    admin = await adminClient();
    svc = newService(pool, { now: () => now });
  });
  afterAll(async () => {
    await pool.end();
    await admin.end();
  });

  describe("entry memory (run / session / long-term / tenant)", () => {
    it("writes and recalls run, session and agent memory, newest first, scoped by owner", async () => {
      const t = await newTenant(admin);
      for (const [scope, owner] of [
        ["run", "run-1"],
        ["session", "s-1"],
        ["agent", "support-bot"],
      ] as const) {
        await svc.write(t, {
          scope,
          ownerRef: owner,
          content: `${scope} note one`,
          principal: ALICE,
        });
        now = new Date(now.getTime() + 1000);
        await svc.write(t, {
          scope,
          ownerRef: owner,
          content: `${scope} note two`,
          principal: ALICE,
        });
        now = new Date(now.getTime() + 1000);
      }
      const run = await svc.recall(t, ALICE, { scope: "run", ownerRef: "run-1" });
      expect(run.map((e) => e.content)).toEqual(["run note two", "run note one"]);
      expect(await svc.recall(t, ALICE, { scope: "run", ownerRef: "other-run" })).toEqual([]);
      expect((await svc.recall(t, ALICE, { scope: "agent" })).map((e) => e.ownerRef)).toEqual([
        "support-bot",
        "support-bot",
      ]);
      expect(await svc.recall(t, ALICE, { scope: "session", limit: 1 })).toHaveLength(1);
    });

    it("defaults the ACL to the writer alone and honours explicit sharing", async () => {
      const t = await newTenant(admin);
      await svc.write(t, { scope: "tenant", content: "private to alice", principal: ALICE });
      await svc.write(t, {
        scope: "tenant",
        content: "shared with eng",
        acl: { roles: ["eng"] },
        principal: ALICE,
      });
      await svc.write(t, {
        scope: "tenant",
        content: "shared with everyone",
        acl: { tenant: true },
        principal: ALICE,
      });
      const bob = who("bob", "eng");
      const carol = who("carol");
      expect(
        (await svc.recall(t, ALICE, { scope: "tenant" })).map((e) => e.content).sort(),
      ).toEqual(["private to alice", "shared with eng", "shared with everyone"]);
      expect((await svc.recall(t, bob, { scope: "tenant" })).map((e) => e.content).sort()).toEqual([
        "shared with eng",
        "shared with everyone",
      ]);
      expect((await svc.recall(t, carol, { scope: "tenant" })).map((e) => e.content)).toEqual([
        "shared with everyone",
      ]);
    });

    it("an empty ACL is readable by nobody (fail closed)", async () => {
      const t = await newTenant(admin);
      await svc.write(t, { scope: "tenant", content: "orphan", acl: {}, principal: ALICE });
      expect(await svc.recall(t, ALICE, { scope: "tenant" })).toEqual([]);
      expect(await svc.search(t, ALICE, { query: "orphan" })).toEqual([]);
    });

    it("is idempotent per (scope, owner, content, acl): a repeat refreshes instead of duplicating", async () => {
      const t = await newTenant(admin);
      const a = await svc.write(t, {
        scope: "agent",
        ownerRef: "bot",
        content: "remember x",
        ttlSeconds: 10,
        principal: ALICE,
      });
      now = new Date(now.getTime() + 5000);
      const b = await svc.write(t, {
        scope: "agent",
        ownerRef: "bot",
        content: "remember x",
        ttlSeconds: 100,
        principal: ALICE,
      });
      expect(a.deduped).toBe(false);
      expect(b).toMatchObject({ id: a.id, deduped: true });
      expect(b.expiresAt).toBe(new Date(now.getTime() + 100_000).toISOString());
      const c = await svc.write(t, {
        scope: "agent",
        ownerRef: "other-bot",
        content: "remember x",
        principal: ALICE,
      });
      expect(c.id).not.toBe(a.id);
      const d = await svc.write(t, {
        scope: "agent",
        ownerRef: "bot",
        content: "remember x",
        acl: { tenant: true },
        principal: ALICE,
      });
      expect(d.id).not.toBe(a.id);
    });

    it("validates scope, owner, content, ttl, metadata and principal", async () => {
      const t = await newTenant(admin);
      const ok = { scope: "run", ownerRef: "r", content: "c", principal: ALICE } as const;
      await rejects(svc.write(t, { ...ok, scope: "kb" as never }));
      await rejects(svc.write(t, { ...ok, ownerRef: undefined as never }));
      await rejects(svc.write(t, { ...ok, scope: "tenant" }));
      await rejects(svc.write(t, { ...ok, content: "  " }));
      await rejects(svc.write(t, { ...ok, content: "a\u0000b" }));
      await rejects(svc.write(t, { ...ok, content: "x".repeat(32_001) }));
      await rejects(svc.write(t, { ...ok, ttlSeconds: 0 }));
      await rejects(svc.write(t, { ...ok, ttlSeconds: 1.5 }));
      await rejects(svc.write(t, { ...ok, metadata: [] as never }));
      await rejects(svc.write(t, { ...ok, metadata: { k: "x".repeat(17_000) } }));
      await rejects(svc.write(t, { ...ok, metadata: { k: "a\u0000b" } }));
      await rejects(svc.write(t, { ...ok, principal: { id: "", groups: [] } }));
      await rejects(svc.write(t, { ...ok, principal: { id: "a", groups: [""] } }));
      await rejects(svc.write(t, { ...ok, principal: { id: "a", groups: "x" as never } }));
      await rejects(svc.write(t, { ...ok, acl: { users: "x" as never } }));
      await rejects(svc.write(t, { ...ok, acl: { users: [""] } }));
      await rejects(svc.write(t, { ...ok, acl: { admins: ["x"] } as never }));
      await rejects(svc.write(t, { ...ok, acl: { tenant: "yes" as never } }));
      await rejects(svc.write(t, { ...ok, subject: "" }));
      await rejects(svc.write(t, { ...ok, ownerRef: "x".repeat(257) }));
      await rejects(svc.write(t, { ...ok, redact: ["a..b"], phi: true }));
    });

    it("rejects an unknown tenant and a malformed tenant id", async () => {
      await rejects(
        svc.write("00000000-0000-4000-8000-000000000000", {
          scope: "tenant",
          content: "x",
          principal: ALICE,
        }),
        "NOT_FOUND",
      );
      await expect(
        svc.write("not-a-uuid", { scope: "tenant", content: "x", principal: ALICE }),
      ).rejects.toThrow(/UUID/);
    });
  });

  describe("knowledge base ingestion and vector search", () => {
    const docs = {
      pets: "Dogs and cats are common household pets. Feeding a dog twice daily keeps the dog healthy.",
      cars: "Electric cars use lithium batteries. Charging an electric car at home takes several hours.",
      cook: "To bake sourdough bread you need flour, water, salt and a mature starter culture.",
    };

    it("chunks, embeds and finds the closest document first (top-k)", async () => {
      const t = await newTenant(admin);
      for (const [k, v] of Object.entries(docs))
        await svc.ingestDocument(t, {
          kb: "handbook",
          content: v,
          acl: { tenant: true },
          title: k,
          principal: ALICE,
        });
      const hits = await svc.search(t, ALICE, {
        query: "how long does charging an electric car take",
        limit: 2,
      });
      expect(hits).toHaveLength(2);
      expect(hits[0]?.metadata).toMatchObject({ title: "cars" });
      expect(hits[0]!.score).toBeGreaterThan(hits[1]!.score);
      expect(hits[0]).toMatchObject({ scope: "kb", kb: "handbook", ownerRef: null });
      expect(hits[0]?.documentId).toEqual(expect.any(String));
      expect(await svc.search(t, ALICE, { query: "sourdough starter", limit: 1 })).toHaveLength(1);
    });

    it("chunks long documents deterministically with ordinals and overlap, and dedupes by content hash + ACL", async () => {
      const small = newService(pool, { chunking: { size: 60, overlap: 10 } });
      const t = await newTenant(admin);
      const text =
        "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon";
      const a = await small.ingestDocument(t, {
        kb: "greek",
        content: text,
        acl: { tenant: true },
        principal: ALICE,
      });
      expect(a.chunks).toBeGreaterThan(1);
      const rows = await admin.query(
        "SELECT ordinal, content FROM memory_chunks WHERE tenant_id = $1 ORDER BY ordinal",
        [t],
      );
      expect(rows.rows.map((r) => r.ordinal)).toEqual([...rows.rows.keys()]);
      const dup = await small.ingestDocument(t, {
        kb: "greek",
        content: text,
        acl: { tenant: true },
        principal: who("other"),
      });
      expect(dup).toMatchObject({ documentId: a.documentId, chunks: 0, deduped: true });
      const relabelled = await small.ingestDocument(t, {
        kb: "greek",
        content: text,
        acl: { users: ["alice"] },
        principal: ALICE,
      });
      expect(relabelled.deduped).toBe(false);
      expect(relabelled.documentId).not.toBe(a.documentId);
      const sameInOtherKb = await small.ingestDocument(t, {
        kb: "other-kb",
        content: text,
        acl: { tenant: true },
        principal: ALICE,
      });
      expect(sameInOtherKb.deduped).toBe(false);
    });

    it("requires an explicit ACL and a valid kb name, and bounds document size", async () => {
      const t = await newTenant(admin);
      await rejects(svc.ingestDocument(t, { kb: "k1", content: "x", principal: ALICE } as never));
      await rejects(
        svc.ingestDocument(t, { kb: "Bad Name", content: "x", acl: {}, principal: ALICE }),
      );
      await rejects(svc.ensureKnowledgeBase(t, "UPPER"));
      await rejects(
        svc.ingestDocument(t, {
          kb: "big",
          content: "x ".repeat(600_000),
          acl: {},
          principal: ALICE,
        }),
      );
      const tiny = newService(pool, { chunking: { size: 2, overlap: 0 } });
      await rejects(
        tiny.ingestDocument(t, {
          kb: "many",
          content: "a".repeat(2002 * 2),
          acl: { tenant: true },
          principal: ALICE,
        }),
      );
      expect(await svc.ensureKnowledgeBase(t, "same-kb")).toBe(
        await svc.ensureKnowledgeBase(t, "same-kb"),
      );
    });

    it("filters by scope, owner, kb, metadata and minScore, and bounds limit", async () => {
      const t = await newTenant(admin);
      await svc.ingestDocument(t, {
        kb: "docs-a",
        content: "red apples",
        acl: { tenant: true },
        metadata: { lang: "en", tier: 1 },
        principal: ALICE,
      });
      await svc.ingestDocument(t, {
        kb: "docs-b",
        content: "red apples and pears",
        acl: { tenant: true },
        metadata: { lang: "de" },
        principal: ALICE,
      });
      await svc.write(t, {
        scope: "session",
        ownerRef: "s1",
        content: "red apples session note",
        acl: { tenant: true },
        principal: ALICE,
      });
      const q = { query: "red apples" };
      expect((await svc.search(t, ALICE, q)).length).toBe(3);
      expect(
        (await svc.search(t, ALICE, { ...q, scopes: ["session"] })).map((h) => h.scope),
      ).toEqual(["session"]);
      expect((await svc.search(t, ALICE, { ...q, ownerRef: "s1" })).map((h) => h.ownerRef)).toEqual(
        ["s1"],
      );
      expect((await svc.search(t, ALICE, { ...q, kbs: ["docs-b"] })).map((h) => h.kb)).toEqual([
        "docs-b",
      ]);
      expect(await svc.search(t, ALICE, { ...q, kbs: ["no-such-kb"] })).toEqual([]);
      expect(
        (await svc.search(t, ALICE, { ...q, metadata: { lang: "en" } })).map(
          (h: SearchHit) => h.metadata["tier"],
        ),
      ).toEqual([1]);
      expect((await svc.search(t, ALICE, { ...q, minScore: 0.99 })).length).toBe(1);
      expect(await svc.search(t, ALICE, { ...q, limit: 2 })).toHaveLength(2);
      for (const bad of [
        { limit: 0 },
        { limit: 51 },
        { limit: 1.5 },
        { scopes: ["x" as never] },
        { minScore: 2 },
        { minScore: "a" as never },
        { kbs: ["Bad"] },
        { query: "" },
      ])
        await rejects(svc.search(t, ALICE, { ...q, ...bad }));
      await rejects(svc.recall(t, ALICE, { scope: "x" as never }));
      await rejects(svc.recall(t, ALICE, { scope: "run", limit: 0 }));
    });

    it("never compares vectors across embedding models", async () => {
      const t = await newTenant(admin);
      await svc.write(t, {
        scope: "tenant",
        content: "model one memory",
        acl: { tenant: true },
        principal: ALICE,
      });
      const other: Embedder = {
        id: "other-model",
        dimensions: 1536,
        embed: (xs) => Promise.resolve(xs.map(() => [1, ...Array<number>(1535).fill(0)])),
      };
      const svc2 = newService(pool, { embedder: other });
      expect(await svc2.search(t, ALICE, { query: "model one memory" })).toEqual([]);
      expect(await svc.search(t, ALICE, { query: "model one memory" })).toHaveLength(1);
    });

    it("surfaces embedder failures as EMBEDDER and refuses a wrong-width embedder", async () => {
      const t = await newTenant(admin);
      const boom = newService(pool, {
        embedder: {
          id: "x",
          dimensions: 1536,
          embed: () => Promise.reject(new Error("provider down")),
        },
      });
      await rejects(boom.write(t, { scope: "tenant", content: "x", principal: ALICE }), "EMBEDDER");
      const short = newService(pool, {
        embedder: {
          id: "x",
          dimensions: 1536,
          embed: (xs) => Promise.resolve(xs.map(() => [1, 2, 3])),
        },
      });
      await rejects(
        short.write(t, { scope: "tenant", content: "x", principal: ALICE }),
        "EMBEDDER",
      );
      const nan = newService(pool, {
        embedder: {
          id: "x",
          dimensions: 1536,
          embed: (xs) => Promise.resolve(xs.map(() => Array<number>(1536).fill(NaN))),
        },
      });
      await rejects(nan.write(t, { scope: "tenant", content: "x", principal: ALICE }), "EMBEDDER");
      const count = newService(pool, {
        embedder: { id: "x", dimensions: 1536, embed: () => Promise.resolve([]) },
      });
      await rejects(
        count.write(t, { scope: "tenant", content: "x", principal: ALICE }),
        "EMBEDDER",
      );
      expect(
        () =>
          new PgMemoryService({
            pool,
            embedder: { id: "x", dimensions: 3, embed: () => Promise.resolve([]) },
          }),
      ).toThrow(MemoryError);
    });
  });

  describe("TTL, forget (DSAR), deletion and ACL changes", () => {
    it("ignores expired rows on read and purges them physically", async () => {
      const t = await newTenant(admin);
      const start = now;
      await svc.write(t, {
        scope: "session",
        ownerRef: "s",
        content: "short lived note",
        ttlSeconds: 60,
        principal: ALICE,
      });
      await svc.write(t, {
        scope: "session",
        ownerRef: "s",
        content: "durable note",
        principal: ALICE,
      });
      await svc.ingestDocument(t, {
        kb: "tmp",
        content: "short lived doc",
        acl: { tenant: true },
        ttlSeconds: 60,
        principal: ALICE,
      });
      expect(await svc.recall(t, ALICE, { scope: "session", ownerRef: "s" })).toHaveLength(2);
      now = new Date(start.getTime() + 61_000);
      expect(
        (await svc.recall(t, ALICE, { scope: "session", ownerRef: "s" })).map((e) => e.content),
      ).toEqual(["durable note"]);
      expect(
        (await svc.search(t, ALICE, { query: "short lived" })).map((h) => h.content),
      ).not.toContain("short lived note");
      expect(await svc.search(t, ALICE, { query: "short lived doc", scopes: ["kb"] })).toEqual([]);
      expect(await svc.purgeExpired(t)).toEqual({ chunks: 2, documents: 1 });
      expect(await svc.purgeExpired(t)).toEqual({ chunks: 0, documents: 0 });
      expect(
        Number(
          (await admin.query("SELECT count(*) FROM memory_chunks WHERE tenant_id = $1", [t]))
            .rows[0].count,
        ),
      ).toBe(1);
      now = start;
    });

    it("forgets everything about a subject, in this tenant only", async () => {
      const t1 = await newTenant(admin);
      const t2 = await newTenant(admin);
      for (const t of [t1, t2]) {
        await svc.write(t, {
          scope: "agent",
          ownerRef: "bot",
          content: "patient prefers mornings",
          subject: "subj-1",
          principal: ALICE,
        });
        await svc.write(t, {
          scope: "agent",
          ownerRef: "bot",
          content: "unrelated note",
          subject: "subj-2",
          principal: ALICE,
        });
        await svc.ingestDocument(t, {
          kb: "notes",
          content: "history of subj-1",
          acl: { tenant: true },
          subject: "subj-1",
          principal: ALICE,
        });
      }
      const r = await svc.forgetSubject(t1, "subj-1");
      expect(r.documents).toBe(1);
      expect(r.chunks).toBe(2); // one entry + the document's chunk
      expect(await svc.forgetSubject(t1, "subj-1")).toEqual({ chunks: 0, documents: 0 });
      const left = await admin.query(
        "SELECT subject, tenant_id FROM memory_chunks WHERE tenant_id = ANY($1) ORDER BY tenant_id, subject",
        [[t1, t2]],
      );
      expect(left.rows.filter((x) => x.tenant_id === t1).map((x) => x.subject)).toEqual(["subj-2"]);
      expect(left.rows.filter((x) => x.tenant_id === t2).map((x) => x.subject)).toEqual([
        "subj-1",
        "subj-1",
        "subj-2",
      ]);
      await rejects(svc.forgetSubject(t1, ""));
    });

    it("deletes a document with its chunks, and treats foreign or unknown ids alike", async () => {
      const t1 = await newTenant(admin);
      const t2 = await newTenant(admin);
      const d = await svc.ingestDocument(t1, {
        kb: "kb-x",
        content: "to be deleted",
        acl: { tenant: true },
        principal: ALICE,
      });
      await rejects(svc.deleteDocument(t2, d.documentId), "NOT_FOUND");
      await rejects(svc.deleteDocument(t1, "00000000-0000-4000-8000-000000000000"), "NOT_FOUND");
      await svc.deleteDocument(t1, d.documentId);
      expect(await svc.search(t1, ALICE, { query: "to be deleted" })).toEqual([]);
      expect(
        Number(
          (
            await admin.query("SELECT count(*) FROM memory_chunks WHERE document_id = $1", [
              d.documentId,
            ])
          ).rows[0].count,
        ),
      ).toBe(0);
    });

    it("changes a document ACL for the document and all its chunks at once", async () => {
      const small = newService(pool, { chunking: { size: 30, overlap: 5 } });
      const t = await newTenant(admin);
      const d = await small.ingestDocument(t, {
        kb: "acl-kb",
        content: "one two three four five six seven eight nine ten eleven twelve",
        acl: { users: ["alice"] },
        principal: ALICE,
      });
      const bob = who("bob");
      expect(await small.search(t, bob, { query: "one two three" })).toEqual([]);
      await small.setDocumentAcl(t, d.documentId, { users: ["alice", "bob"] });
      expect((await small.search(t, bob, { query: "one two three" })).length).toBeGreaterThan(0);
      await small.setDocumentAcl(t, d.documentId, { users: ["alice"] });
      expect(await small.search(t, bob, { query: "one two three" })).toEqual([]);
      await rejects(
        small.setDocumentAcl(t, "00000000-0000-4000-8000-000000000000", {}),
        "NOT_FOUND",
      );
      await rejects(small.setDocumentAcl(t, d.documentId, { bogus: 1 } as never));
    });
  });

  describe("PHI mode: redaction before persistence", () => {
    const secrets = ["123-45-6789", "jane.doe@example.com", "555-867-5309", "MRN: 99887766"];
    const content = `Patient Jane Roe, SSN 123-45-6789, reachable at jane.doe@example.com or 555-867-5309 (MRN: 99887766). Prefers mornings.`;

    async function everythingStored(t: string): Promise<string> {
      const c = await admin.query(
        "SELECT to_jsonb(memory_chunks) AS j FROM memory_chunks WHERE tenant_id = $1",
        [t],
      );
      const d = await admin.query(
        "SELECT to_jsonb(memory_documents) AS j FROM memory_documents WHERE tenant_id = $1",
        [t],
      );
      return JSON.stringify([...c.rows, ...d.rows]);
    }

    it("tenant phi_mode: nothing identifying reaches the row, the hash or the embedder", async () => {
      const spy = new SpyEmbedder();
      const s = newService(pool, { embedder: spy });
      const t = await newTenant(admin, true);
      const meta = {
        phi: { mrn: "99887766", name: "Jane Roe" },
        pii: { email: "jane.doe@example.com" },
        topic: "scheduling",
        note: "call 555-867-5309",
      };
      const w = await s.write(t, {
        scope: "agent",
        ownerRef: "bot",
        content,
        metadata: meta,
        redact: ["args.metadata.note"],
        principal: ALICE,
      });
      const d = await s.ingestDocument(t, {
        kb: "charts",
        content,
        acl: { tenant: true },
        metadata: meta,
        principal: ALICE,
      });
      expect(w.phi && d.phi).toBe(true);
      const stored = await everythingStored(t);
      for (const secret of secrets) expect(stored).not.toContain(secret);
      for (const secret of ["99887766", "123-45-6789", "jane.doe@example.com"])
        expect(stored).not.toContain(secret);
      expect(stored).toContain("[REDACTED]");
      expect(stored).toContain("Prefers mornings"); // non-sensitive text survives
      expect(stored).not.toContain('"name":"Jane Roe"'); // structured phi subtree is gone
      expect(stored).toContain("Patient Jane Roe"); // free-text NAMES are not detectable: documented limit (NEEDS)
      for (const text of spy.seen) for (const secret of secrets) expect(text).not.toContain(secret);
      const hit = (await s.search(t, ALICE, { query: "prefers mornings" }))[0];
      expect(hit?.metadata["topic"]).toBe("scheduling");
    });

    it("a request can opt in per call, but can never opt out of the tenant's phi_mode", async () => {
      const t = await newTenant(admin, false);
      const on = await svc.write(t, {
        scope: "tenant",
        content,
        acl: { tenant: true },
        phi: true,
        principal: ALICE,
      });
      expect(on.phi).toBe(true);
      expect(await everythingStored(t)).not.toContain("123-45-6789");
      const plain = await svc.write(t, {
        scope: "tenant",
        content: "SSN 123-45-6789 stays when not PHI",
        acl: { tenant: true },
        principal: ALICE,
      });
      expect(plain.phi).toBe(false);
      const strict = await newTenant(admin, true);
      const off = await svc.write(strict, {
        scope: "tenant",
        content,
        acl: { tenant: true },
        phi: false,
        principal: ALICE,
      });
      expect(off.phi).toBe(true);
      expect(await everythingStored(strict)).not.toContain("123-45-6789");
    });

    it("dedupes on the redacted content: two documents differing only in PHI are one document", async () => {
      const t = await newTenant(admin, true);
      const a = await svc.ingestDocument(t, {
        kb: "charts",
        content: "SSN 111-22-3333 is on file",
        acl: { tenant: true },
        principal: ALICE,
      });
      const b = await svc.ingestDocument(t, {
        kb: "charts",
        content: "SSN 444-55-6666 is on file",
        acl: { tenant: true },
        principal: ALICE,
      });
      expect(b).toMatchObject({ documentId: a.documentId, deduped: true });
    });

    it("rejects malformed redaction paths instead of persisting unredacted data", async () => {
      const t = await newTenant(admin, true);
      await rejects(
        svc.write(t, { scope: "tenant", content, redact: ["metadata..x"], principal: ALICE }),
      );
      expect(
        Number(
          (await admin.query("SELECT count(*) FROM memory_chunks WHERE tenant_id = $1", [t]))
            .rows[0].count,
        ),
      ).toBe(0);
    });

    it("writes of a missing tenant row in phi lookup are NOT_FOUND", async () => {
      await rejects(
        svc.ingestDocument("00000000-0000-4000-8000-000000000001", {
          kb: "kb-1",
          content: "x",
          acl: {},
          principal: ALICE,
        }),
        "NOT_FOUND",
      );
    });
  });
});
