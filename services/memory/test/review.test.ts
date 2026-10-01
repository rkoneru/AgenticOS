import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { scrubText } from "../src/redact.js";
import { adminClient, newPool, newService, newTenant, who } from "./helpers.js";
import type { PgMemoryService } from "../src/index.js";

const ALICE = who("alice", "eng");

describe("Phase 4 review: memory", () => {
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

  async function stored(t: string): Promise<string> {
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

  it("PHI mode scrubs a document's title and source, which were persisted verbatim", async () => {
    const t = await newTenant(admin, true);
    await svc.ingestDocument(t, {
      kb: "charts",
      content: "Quarterly summary",
      title: "Chart for SSN 123-45-6789",
      source: "https://ehr.example/records?email=jane.doe@example.com&mrn=1",
      acl: { tenant: true },
      principal: ALICE,
    });
    const s = await stored(t);
    expect(s).not.toContain("123-45-6789");
    expect(s).not.toContain("jane.doe@example.com");
  });

  describe("PHI scrub is a net, but not one a separator or a code point gets through", () => {
    const ssns = [
      "123-45-6789",
      "123 45 6789",
      "123.45.6789",
      "123–45–6789", // en dashes
      "123−45−6789", // minus sign
      "123 - 45 - 6789",
      "１２３-４５-６７８９", // fullwidth digits
      "123-45-67​89", // zero-width space inside a group
      "1​23-45-6789",
      "١٢٣-٤٥-٦٧٨٩", // Arabic-Indic digits
      "SSN: 123456789",
      "social security number 123456789",
    ];
    for (const ssn of ssns)
      it(`scrubs ${JSON.stringify(ssn)}`, () => {
        const out = scrubText(`patient ${ssn} on file`);
        expect(out).toContain("[REDACTED]");
        expect(out.replace(/\D/g, "")).not.toMatch(/123456789/);
      });
    it("does not redact ordinary numbers", () => {
      for (const ok of ["order 2024-12-31", "version 1.2.3", "call 4155 now", "room 12 45 floor"])
        expect(scrubText(ok)).toBe(ok);
    });
  });

  it("a deduped write cannot detach a row from its data subject (DSAR forget must still find it)", async () => {
    const t = await newTenant(admin);
    const base = { scope: "tenant" as const, content: "Prefers mornings", principal: ALICE };
    const a = await svc.write(t, { ...base, subject: "subject-1" });
    const b = await svc.write(t, base); // same content and ACL, no subject: dedupes onto row a
    expect(b).toMatchObject({ id: a.id, deduped: true });
    expect(await svc.forgetSubject(t, "subject-1")).toEqual({ chunks: 1, documents: 0 });
  });
});
