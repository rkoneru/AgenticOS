import { PgAuditLog } from "@axis/audit";
import { PgConversationStore, transcriptContent, parseTranscriptEvent } from "@axis/channels";
import { PgDocStore, createEvalHub } from "@axis/eval-hub";
import { HashEmbedder, PgMemoryService } from "@axis/memory";
import { ServiceAudit } from "@axis/registry";
import { createHash } from "node:crypto";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CANARIES, NAME_CANARY, findLeaks, leaks, normalize } from "../src/phi-canary.js";
import { adminClient, newPool, newTenant } from "./helpers.js";
import { dumpTenant } from "./seed.js";

let admin: pg.Client;
let pool: pg.Pool;
beforeAll(async () => {
  admin = await adminClient();
  pool = newPool();
});
afterAll(async () => {
  await pool.end();
  await admin.end();
});

const ALL_TEXT = CANARIES.map((c) => c.text).join(" | ");
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

describe("canary detector", () => {
  it("sees obfuscated variants and ignores unrelated numbers", () => {
    for (const c of CANARIES) expect(leaks(c.text, c), c.id).toBe(true);
    expect(leaks("SSN １２３ ４５ ６７８９", CANARIES[0]!)).toBe(true);
    expect(leaks("order 99-1234 of 2026", CANARIES[0]!)).toBe(false);
    expect(findLeaks("[REDACTED] and [REDACTED]")).toEqual([]);
    expect(normalize("A​B")).toBe("ab");
  });
});

describe("PHI-mode tenant: no raw canary in any persisted store, log, audit event or error", () => {
  it("holds across memory, eval datasets, channel messages and voice transcript events", async () => {
    const tenant = await newTenant(admin, { phi: true });
    const logs: string[] = [];
    const errors: string[] = [];
    const attempt = async (f: () => Promise<unknown>): Promise<void> => {
      try {
        await f();
      } catch (e) {
        errors.push(String((e as Error).message));
      }
    };

    // --- memory write + ingest (tenant phi_mode turns redaction on)
    const mem = new PgMemoryService({ pool, embedder: new HashEmbedder(), role: "axis_app" });
    const who = { id: "svc", groups: [] as string[] };
    await mem.write(tenant, {
      scope: "tenant",
      content: ALL_TEXT,
      metadata: { note: ALL_TEXT, nested: { deep: [ALL_TEXT] } },
      subject: "opaque-subject-1",
      principal: who,
    });
    await mem.ensureKnowledgeBase(tenant, "kb-phi");
    await mem.ingestDocument(tenant, {
      kb: "kb-phi",
      content: Array(3).fill(ALL_TEXT).join(" / "),
      acl: { tenant: true },
      title: CANARIES[0]!.text,
      source: `https://x.example/?q=${CANARIES[7]!.core.value}`,
      metadata: { m: ALL_TEXT },
      subject: "opaque-subject-1",
      principal: who,
    } as never);
    await attempt(() =>
      mem.write(tenant, { scope: "run", ownerRef: ALL_TEXT, content: "x", principal: who }),
    );
    await attempt(() => mem.search(tenant, who, { query: ALL_TEXT, limit: 3 } as never));

    // --- eval dataset ingest (phi flag), hook-free
    const docs = new PgDocStore({ pool, role: "axis_app" });
    const auditLog = new PgAuditLog({ pool, role: "axis_app" });
    const hub = createEvalHub({
      docs,
      audit: new ServiceAudit(auditLog, "eval-hub"),
      log: (m: string) => logs.push(m),
    });
    const admn = {
      kind: "tenant" as const,
      tenantId: tenant,
      subject: "alice",
      role: "admin" as const,
    };
    await hub.datasets.create(admn, {
      name: "phi-set",
      phi: true,
      description: ALL_TEXT,
      cases: [
        {
          id: "c1",
          input: { q: ALL_TEXT, [CANARIES[7]!.core.value]: 1 },
          expected: ALL_TEXT,
          tags: [CANARIES[0]!.core.value],
          metadata: { x: ALL_TEXT },
        },
      ],
    });
    await attempt(() => hub.datasets.create(admn, { name: ALL_TEXT, cases: [] }));

    // --- channel messages: the transcript policy the gateway applies, then the real Postgres message log
    const store = new PgConversationStore({ pool, role: "axis_app" });
    const { identity } = await store.resolveIdentity(tenant, "slack", "U123");
    const conv = await store.createConversation(
      tenant,
      identity.end_user_id,
      { name: "support", version: "1.0.0" },
      "slack",
    );
    for (const mode of ["full", "redacted_preview", "hash_only"] as const) {
      const t = transcriptContent(ALL_TEXT, mode, true);
      await store.appendMessage(tenant, {
        tenant_id: tenant,
        conversation_id: conv.id,
        direction: "in",
        channel: "slack",
        idempotency_key: `k-${mode}`,
        content_mode: t.mode,
        content: t.content,
        content_hash: sha(t.content ?? ""),
        size_bytes: ALL_TEXT.length,
        attachments: [],
        audit_event_id: null,
        audit_hash: null,
      });
    }

    // --- voice: transcript events may carry hashes/ids only; text smuggled into any string field is refused
    for (const c of CANARIES.slice(0, 4))
      await attempt(async () =>
        parseTranscriptEvent({
          kind: "turn",
          channel: "voice",
          call_id: c.text,
          trace_id: "a".repeat(32),
          agent: { name: "a", version: "1" },
          turn: 1,
          role: "user",
          text_sha256: "b".repeat(64),
          size: 5,
          redacted: true,
          truncated: false,
          audio_bytes: 0,
        }),
      );
    await attempt(async () =>
      parseTranscriptEvent({
        kind: "call",
        channel: "voice",
        call_id: "c1",
        trace_id: "a".repeat(32),
        agent: { name: "a", version: "1" },
        phase: ALL_TEXT,
      }),
    );

    // --- scan: every table of the tenant (postgres text dump), captured logs, error messages
    const dump = await dumpTenant(admin, tenant);
    expect(dump.length).toBeGreaterThan(500);
    const byTable: Record<string, string[]> = {};
    for (const line of dump.split("\n")) {
      const tbl = line.slice(0, line.indexOf(":"));
      const hit = findLeaks(line);
      if (hit.length) (byTable[tbl] ??= []).push(...hit);
    }
    expect(Object.keys(byTable), JSON.stringify(byTable)).toEqual([]);
    expect(findLeaks(logs.join("\n")), "logs").toEqual([]);
    expect(findLeaks(errors.join("\n")), "errors").toEqual([]);
    expect(errors.length).toBeGreaterThan(0);
    // sanity: the stores really were written (the scan is not vacuous)
    expect(dump).toContain("[REDACTED]");
    expect(dump).toContain("opaque-subject-1");
  });

  it("a name has no pattern: it is NOT removed by the built-in net (known limit, NEEDS 3201)", async () => {
    const t = transcriptContent(NAME_CANARY.text, "full", true);
    expect(leaks(t.content ?? "", NAME_CANARY)).toBe(true);
    const hooked = transcriptContent(NAME_CANARY.text, "full", true, (s) =>
      s.replace(/Zelda Quentin Canary/g, "[NAME]"),
    );
    expect(leaks(hooked.content ?? "", NAME_CANARY)).toBe(false);
  });
});
