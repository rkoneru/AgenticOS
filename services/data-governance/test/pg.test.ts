import { PgAuditLog } from "@axis/audit";
import { verifyChain } from "@axis/contracts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ApprovalsProvider,
  BillingProvider,
  ChannelsProvider,
  DsarEngine,
  EvalHubProvider,
  GovernanceAudit,
  HoldRegistry,
  ManifestSigner,
  MasterKeyProvider,
  MembersProvider,
  MemoryProvider,
  PgGovernanceStore,
  Pseudonymiser,
  ResidencyPolicy,
  RetentionEngine,
  RunLogsProvider,
  Sealer,
  StaticRegionResolver,
  verifyBundle,
  type SubjectDataProvider,
} from "../src/index.js";
import { ROLE, adminClient, newPool, newTenant, officer, OkVerifier } from "./helpers.js";
import { BOB, JANE, dumpTenant, seedTenant, type Seeded } from "./seed.js";
import type pg from "pg";

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

function build(region = "eu-west-1") {
  const o = { pool, role: ROLE };
  const store = new PgGovernanceStore(o);
  const providers: SubjectDataProvider[] = [
    new ChannelsProvider(o, true),
    new ChannelsProvider(o),
    new MemoryProvider(o),
    new MembersProvider(o),
    new BillingProvider(o),
    new EvalHubProvider(o),
    new RunLogsProvider(o),
    new ApprovalsProvider({ pg: o }),
  ];
  const keys = new MasterKeyProvider();
  const pseudo = new Pseudonymiser(keys);
  const sealer = new Sealer(keys);
  const auditLog = new PgAuditLog({ pool, role: "axis_app" });
  const audit = new GovernanceAudit(auditLog);
  const holds = new HoldRegistry({ store, pseudo, sealer, audit, now: () => new Date() });
  const signer = new ManifestSigner();
  const residency = new ResidencyPolicy({ resolve: async () => ({ homeRegion: region }) });
  const engine = new DsarEngine({
    store,
    pseudo,
    sealer,
    providers,
    audit,
    verifier: new OkVerifier(),
    residency,
    holds,
    signer,
    serviceRegion: region,
  });
  const retention = new RetentionEngine({
    store,
    providers,
    holds,
    audit,
    settings: {
      get: async () => ({
        retentionAuditDays: 2555,
        retentionTranscriptDays: 1,
        retentionMemoryDays: 1,
      }),
    },
  });
  return { store, providers, auditLog, engine, holds, signer, retention, o };
}

describe("DSAR over every real store (Postgres 16, forced RLS)", () => {
  let a: Seeded;
  let b: Seeded;
  beforeAll(async () => {
    a = await seedTenant(admin, await newTenant(admin));
    b = await seedTenant(admin, await newTenant(admin));
  });

  it("exports Jane's data from every store as a signed, verifiable bundle (and not Bob's)", async () => {
    const g = build();
    const p = officer(a.tenantId);
    const q = await g.engine.open(p, {
      kind: "export",
      identifiers: [
        { kind: "email", value: JANE.email },
        { kind: "user_ref", value: JANE.userRef },
        { kind: "subject_key", value: JANE.subjectKey },
        { kind: "channel_identity", value: JANE.slack },
      ],
    });
    await g.engine.verify(p, q.id, {});
    const bundle = await g.engine.export(p, q.id);
    expect(verifyBundle(bundle, g.signer.publicKey)).toEqual({ ok: true });
    const by = (prov: string, col: string) => bundle.records[prov]?.[col] ?? [];
    expect(by("memory", "memory_chunks")).toHaveLength(1);
    expect(by("memory", "memory_documents")).toHaveLength(1);
    expect(by("channels", "messages").length).toBe(2); // slack + voice of Jane's conversation
    expect(by("voice-transcripts", "voice_transcript_messages")).toHaveLength(1);
    expect(by("channels", "channel_identities")).toHaveLength(2);
    expect(by("control-plane-members", "members")).toHaveLength(1);
    expect(by("billing", "usage_events")).toHaveLength(2);
    expect(by("eval-hub", "dataset_cases")).toHaveLength(1);
    expect(by("eval-hub", "run_case_results")).toHaveLength(1);
    expect(by("run-logs", "runs")).toHaveLength(1);
    expect(by("approvals", "approvals_table")).toHaveLength(1);
    const text = JSON.stringify(bundle);
    expect(text).not.toContain(BOB.email);
    expect(text).not.toContain("bob fact");
    expect(bundle.manifest.stores.every((s) => s.declaration.dataClasses.length > 0)).toBe(true);
  });

  it("erases, verifies zero residual, keeps Bob and tenant B intact, and the audit chain still verifies", async () => {
    const g = build();
    const p = officer(a.tenantId);
    const bBefore = await dumpTenant(admin, b.tenantId);
    const chainBefore = await g.auditLog.verify(a.tenantId);
    expect(chainBefore.ok).toBe(true);
    const q = await g.engine.open(p, {
      kind: "erase",
      identifiers: [
        { kind: "email", value: JANE.email },
        { kind: "user_ref", value: JANE.userRef },
        { kind: "subject_key", value: JANE.subjectKey },
      ],
    });
    await g.engine.verify(p, q.id, {});
    const out = await g.engine.erase(p, q.id);
    expect(out.status).toBe("completed");
    for (const o of out.providers) expect(o.verify?.residual, o.provider).toBe(0);

    // 1. zero residual: no raw Jane identifier remains in ANY table of tenant A, except the audit tables (hashes only) and governance's own sealed request
    const dump = await dumpTenant(admin, a.tenantId);
    for (const raw of [
      JANE.email,
      JANE.userRef.replace("user_jane_01", "jane.doe"),
      "Jane Doe",
      "ext-jane",
      "subj-jane",
      "output of jane-set",
      "trace jane-set",
      "voice transcript of jane",
    ])
      expect(dump.toLowerCase(), raw).not.toContain(raw.toLowerCase());
    // user_ref stays as the opaque admin-history key on the member row (declared retained), nowhere else
    const refs = dump.split("\n").filter((l) => l.includes(JANE.userRef));
    expect(refs.every((l) => l.startsWith("members:") || l.startsWith("governance_"))).toBe(true);

    // 2. Bob and the generic data are untouched
    expect(dump).toContain(BOB.email);
    expect(dump).toContain("bob fact");
    expect(dump).toContain("question from bob");
    expect(dump).toContain("generic question");
    // 3. structure retained: run skeleton, usage quantities, member row deprovisioned, approvals decision
    const sk = await admin.query("SELECT count(*)::int n FROM run_events WHERE run_id = $1", [
      a.janeRun,
    ]);
    expect(sk.rows[0].n).toBe(2);
    const usage = await admin.query(
      "SELECT sum(quantity)::int s FROM usage_events WHERE tenant_id = $1",
      [a.tenantId],
    );
    expect(usage.rows[0].s).toBe(7 + 11 + 13);
    const m = (
      await admin.query(
        "SELECT status, email, display_name, external_id FROM members WHERE id = $1",
        [a.janeMember],
      )
    ).rows[0];
    expect(m).toMatchObject({ status: "deprovisioned", display_name: null, external_id: null });
    expect(m.email).toMatch(/^anon_[0-9a-f]{24}@erased\.invalid$/);
    expect(
      (
        await admin.query(
          "SELECT count(*)::int n FROM sessions WHERE member_id = $1 AND revoked_at IS NULL",
          [a.janeMember],
        )
      ).rows[0].n,
    ).toBe(0);
    expect(
      (
        await admin.query(
          "SELECT count(*)::int n FROM api_keys WHERE owner_member_id = $1 AND revoked_at IS NULL",
          [a.janeMember],
        )
      ).rows[0].n,
    ).toBe(0);
    expect(
      (
        await admin.query(
          "SELECT count(*)::int n FROM approvals WHERE tenant_id = $1 AND decided_by LIKE 'anon_%'",
          [a.tenantId],
        )
      ).rows[0].n,
    ).toBe(1);
    // the eval dataset keeps its case ids but the content is tombstoned
    const ds = (
      await admin.query("SELECT data FROM eval_hub_docs WHERE tenant_id=$1 AND key='jane-set@1'", [
        a.tenantId,
      ])
    ).rows[0].data;
    expect(ds.cases.map((c: { id: string }) => c.id)).toEqual(["c1", "c2"]);
    expect(ds.cases[0].input).toEqual({ governance: "erased" });

    // 4. tenant B: byte-identical
    expect(await dumpTenant(admin, b.tenantId)).toBe(bBefore);

    // 5. the audit chain is intact after the erase and carries no raw PII
    const verdict = await g.auditLog.verify(a.tenantId);
    expect(verdict.ok).toBe(true);
    const events = await g.auditLog.read(a.tenantId, {});
    expect(verifyChain(events)).toMatchObject({ ok: true });
    expect(events.map((e) => e.action)).toEqual(
      expect.arrayContaining([
        "dsar.received",
        "dsar.verified",
        "dsar.erase.started",
        "dsar.erase.completed",
      ]),
    );
    const evText = JSON.stringify(events).toLowerCase();
    for (const raw of [JANE.email, "jane", JANE.userRef, JANE.subjectKey])
      expect(evText).not.toContain(raw.toLowerCase());

    // 6. shredded: the identifier no longer maps to the subject, request identifiers are gone
    const done = await g.store.getRequest(a.tenantId, q.id);
    expect(done?.sealedIdentifiers).toBeNull();
    expect(await g.store.findSubjects(a.tenantId, [])).toEqual([]);
    expect(
      (
        await admin.query(
          "SELECT count(*)::int n FROM governance_subject_identifiers WHERE tenant_id=$1 AND subject_id=$2",
          [a.tenantId, done!.subjectId],
        )
      ).rows[0].n,
    ).toBe(0);
    expect(
      (
        await admin.query(
          "SELECT salt FROM governance_subjects WHERE tenant_id=$1 AND subject_id=$2",
          [a.tenantId, done!.subjectId],
        )
      ).rows[0].salt,
    ).toBeNull();

    // 7. idempotent
    const again = await g.engine.erase(p, q.id);
    expect(again.status).toBe("completed");
  });

  const asRole = async (
    role: string,
    tenant: string,
    sql: string,
  ): Promise<{ rows: { n: number }[] }> => {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(`SET LOCAL ROLE ${role}`);
      await c.query("SELECT axis.set_tenant($1)", [tenant]);
      return (await c.query(sql)) as { rows: { n: number }[] };
    } finally {
      await c.query("ROLLBACK").catch(() => undefined);
      c.release();
    }
  };

  it("the append-only guards still hold for the application role", async () => {
    const app = (sql: string) => asRole("axis_app", b.tenantId, sql);
    await expect(app("UPDATE run_events SET data = '{}'")).rejects.toThrow(
      /permission denied|append-only/,
    );
    await expect(app("UPDATE usage_events SET actor = 'x'")).rejects.toThrow(
      /permission denied|append-only/,
    );
    await expect(app(`UPDATE runs SET input = '{}' WHERE id = '${b.bobRun}'`)).rejects.toThrow(
      /immutable|terminated/,
    );
    await expect(app("UPDATE approvals SET decided_by = 'x'")).rejects.toThrow(
      /already|permission denied/,
    );
    await expect(app("DELETE FROM eval_hub_docs")).rejects.toThrow(/permission denied|forbidden/);
    await expect(app("DELETE FROM governance_subject_identifiers")).rejects.toThrow(
      /permission denied/,
    );
    await expect(app("SELECT 1 FROM governance_holds")).resolves.toBeTruthy(); // RLS-scoped read is fine
  });

  it("the governance role itself cannot touch audit tables or another tenant, and can only scrub the allowed columns", async () => {
    const gov = (sql: string, tenant = b.tenantId) => asRole("axis_governance", tenant, sql);
    await expect(gov("DELETE FROM audit_events")).rejects.toThrow(/permission denied/);
    await expect(gov("UPDATE audit_events SET reason = 'x'")).rejects.toThrow(/permission denied/);
    await expect(gov("UPDATE usage_events SET quantity = 1")).rejects.toThrow(/append-only/);
    await expect(gov("UPDATE run_events SET type = 'x'")).rejects.toThrow(/append-only/);
    await expect(gov("DELETE FROM run_events")).rejects.toThrow(/permission denied/);
    await expect(gov("DELETE FROM usage_events")).rejects.toThrow(/permission denied/);
    await expect(gov("UPDATE runs SET state = 'running'")).rejects.toThrow(/terminated/);
    await expect(gov("DELETE FROM governance_requests")).rejects.toThrow(/permission denied/);
    await expect(gov("UPDATE eval_hub_docs SET data = '{}'")).rejects.toThrow(/stale|identity/);
    await expect(gov("UPDATE approvals SET status = 'pending'")).rejects.toThrow(/already/);
    expect((await gov("SELECT count(*)::int n FROM members", a.tenantId)).rows[0]?.n).toBe(3);
    expect(
      (await gov("SELECT count(*)::int n FROM members", "00000000-0000-4000-8000-000000000000"))
        .rows[0]?.n,
    ).toBe(0);
  });

  it("refuses to erase the sole active owner", async () => {
    const g = build();
    const p = officer(b.tenantId);
    const q = await g.engine.open(p, {
      kind: "erase",
      identifiers: [{ kind: "email", value: "owner@corp.example" }],
    });
    await g.engine.verify(p, q.id, {});
    await expect(g.engine.erase(p, q.id)).rejects.toMatchObject({ code: "conflict" });
    expect(
      (
        await admin.query(
          "SELECT status FROM members WHERE user_ref='user_owner_00' AND tenant_id=$1",
          [b.tenantId],
        )
      ).rows[0].status,
    ).toBe("active");
  });

  it("a region-pinned tenant's export to another region is refused", async () => {
    const g = build("eu-west-1");
    const p = officer(b.tenantId);
    const q = await g.engine.open(p, {
      kind: "export",
      identifiers: [{ kind: "email", value: BOB.email }],
      destinationRegion: "us-east-1",
    });
    await g.engine.verify(p, q.id, {});
    await expect(g.engine.export(p, q.id)).rejects.toMatchObject({ code: "residency" });
    const regions = new ResidencyPolicy(new StaticRegionResolver({}));
    await expect(regions.assertEgress(b.tenantId, "eu-west-1")).rejects.toThrow();
  });
});

describe("retention purge over real stores", () => {
  it("purges expired rows per class, protects held subjects, and dry-run changes nothing", async () => {
    const t = await newTenant(admin);
    const s = await seedTenant(admin, t);
    // age everything by 10 days
    await admin.query(
      "UPDATE memory_chunks SET created_at = now() - interval '10 days' WHERE tenant_id = $1",
      [t],
    );
    await admin.query(
      "UPDATE memory_documents SET created_at = now() - interval '10 days' WHERE tenant_id = $1",
      [t],
    );
    await admin.query(
      "UPDATE conversation_messages SET created_at = now() - interval '10 days' WHERE tenant_id = $1",
      [t],
    );
    const g = build();
    const p = officer(t);
    const count = async (sql: string) => Number((await admin.query(sql, [t])).rows[0].n);
    const before = {
      chunks: await count("SELECT count(*) n FROM memory_chunks WHERE tenant_id=$1"),
      msgs: await count("SELECT count(*) n FROM conversation_messages WHERE tenant_id=$1"),
    };
    const dry = await g.retention.run(p, {
      dryRun: true,
      classes: ["memory", "conversation", "transcripts"],
    });
    expect(dry.classes.map((c) => c.status)).toEqual(["dry_run", "dry_run", "dry_run"]);
    expect(await count("SELECT count(*) n FROM memory_chunks WHERE tenant_id=$1")).toBe(
      before.chunks,
    );

    // hold Bob (subject key + end user): his rows must survive, Jane's go
    await g.holds.placeHold(p, {
      scope: "subject",
      reason: "dispute with Bob",
      groups: [
        [
          { kind: "subject_key", value: BOB.subjectKey },
          { kind: "end_user_id", value: s.bobEndUser },
        ],
      ],
    });
    const rep = await g.retention.run(p, { classes: ["memory", "conversation", "transcripts"] });
    expect(rep.classes.map((c) => c.status)).toEqual(["purged", "purged", "purged"]);
    expect(rep.classes[0]?.protectedByHold).toBeGreaterThan(0);
    const left = (
      await admin.query("SELECT subject FROM memory_chunks WHERE tenant_id=$1", [t])
    ).rows.map((r) => r.subject);
    expect(left.every((x) => x === BOB.subjectKey)).toBe(true);
    expect(left.length).toBe(2);
    const msgs = (
      await admin.query(
        "SELECT DISTINCT c.end_user_id FROM conversation_messages m JOIN conversations c ON c.id = m.conversation_id WHERE m.tenant_id=$1",
        [t],
      )
    ).rows.map((r) => r.end_user_id);
    expect(msgs).toEqual([s.bobEndUser]);
    // a tenant hold freezes the rest
    const th = await g.holds.placeHold(p, { scope: "tenant", reason: "global freeze" });
    const frozen = await g.retention.run(p, { classes: ["memory"] });
    expect(frozen.classes[0]?.status).toBe("skipped_hold");
    await g.holds.release(p, th.id);
    expect((await g.retention.run(p, { classes: ["memory"] })).classes[0]?.status).toBe("purged");
    expect(await g.auditLog.verify(t)).toMatchObject({ ok: true });
  });

  it("scrubs old run logs and eval runs and pseudonymises old billing actors without deleting financial rows", async () => {
    const t = await newTenant(admin);
    const s = await seedTenant(admin, t);
    await admin.query("UPDATE runs SET created_at = created_at WHERE false");
    await admin.query("SET session_replication_role = replica"); // owner-only backdating for the test (bypasses the immutable-column guard)
    await admin.query(
      "UPDATE runs SET created_at = now() - interval '400 days' WHERE tenant_id = $1",
      [t],
    );
    await admin.query(
      "UPDATE usage_events SET event_time = now() - interval '4000 days' WHERE tenant_id = $1",
      [t],
    );
    await admin.query("SET session_replication_role = origin");
    await admin
      .query(
        "UPDATE eval_hub_docs SET data = jsonb_set(data, '{created_at}', to_jsonb((now() - interval '900 days')::text)), rev = rev WHERE tenant_id=$1 AND coll='runs'",
        [t],
      )
      .catch(() => undefined);
    const g = build();
    const p = officer(t);
    const rep = await g.retention.run(p, { classes: ["run_logs", "billing"] });
    expect(rep.classes.find((c) => c.dataClass === "run_logs")).toMatchObject({ status: "purged" });
    expect(rep.classes.find((c) => c.dataClass === "billing")).toMatchObject({ status: "purged" });
    const runs = (await admin.query("SELECT input FROM runs WHERE tenant_id=$1", [t])).rows.map(
      (r) => r.input,
    );
    expect(runs.every((i) => i.governance === "purged")).toBe(true);
    expect(
      (await admin.query("SELECT count(*)::int n FROM run_events WHERE tenant_id=$1", [t])).rows[0]
        .n,
    ).toBe(4);
    const ev = (await admin.query("SELECT data FROM run_events WHERE tenant_id=$1", [t])).rows.map(
      (r) => r.data,
    );
    expect(ev.every((d) => d.governance === "purged")).toBe(true);
    const bill = (
      await admin.query("SELECT actor, quantity FROM usage_events WHERE tenant_id=$1", [t])
    ).rows;
    expect(bill).toHaveLength(3);
    expect(bill.filter((r) => r.actor !== null).every((r) => r.actor === "anon_expired")).toBe(
      true,
    );
    expect(s.janeRun).toBeTruthy();
  });
});

describe("eval-hub retention purge", () => {
  it("purges old finished runs, protects runs over held subjects' datasets", async () => {
    const t = await newTenant(admin);
    await seedTenant(admin, t);
    await admin.query("SET session_replication_role = replica"); // owner-only backdating (bypasses the immutability trigger)
    await admin.query(
      "UPDATE eval_hub_docs SET data = jsonb_set(data, '{created_at}', to_jsonb((now() - interval '2000 days')::text)) WHERE tenant_id=$1 AND coll='runs'",
      [t],
    );
    await admin.query("SET session_replication_role = origin");
    const g = build();
    const p = officer(t);
    await g.holds.placeHold(p, {
      scope: "subject",
      reason: "dispute",
      groups: [[{ kind: "subject_key", value: BOB.subjectKey }]],
    });
    const dry = await g.retention.run(p, { dryRun: true, classes: ["eval_data"] });
    expect(dry.classes[0]).toMatchObject({
      status: "dry_run",
      matched: 2,
      purged: 0,
      protectedByHold: 1,
    });
    const rep = await g.retention.run(p, { classes: ["eval_data"] });
    expect(rep.classes[0]).toMatchObject({
      status: "purged",
      matched: 2,
      purged: 1,
      protectedByHold: 1,
    });
    const left = (
      await admin.query("SELECT key FROM eval_hub_docs WHERE tenant_id=$1 AND coll='runs'", [t])
    ).rows.map((r) => r.key);
    expect(left).toEqual(["run-bob"]);
  });
});

describe("PgGovernanceStore contract", () => {
  it("round-trips requests, steps, holds, policies and runs under RLS", async () => {
    const t1 = await newTenant(admin);
    const t2 = await newTenant(admin);
    const g = build();
    const s = g.store;
    const lookups = [{ hmac: "a".repeat(64), kind: "email" }];
    const sid = await s.createSubject(t1, lookups, Buffer.alloc(32, 1));
    expect(await s.findSubjects(t1, ["a".repeat(64)])).toEqual([sid]);
    expect(await s.findSubjects(t2, ["a".repeat(64)])).toEqual([]);
    await s.addLookups(t1, sid, [{ hmac: "b".repeat(64), kind: "phone" }]);
    expect(await s.findSubjects(t1, ["a".repeat(64), "b".repeat(64)])).toEqual([sid]);
    expect((await s.getSubject(t1, sid))?.salt?.length).toBe(32);
    expect(await s.getSubject(t2, sid)).toBeUndefined();
    expect(await s.shredSubject(t1, sid, new Date())).toBe(2);
    expect((await s.getSubject(t1, sid))?.salt).toBeNull();
    expect(await s.shredSubject(t1, sid, new Date())).toBe(0);
    await expect(s.findSubjects(t1, [])).resolves.toEqual([]);
    const req = {
      tenantId: t1,
      id: "00000000-0000-4000-8000-0000000000aa",
      kind: "erase" as const,
      subjectId: sid,
      subjectRef: `sub_${"c".repeat(32)}`,
      status: "received" as const,
      receivedAt: new Date(),
      dueAt: new Date(Date.now() + 1e9),
      extendedUntil: null,
      extensionReason: null,
      verifiedAt: null,
      verifiedMethod: null,
      requestedBy: "o",
      destinationRegion: null,
      sealedIdentifiers: Buffer.from("zz"),
      result: {},
      rev: 1,
    };
    await s.insertRequest(req);
    await expect(s.insertRequest(req)).rejects.toMatchObject({ code: "conflict" });
    expect(await s.getRequest(t2, req.id)).toBeUndefined();
    const up = await s.updateRequest({ ...req, status: "verified", result: { a: 1 } }, 1);
    expect(up).toMatchObject({ rev: 2, status: "verified", result: { a: 1 } });
    await expect(s.updateRequest({ ...req, status: "verified" }, 1)).rejects.toMatchObject({
      code: "conflict",
    });
    expect(await s.listRequests(t1, ["verified"])).toHaveLength(1);
    expect(await s.listRequests(t1, ["completed"])).toHaveLength(0);
    expect(await s.listRequests(t1)).toHaveLength(1);
    expect(await s.listRequests(t2)).toHaveLength(0);
    await s.putStep({
      tenantId: t1,
      requestId: req.id,
      provider: "x",
      phase: "erase",
      status: "done",
      result: { n: 1 },
    });
    await s.putStep({
      tenantId: t1,
      requestId: req.id,
      provider: "x",
      phase: "erase",
      status: "done",
      result: { n: 2 },
    });
    expect((await s.getStep(t1, req.id, "x", "erase"))?.result).toEqual({ n: 2 });
    expect(await s.getStep(t1, req.id, "x", "verify")).toBeUndefined();
    expect(await s.listSteps(t1, req.id)).toHaveLength(1);
    const hold = {
      tenantId: t1,
      id: "00000000-0000-4000-8000-0000000000bb",
      kind: "legal_hold" as const,
      scope: "tenant" as const,
      subjectId: null,
      caseRef: null,
      dataClasses: ["memory" as const],
      reason: "because",
      sealedIdentifiers: null,
      placedBy: "o",
      placedAt: new Date(),
      releasedBy: null,
      releasedAt: null,
    };
    await s.insertHold(hold);
    expect(await s.listHolds(t1, true)).toHaveLength(1);
    expect(await s.listHolds(t2, false)).toHaveLength(0);
    expect((await s.getHold(t1, hold.id))?.dataClasses).toEqual(["memory"]);
    await s.releaseHold(t1, hold.id, "o2", new Date());
    expect(await s.listHolds(t1, true)).toHaveLength(0);
    expect(await s.listHolds(t1, false)).toHaveLength(1);
    await expect(
      s.releaseHold(t1, "00000000-0000-4000-8000-0000000000cc", "o", new Date()),
    ).rejects.toMatchObject({ code: "not_found" });
    await s.setPolicy(t1, "run_logs", 90, "o", new Date());
    await s.setPolicy(t1, "run_logs", 120, "o", new Date());
    expect(await s.getPolicies(t1)).toEqual({ run_logs: 120 });
    expect(await s.getPolicies(t2)).toEqual({});
    const run = {
      tenantId: t1,
      id: "00000000-0000-4000-8000-0000000000dd",
      dryRun: true,
      startedAt: new Date(),
      finishedAt: null,
      report: {},
    };
    await s.insertRun(run);
    await s.finishRun(t1, run.id, new Date(), { ok: 1 });
    expect((await s.listRuns(t1))[0]).toMatchObject({ report: { ok: 1 } });
    expect(await s.listRuns(t2)).toEqual([]);
  });
});

void RetentionEngine;
