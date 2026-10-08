import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ComplianceAdapter,
  GatewayAuditSource,
  GatewayBlueprintSource,
  GatewayEvalSource,
  GatewayPolicySource,
  UnavailableCompliance,
  fromComplianceError,
  isDocumentationEvent,
  suiteMatches,
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type ComplianceSourceDeps,
} from "../src/index.js";
import { ComplianceError } from "@axis/compliance";
import { ABL, call, makeWorld, seed, type Cred, type Seed, type World } from "./world.js";

let w: World;
let s: Seed;
let builder: Cred;
let auditor: Cred;
let admin: Cred;

beforeAll(async () => {
  w = await makeWorld({
    rate: { burst: 1e6, perSecond: 1e6 },
    unauthRate: { burst: 1e6, perSecond: 1e6 },
  });
  s = await seed(w);
  builder = await w.member(s.owner.tenantId, "builder");
  auditor = await w.member(s.owner.tenantId, "auditor");
  admin = await w.member(s.owner.tenantId, "admin");
});
afterAll(() => w.close());

const sys = (over: Record<string, unknown> = {}) => ({
  name: "Claims triage",
  purpose: "Routes claims",
  owner: "owner@example.test",
  risk_level: "high",
  ...over,
});
const asm = (systemId: string, over: Record<string, unknown> = {}) => ({
  system_id: systemId,
  title: "Impact",
  risk_rating: "high",
  intended_use: "Routing",
  review_due: "2099-01-01",
  ...over,
});

describe("compliance over HTTP", () => {
  it("runs the whole workflow with the roles of the pack; the reviewer must be independent", async () => {
    const mk = await call(w, "POST", "/compliance/systems", {
      token: builder.token,
      body: sys({ system_id: "http-flow" }),
    });
    expect(mk.status, mk.text).toBe(201);
    expect(mk.body.created_by).toBe(builder.memberId);
    const up = await call(w, "PUT", "/compliance/systems/http-flow", {
      token: builder.token,
      body: { expected_version: 1, lifecycle_stage: "deployed" },
    });
    expect(up.body.version).toBe(2);
    const stale = await call(w, "PUT", "/compliance/systems/http-flow", {
      token: builder.token,
      body: { expected_version: 1, purpose: "x" },
    });
    expect(stale.status).toBe(409);
    const a = await call(w, "POST", "/compliance/impact-assessments", {
      token: builder.token,
      body: asm("http-flow"),
    });
    expect(a.status, a.text).toBe(201);
    const id = a.body.assessment_id as string;
    const sub = await call(w, "POST", `/compliance/impact-assessments/${id}/submit`, {
      token: builder.token,
      body: { expected_version: 1 },
    });
    expect(sub.body.state).toBe("in_review");
    // the author's role cannot review at all (pack), an auditor can; the author as owner would be refused as the same person
    const asBuilder = await call(w, "POST", `/compliance/impact-assessments/${id}/review`, {
      token: builder.token,
      body: { expected_version: 1, decision: "approve" },
    });
    expect(asBuilder.status).toBe(403);
    const done = await call(w, "POST", `/compliance/impact-assessments/${id}/review`, {
      token: auditor.token,
      body: { expected_version: 1, decision: "approve", comment: "ok" },
    });
    expect(done.status, done.text).toBe(200);
    expect(done.body).toMatchObject({ state: "approved", reviewed_by: auditor.memberId });
    const again = await call(w, "POST", `/compliance/impact-assessments/${id}/review`, {
      token: auditor.token,
      body: { expected_version: 1, decision: "approve" },
    });
    expect(again.status).toBe(422);
    const v2 = await call(w, "PUT", `/compliance/impact-assessments/${id}`, {
      token: admin.token,
      body: { expected_version: 1, risk_rating: "critical" },
    });
    expect(v2.body).toMatchObject({ version: 2, state: "draft", supersedes: 1 });
    const list = await call(w, "GET", `/compliance/impact-assessments?system_id=http-flow`, {
      token: auditor.token,
    });
    expect(list.body.items.map((x: { version: number }) => x.version)).toEqual([2]);
    const old = await call(w, "GET", `/compliance/impact-assessments/${id}?version=1`, {
      token: auditor.token,
    });
    expect(old.body).toMatchObject({ version: 1, superseded: true });
  });

  it("an owner who authored an assessment cannot approve it, even though the role is allowed", async () => {
    const a = await call(w, "POST", "/compliance/impact-assessments", {
      token: s.owner.token,
      body: asm(s.compliance.systemId),
    });
    const id = a.body.assessment_id as string;
    await call(w, "POST", `/compliance/impact-assessments/${id}/submit`, {
      token: s.owner.token,
      body: { expected_version: 1 },
    });
    const r = await call(w, "POST", `/compliance/impact-assessments/${id}/review`, {
      token: s.owner.token,
      body: { expected_version: 1, decision: "approve" },
    });
    expect(r.status, r.text).toBe(403);
    expect(
      (await call(w, "GET", `/compliance/impact-assessments/${id}`, { token: s.owner.token })).body
        .state,
    ).toBe("in_review");
    // the refusal is in the tenant's chain
    const events = await w.audit.read(s.owner.tenantId, {});
    expect(
      events.some((e) => e.action === "compliance.assessment.review" && e.decision === "DENY"),
    ).toBe(true);
  });

  it("validation problems carry the failing paths", async () => {
    const r = await call(w, "POST", "/compliance/impact-assessments", {
      token: builder.token,
      body: asm("nope-system", { review_due: "2026-02-30" }),
    });
    expect(r.status).toBe(422);
    expect(JSON.stringify(r.body)).toContain("/review_due");
    const r2 = await call(w, "POST", "/compliance/systems", {
      token: builder.token,
      body: sys({ blueprints: [{ name: "BAD NAME", version: "1.0.0" }] }),
    });
    expect(r2.status).toBe(422);
  });

  it("another tenant sees none of it, and cannot act on it", async () => {
    const other = await w.tenant();
    const otherAuditor = await w.member(other.tenantId, "auditor");
    expect(
      (await call(w, "GET", "/compliance/systems", { token: other.token })).body.items,
    ).toEqual([]);
    expect(
      (await call(w, "GET", `/compliance/systems/${s.compliance.systemId}`, { token: other.token }))
        .status,
    ).toBe(404);
    expect(
      (
        await call(w, "GET", `/compliance/impact-assessments/${s.compliance.reviewId}`, {
          token: other.token,
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await call(w, "GET", `/compliance/documents/${s.compliance.documentId}`, {
          token: other.token,
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await call(w, "POST", `/compliance/impact-assessments/${s.compliance.reviewId}/review`, {
          token: otherAuditor.token,
          body: { expected_version: 1, decision: "approve" },
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await call(w, "PUT", `/compliance/systems/${s.compliance.systemId}`, {
          token: other.token,
          body: { expected_version: 1, purpose: "hijack" },
        })
      ).status,
    ).toBe(404);
    // a document is generated from the caller's tenant only: the other tenant has no such blueprint
    const g = await call(w, "POST", "/compliance/documents", {
      token: other.token,
      body: { blueprint: s.blueprint },
    });
    expect(g.status).toBe(201);
    expect(g.body.document.body.sections.general.status).toBe("gap");
    expect(g.body.document.body.blueprint.content_hash).toBeNull();
  });

  it("API key scopes: compliance:read cannot write; compliance:write can write but a builder's key cannot review", async () => {
    const ro = await w.apiKey(admin, ["compliance:read"]);
    expect((await call(w, "GET", "/compliance/systems", { key: ro })).status).toBe(200);
    expect((await call(w, "POST", "/compliance/systems", { key: ro, body: sys() })).status).toBe(
      403,
    );
    const rw = await w.apiKey(builder, ["compliance:write"]);
    expect(
      (
        await call(w, "POST", "/compliance/systems", {
          key: rw,
          body: sys({ system_id: "key-made" }),
        })
      ).status,
    ).toBe(201);
    const wrong = await w.apiKey(builder, ["runs:write"]);
    expect((await call(w, "GET", "/compliance/systems", { key: wrong })).status).toBe(403);
  });

  it("documents: a tenant-local blueprint is documented with its gaps; regenerating unchanged gives the same document", async () => {
    const g1 = await call(w, "POST", "/compliance/documents", {
      token: builder.token,
      body: { blueprint: s.blueprint },
    });
    expect([200, 201]).toContain(g1.status);
    const d = g1.body.document;
    expect(d.body.sections.general.data.origin).toBe("tenant");
    expect(d.body.sections.record_keeping.status).toBe("complete");
    expect(d.body.sections.record_keeping.data.chain_verified).toBe(true);
    expect(d.body.gaps.some((x: { item: string }) => x.item === "registry_provenance")).toBe(true);
    expect(d.body.sections.limitations.data.items[0].id).toBe("NEEDS-1");
    const g2 = await call(w, "POST", "/compliance/documents", {
      token: builder.token,
      body: { blueprint: s.blueprint },
    });
    expect(g2.status).toBe(200);
    expect(g2.body.created).toBe(false);
    expect(JSON.stringify(g2.body.document)).toBe(JSON.stringify(g1.body.document));
    const got = await call(w, "GET", `/compliance/documents/${d.meta.document_id}`, {
      token: auditor.token,
    });
    expect(got.body.verification).toEqual({ ok: true, failed: [] });
    // unrelated audit activity changes the statistics, so the next document is a new version
    const pub = await call(w, "POST", "/blueprints", {
      token: s.owner.token,
      body: { abl: ABL("other-agent", "1.0.0") },
    });
    expect(pub.status, pub.text).toBe(201);
    const g3 = await call(w, "POST", "/compliance/documents", {
      token: builder.token,
      body: { blueprint: s.blueprint },
    });
    expect(g3.status).toBe(201);
    expect(g3.body.document.meta.doc_version).toBe(g1.body.document.meta.doc_version + 1);
    const list = await call(
      w,
      "GET",
      `/compliance/documents?blueprint_name=${s.blueprint.name}&blueprint_version=${s.blueprint.version}`,
      { token: auditor.token },
    );
    expect(list.body.items.length).toBeGreaterThanOrEqual(2);
  });

  it("documents: a registry blueprint is verified again, and its eval history and attestations are read from the hub and registry", async () => {
    const g = await call(w, "POST", "/compliance/documents", {
      token: builder.token,
      body: { blueprint: { name: s.own.name, version: "1.0.0" } },
    });
    expect(g.status, g.text).toBe(201);
    const body = g.body.document.body;
    expect(body.sections.general.data.origin).toBe("registry");
    expect(body.sections.development.data.registry).toMatchObject({
      namespace: s.own.namespace,
      verification_ok: true,
    });
    expect(
      body.sections.lifecycle.data.versions.map((v: { version: string }) => v.version),
    ).toEqual(["1.0.0", "1.1.0"]);
    expect(body.gaps.some((x: { item: string }) => x.item === "registry_provenance")).toBe(false);
  });

  it("an unknown blueprint gives a document made of gaps, not an error", async () => {
    const g = await call(w, "POST", "/compliance/documents", {
      token: builder.token,
      body: { blueprint: { name: "does-not-exist", version: "1.0.0" } },
    });
    expect(g.status).toBe(201);
    expect(
      g.body.document.body.sources.find((x: { name: string }) => x.name === "blueprint").status,
    ).toBe("gap");
    expect(
      g.body.document.body.annex_iv_coverage.filter((c: { status: string }) => c.status === "gap")
        .length,
    ).toBeGreaterThan(5);
  });

  it("a gateway wired without the compliance service answers 503 for every operation (fail-closed)", async () => {
    const bare = await makeWorld({}, { compliance: new UnavailableCompliance() });
    const o = await bare.tenant();
    for (const [m, p, body] of [
      ["GET", "/compliance/systems", undefined],
      ["POST", "/compliance/systems", sys()],
      ["GET", "/compliance/documents", undefined],
      ["POST", "/compliance/documents", { blueprint: { name: "a-b", version: "1.0.0" } }],
    ] as const) {
      const r = await call(bare, m, p, { token: o.token, ...(body ? { body } : {}) });
      expect(r.status, `${m} ${p}`).toBe(503);
    }
    const p = {
      tenantId: "t",
      memberId: "m",
      role: "owner" as const,
      credential: "session" as const,
    };
    const u = new UnavailableCompliance();
    for (const f of [
      u.listSystems,
      u.createSystem,
      u.getSystem,
      u.updateSystem,
      u.listAssessments,
      u.createAssessment,
      u.getAssessment,
      u.reviseAssessment,
      u.submitAssessment,
      u.withdrawAssessment,
      u.reviewAssessment,
      u.generateDocument,
      u.listDocuments,
      u.getDocument,
    ])
      expect(() => (f as (...a: unknown[]) => unknown)(p)).toThrow(PortUnavailable);
    await bare.close();
  });
});

describe("error mapping", () => {
  it("maps every service error to a port error, and leaves other errors alone", () => {
    const of =
      (code: ConstructorParameters<typeof ComplianceError>[0], checks: string[] = []) =>
      () =>
        fromComplianceError(new ComplianceError(code, "m", checks));
    expect(of("not_found")).toThrow(PortNotFound);
    expect(of("forbidden")).toThrow(PortForbidden);
    expect(of("unauthenticated")).toThrow(PortForbidden);
    expect(of("conflict")).toThrow(PortConflict);
    expect(of("invalid", ["/a"])).toThrow(PortInvalid);
    expect(of("invalid")).toThrow(PortInvalid);
    expect(of("unavailable")).toThrow(PortUnavailable);
    expect(() => fromComplianceError(new Error("x"))).toThrow("x");
    expect(new ComplianceAdapter({} as never)).toBeTruthy();
  });
});

describe("document sources", () => {
  it("suiteMatches: a run counts toward a declared range of the same suite only", () => {
    expect(suiteMatches("claims@^1.0.0", "claims@1.4.0")).toBe(true);
    expect(suiteMatches("claims@^1.0.0", "claims@2.0.0")).toBe(false);
    expect(suiteMatches("claims@^1.0.0", "other@1.0.0")).toBe(false);
    expect(suiteMatches("claims", "claims@1.0.0")).toBe(false);
    expect(suiteMatches("claims@1.0.0", "claims")).toBe(false);
    expect(suiteMatches("claims@not a range!!", "claims@1.0.0")).toBe(false);
    expect(suiteMatches("claims@not a range!!", "claims@not a range!!")).toBe(true);
  });

  it("documentation events are the only ones left out of the statistics", () => {
    expect(isDocumentationEvent("compliance.document.generate")).toBe(true);
    expect(isDocumentationEvent("api.generateComplianceDocument")).toBe(true);
    expect(isDocumentationEvent("api.reviewComplianceImpactAssessment")).toBe(true);
    expect(isDocumentationEvent("api.startEvalRun")).toBe(false);
    expect(isDocumentationEvent("lookup-claim")).toBe(false);
    expect(isDocumentationEvent("api.evals.run")).toBe(false);
  });

  const deps = (): ComplianceSourceDeps => ({
    blueprints: w.deps.blueprints,
    registry: w.deps.registry,
    evals: w.deps.evals,
    policies: w.deps.policies,
    auditLog: w.deps.auditLog,
    limitations: { list: () => Promise.resolve({ ok: false, reason: "n/a" }) },
  });
  const actor = () => ({ tenantId: s.owner.tenantId, subject: s.owner.memberId, role: "owner" });

  it("the blueprint source reads the caller's tenant only and reports a failed verification as a gap", async () => {
    const src = new GatewayBlueprintSource(deps());
    expect((await src.get(actor(), s.blueprint)).ok).toBe(true);
    const other = await w.tenant();
    const foreign = await src.get(
      { tenantId: other.tenantId, subject: other.memberId, role: "owner" },
      s.blueprint,
    );
    expect(foreign.ok).toBe(false);
    const broken = new GatewayBlueprintSource({
      ...deps(),
      registry: Object.assign(Object.create(w.deps.registry), {
        resolve: () =>
          Promise.reject(
            new PortInvalid("bad", [
              { path: "/v", message: "m", keyword: "signature" },
              { path: "/v", message: "m" },
            ]),
          ),
      }),
    });
    const r = await broken.get(actor(), { name: s.own.name, version: "1.0.0" });
    expect(r).toEqual({ ok: false, reason: "registry verification failed: failed,signature" });
    const failing = new GatewayBlueprintSource({
      ...deps(),
      registry: Object.assign(Object.create(w.deps.registry), {
        resolve: () => Promise.reject(new Error("boom")),
      }),
    });
    await expect(failing.get(actor(), { name: s.own.name, version: "1.0.0" })).rejects.toThrow(
      "boom",
    );
  });

  it("the eval source returns runs of THIS content hash only, with the gate verdicts of the declared suites", async () => {
    const src = new GatewayEvalSource(deps());
    const r = await src.evidence(actor(), { ...s.blueprint, content_hash: s.evals.contentHash }, [
      { ref: "seed-plain@^1.0.0", threshold: 0.8 },
    ]);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.runs.length).toBeGreaterThan(0);
      expect(r.value.runs.every((x) => x.content_hash === s.evals.contentHash)).toBe(true);
      expect(r.value.runs.some((x) => x.declared_ref === "seed-plain@^1.0.0")).toBe(true);
      expect(r.value.gate.length).toBeGreaterThan(0);
      expect(r.value.attestations).toEqual([]); // a tenant-local blueprint has no registry attestations
    }
    const none = await src.evidence(actor(), { ...s.blueprint, content_hash: "f".repeat(64) }, []);
    expect(none.ok && none.value.runs).toEqual([]);
    expect(none.ok && none.value.gate).toEqual([]);
  });

  it("the policy source lists active packs only", async () => {
    const src = new GatewayPolicySource(deps());
    const before = await src.activePacks(actor());
    expect(before.ok && before.value.map((p) => p.id)).not.toContain("seeded-pack");
    await call(w, "POST", `/policies/${s.policyVersionId}/activate`, { token: s.owner.token });
    const after = await src.activePacks(actor());
    expect(after.ok && after.value.map((p) => p.id)).toContain("seeded-pack");
  });

  it("the audit source counts the tenant's events, skips documentation events and reports chain verification", async () => {
    const src = new GatewayAuditSource(deps());
    const r = await src.statistics(actor());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.chain).toEqual({
      verified: true,
      checked_through_seq: expect.any(Number),
      reason: null,
    });
    const total = await w.audit.read(s.owner.tenantId, {});
    const docs = total.filter((e) => isDocumentationEvent(e.action)).length;
    expect(docs).toBeGreaterThan(0);
    expect(r.value.event_count).toBe(total.length - docs);
    expect(Object.values(r.value.by_decision).reduce((a, b) => a + b, 0)).toBe(r.value.event_count);
    // a window smaller than the chain counts the most recent events only
    const small = await new GatewayAuditSource({ ...deps(), maxAuditEvents: 3 }).statistics(
      actor(),
    );
    expect(small.ok && small.value.window_from_seq).toBeGreaterThan(1);
    // an empty chain
    const fresh = await w.tenant();
    const empty = await src.statistics({
      tenantId: fresh.tenantId,
      subject: fresh.memberId,
      role: "owner",
    });
    expect(empty.ok && empty.value.event_count).toBeGreaterThanOrEqual(0);
    // a broken chain is reported, not hidden
    const broken = new GatewayAuditSource({
      ...deps(),
      auditLog: Object.assign(Object.create(w.deps.auditLog), {
        verify: () => Promise.resolve({ ok: false, brokenAtSeq: 4, reason: "hash_mismatch" }),
      }),
    });
    const b = await broken.statistics(actor());
    expect(b.ok && b.value.chain).toEqual({
      verified: false,
      checked_through_seq: 3,
      reason: "hash_mismatch at seq 4",
    });
    const noEvents = new GatewayAuditSource({
      ...deps(),
      auditLog: Object.assign(Object.create(w.deps.auditLog), { head: () => Promise.resolve(0) }),
    });
    const z = await noEvents.statistics(actor());
    expect(z.ok && z.value).toMatchObject({
      event_count: 0,
      head_seq: 0,
      head_hash: null,
      chain: { verified: true },
    });
  });
});
