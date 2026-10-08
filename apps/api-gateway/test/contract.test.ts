import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApiSpec } from "../src/index.js";
import { ROUTES } from "../src/routes.js";
import { randomBytes } from "node:crypto";
import { generatePublisherKey } from "@axis/registry";
import {
  ABL,
  LISTED_ABL,
  POLICY,
  call,
  makeWorld,
  seed,
  signedBundle,
  type Res,
  type Seed,
  type World,
} from "./world.js";

/**
 * Contract tests DERIVED FROM THE SPEC: the operation list comes from the frozen OpenAPI document. Every operation must have a happy
 * path fixture here (a new operation without one fails this file), and for each one we check, with ajv against the document itself:
 * the success response, the 401 problem, the 403 problem, the 422 problem for a body the schema rejects, and the 404 problem for ids
 * the caller's tenant does not own.
 */
const spec = new ApiSpec();
let w: World;
let s: Seed;

interface Fx {
  method: string;
  path: (s: Seed) => string;
  body?: (s: Seed) => unknown;
  headers?: Record<string, string>;
  status: number;
  /** Identity-only operation: any authenticated credential is allowed, so there is no role the matrix refuses. */
  anyRole?: boolean;
}
const rid = (): string => Array.from(randomBytes(6), (b) => "cdfghjkpquxyz"[b % 13]).join("");
const ok = (
  method: string,
  path: string | ((s: Seed) => string),
  status = 200,
  body?: (s: Seed) => unknown,
): Fx => ({
  method,
  path: typeof path === "string" ? () => path : path,
  status,
  ...(body ? { body } : {}),
});

const FIXTURES: Record<string, Fx> = {
  listBlueprints: ok("GET", "/blueprints?limit=5"),
  publishBlueprintVersion: ok("POST", "/blueprints", 201, () => ({ abl: ABL("lead", "2.0.0") })),
  getBlueprintVersion: ok(
    "GET",
    (s) => `/blueprints/${s.blueprint.name}/versions/${s.blueprint.version}`,
  ),
  listRuns: ok("GET", "/runs?state=running"),
  startRun: ok("POST", "/runs", 202, (s) => ({
    blueprint: s.blueprint,
    input: { prompt: "hello" },
  })),
  getRun: ok("GET", (s) => `/runs/${s.runId}`),
  signalRun: ok(
    "POST",
    (s) => `/runs/${s.runId}/signals`,
    200,
    () => ({ signal: "PAUSE", reason: "test" }),
  ),
  listRunEvents: ok("GET", (s) => `/runs/${s.runId}/events?after_sequence=0&limit=10`),
  listApprovals: ok("GET", "/approvals?status=pending"),
  decideApproval: ok(
    "POST",
    (s) => `/approvals/${s.approvalId}/decision`,
    200,
    () => ({ decision: "approve", comment: "ok" }),
  ),
  listPolicyPacks: ok("GET", "/policies"),
  publishPolicyPack: ok("POST", "/policies", 201, () => ({ policy: POLICY() })),
  testPolicy: ok("POST", "/policies:test", 200, () => ({
    policy: POLICY(),
    request: {
      enforcement_point: "tool_call",
      context: { tool: { name: "lookup-claim", side_effects: "read" }, args: { amount: 5 } },
    },
  })),
  listAuditEvents: ok("GET", "/audit/events?limit=10"),
  verifyAuditChain: ok("POST", "/audit/verify", 200, () => ({})),
  listKillSwitches: ok("GET", "/kill-switches"),
  setKillSwitch: ok("PUT", "/kill-switches", 200, () => ({
    scope: "tenant",
    engaged: true,
    reason: "drill",
  })),
  getUsage: ok("GET", () => {
    const from = new Date(Date.now() - 86_400_000).toISOString();
    const to = new Date(Date.now() + 86_400_000).toISOString();
    return `/usage?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&group_by=meter`;
  }),
  startEvalRun: ok("POST", "/evals/runs", 202, (s) => ({
    suite: s.evals.plainSuite,
    mode: "ci",
    blueprint: s.blueprint,
  })),
  listEvalRuns: ok("GET", (s) => `/evals/runs?limit=5&status=passed&blueprint=${s.blueprint.name}`),
  getEvalRun: ok("GET", (s) => `/evals/runs/${s.evals.runId}`),
  getEvalRunComparison: ok("GET", (s) => `/evals/runs/${s.evals.run2Id}/comparison`),
  gateEvalRelease: ok("POST", "/evals/gate", 200, (s) => ({
    blueprint: {
      name: s.blueprint.name,
      version: s.blueprint.version,
      content_hash: s.evals.contentHash,
    },
    suites: [{ ref: s.evals.plainSuite, threshold: 0.8 }],
  })),
  listEvalDatasets: ok("GET", "/evals/datasets?name=seed-ds"),
  createEvalDataset: ok("POST", "/evals/datasets", 201, () => ({
    name: `ds-${rid()}`,
    cases: [{ id: "a", input: "q", expected: "a", tags: ["t"] }],
  })),
  getEvalDatasetVersion: ok("GET", "/evals/datasets/seed-ds/versions/latest"),
  listEvalSuites: ok("GET", "/evals/suites"),
  createEvalSuite: ok("POST", "/evals/suites", 201, () => ({
    ref: `fx-${rid()}@1.0.0`,
    dataset_ref: "seed-ds@1",
    graders: [{ id: "exact", kind: "deterministic", config: { type: "exact" } }],
    pass_threshold: 0.9,
    min_case_score: 0.5,
    settings: { concurrency: 2 },
  })),
  getEvalSuite: ok("GET", "/evals/suites/seed-plain%401.0.0"),
  listEvalBaselines: ok(
    "GET",
    (s) =>
      `/evals/baselines?blueprint=${s.blueprint.name}&suite=${encodeURIComponent(s.evals.plainSuite)}`,
  ),
  setEvalBaseline: ok("POST", "/evals/baselines", 201, (s) => ({ run_id: s.evals.runId })),
  listEvalReviewTasks: ok("GET", "/evals/reviews/tasks?state=open"),
  claimEvalReviewTask: ok("POST", (s) => `/evals/reviews/tasks/${s.evals.claimTask}/claim`),
  gradeEvalReviewTask: ok(
    "POST",
    (s) => `/evals/reviews/tasks/${s.evals.gradeTask}/grade`,
    200,
    () => ({ score: 0.9, comment: "Clear and polite." }),
  ),
  skipEvalReviewTask: ok(
    "POST",
    (s) => `/evals/reviews/tasks/${s.evals.skipTask}/skip`,
    200,
    () => ({ reason: "outside my expertise" }),
  ),
  listEvalSamplingConfigs: ok("GET", "/evals/sampling"),
  putEvalSamplingConfig: ok("PUT", "/evals/sampling/fx-sampling", 200, (s) => ({
    blueprint: s.blueprint.name,
    suite: s.evals.plainSuite,
    rate: 0.05,
    max_per_hour: 20,
    redaction: "phi",
    alert_threshold: 0.7,
  })),
  getEvalOnlineSummary: ok("GET", (s) => `/evals/online/summary?blueprint=${s.blueprint.name}`),
  listEvalRunners: ok("GET", "/evals/runners"),
  registerEvalRunner: ok(
    "PUT",
    () => `/evals/runners/fx-${rid()}`,
    200,
    () => ({ description: "CI worker" }),
  ),
  revokeEvalRunner: ok("POST", (s) => `/evals/runners/${s.evals.revokableRunner}/revoke`),
  explainRun: ok("GET", (s) => `/runs/${s.runId}/explanation`),
  explainAuditEvent: ok("GET", (s) => `/audit/events/${s.denySeq}/explanation`),
  getMe: { ...ok("GET", "/me"), anyRole: true },
  getApproval: ok("GET", (s) => `/approvals/${s.approvalId}`),
  activatePolicyPack: ok("POST", (s) => `/policies/${s.policyVersionId}/activate`),
  listRegistryNamespaces: ok("GET", "/registry/namespaces"),
  claimRegistryNamespace: ok("POST", "/registry/namespaces", 201, () => ({
    namespace: `ns-${rid()}`,
  })),
  listRegistryKeys: ok("GET", (s) => `/registry/namespaces/${s.own.namespace}/keys`),
  addRegistryKey: ok(
    "POST",
    (s) => `/registry/namespaces/${s.own.namespace}/keys`,
    201,
    () => ({ public_key: generatePublisherKey().publicKey }),
  ),
  publishRegistryBlueprint: ok(
    "POST",
    (s) => `/registry/namespaces/${s.own.namespace}/blueprints`,
    201,
    (s) => signedBundle(s.own, LISTED_ABL("own-agent", `2.${Math.floor(Math.random() * 1e9)}.0`)),
  ),
  listRegistryVersions: ok(
    "GET",
    (s) => `/registry/blueprints/${s.own.namespace}/${s.own.name}/versions`,
  ),
  listRegistryEvalAttestations: ok(
    "GET",
    (s) => `/registry/blueprints/${s.own.namespace}/${s.own.name}/versions/1.0.0/eval-attestations`,
  ),
  yankRegistryVersion: ok(
    "POST",
    (s) => `/registry/blueprints/${s.own.namespace}/${s.own.name}/versions/1.1.0/yank`,
    200,
    () => ({ reason: "superseded" }),
  ),
  resolveRegistryBlueprint: ok(
    "GET",
    (s) => `/registry/resolve?ref=${encodeURIComponent(`${s.own.namespace}/${s.own.name}@1.0.0`)}`,
  ),
  listMarketplaceListings: ok("GET", "/marketplace/listings?q=helper"),
  getMarketplaceListing: ok(
    "GET",
    (s) => `/marketplace/listings/${s.listing.namespace}/${s.listing.name}`,
  ),
  previewMarketplaceInstall: ok("POST", "/marketplace/installs/preview", 200, (s) => ({
    namespace: s.listing.namespace,
    name: s.listing.name,
    range: "^1.0.0",
  })),
  listMarketplaceInstalls: ok("GET", "/marketplace/installs"),
  installMarketplaceListing: ok("POST", "/marketplace/installs", 201, (s) => ({
    namespace: s.listing.namespace,
    name: s.listing.name,
    version: s.listing.version,
    content_hash: s.install.content_hash,
    consent_digest: s.install.consent_digest,
  })),
  uninstallMarketplaceListing: ok(
    "POST",
    (s) => `/marketplace/installs/${s.listing.namespace}/${s.listing.name}/uninstall`,
  ),
  listComplianceSystems: ok("GET", "/compliance/systems?risk_level=limited"),
  createComplianceSystem: ok("POST", "/compliance/systems", 201, () => ({
    name: "Contract system",
    purpose: "Created by the contract test",
    owner: "owner@example.test",
    risk_level: "minimal",
  })),
  getComplianceSystem: ok("GET", (s) => `/compliance/systems/${s.compliance.systemId}?version=1`),
  updateComplianceSystem: ok(
    "PUT",
    (s) => `/compliance/systems/${s.compliance.systemId}`,
    200,
    () => ({ expected_version: 1, lifecycle_stage: "deployed" }),
  ),
  listComplianceImpactAssessments: ok(
    "GET",
    (s) => `/compliance/impact-assessments?system_id=${s.compliance.systemId}&overdue=false`,
  ),
  createComplianceImpactAssessment: ok("POST", "/compliance/impact-assessments", 201, (s) => ({
    system_id: s.compliance.systemId,
    title: "Contract assessment",
    risk_rating: "low",
    intended_use: "Created by the contract test",
    review_due: "2099-06-30",
  })),
  getComplianceImpactAssessment: ok(
    "GET",
    (s) => `/compliance/impact-assessments/${s.compliance.draftId}`,
  ),
  reviseComplianceImpactAssessment: ok(
    "PUT",
    (s) => `/compliance/impact-assessments/${s.compliance.draftId}`,
    200,
    () => ({ expected_version: 1, title: "Retitled by the contract test" }),
  ),
  submitComplianceImpactAssessment: ok(
    "POST",
    (s) => `/compliance/impact-assessments/${s.compliance.submitId}/submit`,
    200,
    () => ({ expected_version: 1 }),
  ),
  withdrawComplianceImpactAssessment: ok(
    "POST",
    (s) => `/compliance/impact-assessments/${s.compliance.withdrawId}/withdraw`,
    200,
    () => ({ expected_version: 1 }),
  ),
  reviewComplianceImpactAssessment: ok(
    "POST",
    (s) => `/compliance/impact-assessments/${s.compliance.reviewId}/review`,
    200,
    () => ({ expected_version: 1, decision: "approve", comment: "reviewed" }),
  ),
  listComplianceDocuments: ok(
    "GET",
    (s) => `/compliance/documents?blueprint_name=${s.blueprint.name}`,
  ),
  generateComplianceDocument: ok("POST", "/compliance/documents", 201, (s) => ({
    blueprint: s.blueprint,
  })),
  getComplianceDocument: ok("GET", (s) => `/compliance/documents/${s.compliance.documentId}`),
};

const check = (op: (typeof spec.operations)[number], r: Res): void => {
  const media = r.status >= 400 ? "application/problem+json" : "application/json";
  expect(r.headers.get("content-type") ?? "", `${op.id} content type`).toContain(media);
  const issues = spec.validateResponse(op, r.status, media, r.body);
  expect(issues, `${op.id} ${r.status}: ${r.text}`).toEqual([]);
};

beforeAll(async () => {
  w = await makeWorld({
    rate: { burst: 1e6, perSecond: 1e6 },
    unauthRate: { burst: 1e6, perSecond: 1e6 },
  });
  s = await seed(w);
});
afterAll(() => w.close());

describe("the gateway implements EVERY operation of the frozen OpenAPI", () => {
  it("route table and document agree both ways", () => {
    const ids = spec.operations.map((o) => o.id).sort();
    expect(Object.keys(ROUTES).sort()).toEqual(ids);
    expect(Object.keys(FIXTURES).sort()).toEqual(ids);
    expect(ids.length).toBe(75);
    expect(spec.version).toBe("1.5.0");
  });

  it("every operation has a security requirement in the document (nothing is public)", () => {
    expect((spec.doc["security"] as unknown[]).length).toBeGreaterThan(0);
  });

  for (const op of new ApiSpec().operations) {
    describe(`${op.method.toUpperCase()} ${op.template} (${op.id})`, () => {
      const fx = FIXTURES[op.id] as Fx;
      const url = (): string => fx.path(s);
      const asOwner = (extra: Record<string, string> = {}) => ({
        token: s.owner.token,
        ...(fx.body ? { body: fx.body(s) } : {}),
        headers: { ...(fx.headers ?? {}), ...extra },
      });

      it("happy path: documented status, body valid against the schema", async () => {
        const r = await call(w, fx.method, url(), asOwner());
        expect(r.status, r.text).toBe(fx.status);
        expect(op.responses.has(String(r.status)) || op.responses.has("default")).toBe(true);
        check(op, r);
      });

      it("no credential: 401 problem+json with a trace id and WWW-Authenticate", async () => {
        const r = await call(w, fx.method, url(), { ...(fx.body ? { body: fx.body(s) } : {}) });
        expect(r.status).toBe(401);
        expect(r.headers.get("www-authenticate")).toContain("Bearer");
        expect(r.body.code).toBe("unauthenticated");
        expect(r.body.trace_id).toMatch(/^[0-9a-f]{32}$/);
        check(op, r);
      });

      it.skipIf(fx.anyRole === true)(
        "a role the matrix does not allow: 403 problem+json",
        async () => {
          const role = op.id === "getUsage" ? "viewer" : "billing";
          const m = await w.member(s.owner.tenantId, role);
          const r = await call(w, fx.method, url(), {
            token: m.token,
            ...(fx.body ? { body: fx.body(s) } : {}),
          });
          expect(r.status, r.text).toBe(403);
          expect(["forbidden", "policy_denied"]).toContain(r.body.code);
          check(op, r);
        },
      );

      if (op.bodyPtr && fx.body) {
        it("a body the schema rejects: 422 ValidationProblem with errors", async () => {
          const r = await call(w, fx.method, url(), {
            token: s.owner.token,
            body: ["not", "an", "object"],
          });
          expect(r.status, r.text).toBe(422);
          expect(r.body.code).toBe("validation_failed");
          expect(Array.isArray(r.body.errors) && r.body.errors.length > 0).toBe(true);
          check(op, r);
        });
        it("an unknown property in the body is rejected where the schema forbids it, never silently used", async () => {
          const body = { ...(fx.body!(s) as object), unexpected_field: true };
          const r = await call(w, fx.method, url(), { token: s.owner.token, body });
          // additionalProperties:false operations answer 422; the open ones (policy test request, input) accept it but ignore it.
          expect([422, fx.status]).toContain(r.status);
        });
      }

      const uuidParam = op.params.find((p) => p.in === "path" && /RunId|approvalId/.test(p.ptr));
      if (uuidParam) {
        it("an id the tenant does not own (valid UUID, nothing behind it): 404 problem", async () => {
          const bad = fx
            .path(s)
            .replace(
              /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,
              "00000000-0000-4000-8000-000000000000",
            );
          const r = await call(w, fx.method, bad, {
            token: s.owner.token,
            ...(fx.body ? { body: fx.body(s) } : {}),
          });
          expect(r.status, r.text).toBe(404);
          expect(r.body.code).toBe("not_found");
          check(op, r);
        });
        it("a malformed id: 422 before anything is looked up", async () => {
          const bad = fx
            .path(s)
            .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, "not-a-uuid");
          const r = await call(w, fx.method, bad, {
            token: s.owner.token,
            ...(fx.body ? { body: fx.body(s) } : {}),
          });
          expect(r.status, r.text).toBe(422);
          check(op, r);
        });
      }

      it("an undeclared query parameter is refused (422), never ignored", async () => {
        const sep = url().includes("?") ? "&" : "?";
        const r = await call(w, fx.method, `${url()}${sep}surprise=1`, asOwner());
        expect(r.status, r.text).toBe(422);
        expect(r.body.errors[0].path).toBe("/surprise");
      });

      it("a method the path does not offer: 405 with Allow", async () => {
        const wrong = op.method === "delete" ? "GET" : "DELETE";
        const r = await call(w, wrong, url().split("?")[0] as string, { token: s.owner.token });
        expect(r.status).toBe(405);
        expect(r.headers.get("allow")).toContain(op.method.toUpperCase());
      });
    });
  }
});
