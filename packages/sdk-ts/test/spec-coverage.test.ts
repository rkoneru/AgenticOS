import { describe, expect, it } from "vitest";
import { Axis, OPERATION_IDS, OPERATIONS, type OperationId } from "../src/index.js";
import { createMockServer, model, sampleParams } from "./mock-server.js";

const mk = () => {
  const server = createMockServer();
  const ax = new Axis({
    apiKey: "axk_test_key_123456",
    baseUrl: server.baseUrl,
    fetch: server.fetch,
    maxRetries: 0,
  });
  return { server, ax };
};

/** Every operationId must be reachable through the ergonomic layer too. A new operation breaks compilation here. */
const ERGONOMIC: Record<OperationId, (ax: Axis) => Promise<unknown>> = {
  listBlueprints: (ax) => ax.blueprints.list(),
  publishBlueprintVersion: (ax) => ax.blueprints.publish({ apiVersion: "abl.axis.dev/v1" }),
  getBlueprintVersion: (ax) => ax.blueprints.get("agent-one", "1.0.0"),
  listRuns: (ax) => ax.runs.list({ state: "running" }),
  startRun: (ax) => ax.runs.start({ blueprint: "agent-one@1.0.0", input: { q: 1 } }),
  getRun: (ax) => ax.runs.get("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  signalRun: (ax) => ax.runs.signal("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f", { signal: "PAUSE" }),
  listRunEvents: (ax) => ax.runs.events("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  listApprovals: (ax) => ax.approvals.list({ status: "pending" }),
  decideApproval: (ax) => ax.approvals.approve("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f", "ok"),
  listPolicyPacks: (ax) => ax.policies.list(),
  publishPolicyPack: (ax) => ax.policies.publish({ policy_version: "1" }),
  testPolicy: (ax) => ax.policies.test({}, { enforcement_point: "tool_call", context: {} }),
  explainRun: (ax) => ax.runs.explain("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  explainAuditEvent: (ax) => ax.audit.explainEvent(7),
  listAuditEvents: (ax) => ax.audit.events({ from_seq: 1 }),
  verifyAuditChain: (ax) => ax.audit.verify({ from_seq: 1, to_seq: 9 }),
  listKillSwitches: (ax) => ax.killSwitches.list(),
  setKillSwitch: (ax) => ax.killSwitches.engage("agent", "agent-one", "drill"),
  getUsage: (ax) =>
    ax.usage.get({ from: "2026-01-01T00:00:00Z", to: "2026-02-01T00:00:00Z", groupBy: "day" }),
  startEvalRun: (ax) => ax.evals.start({ suite: "smoke@1.0.0", blueprint: "agent-one@1.0.0" }),
  listEvalRuns: (ax) => ax.evals.list({ suite: "smoke@1.0.0", status: "passed" }),
  getEvalRun: (ax) => ax.evals.get("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  getEvalRunComparison: (ax) => ax.evals.comparison("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  gateEvalRelease: (ax) =>
    ax.evals.gate({
      blueprint: { name: "agent-one", version: "1.0.0", content_hash: "a".repeat(64) },
      suites: [{ ref: "smoke@1.0.0", threshold: 0.8 }],
    }),
  listEvalDatasets: (ax) => ax.evals.datasets.list({ name: "qa" }),
  createEvalDataset: (ax) =>
    ax.evals.datasets.create({ name: "qa", cases: [{ id: "c1", input: "q", expected: "a" }] }),
  getEvalDatasetVersion: (ax) => ax.evals.datasets.get("qa", 1),
  listEvalSuites: (ax) => ax.evals.suites.list(),
  createEvalSuite: (ax) =>
    ax.evals.suites.create({
      ref: "smoke@1.0.0",
      dataset_ref: "qa@1",
      graders: [{ id: "exact", kind: "deterministic", config: { type: "exact" } }],
      pass_threshold: 0.8,
    }),
  getEvalSuite: (ax) => ax.evals.suites.get("smoke@1.0.0"),
  listEvalBaselines: (ax) => ax.evals.baselines.list("agent-one", "smoke@1.0.0"),
  setEvalBaseline: (ax) => ax.evals.baselines.set("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  listEvalReviewTasks: (ax) => ax.evals.review.tasks({ state: "open" }),
  claimEvalReviewTask: (ax) => ax.evals.review.claim("rt-1"),
  gradeEvalReviewTask: (ax) => ax.evals.review.grade("rt-1", { score: 0.9, comment: "clear" }),
  skipEvalReviewTask: (ax) => ax.evals.review.skip("rt-1", "not my area"),
  listEvalSamplingConfigs: (ax) => ax.evals.sampling.list(),
  putEvalSamplingConfig: (ax) =>
    ax.evals.sampling.put("prod", {
      blueprint: "agent-one",
      suite: "smoke@1.0.0",
      rate: 0.1,
      max_per_hour: 10,
    }),
  getEvalOnlineSummary: (ax) => ax.evals.sampling.summary({ blueprint: "agent-one" }),
  listEvalRunners: (ax) => ax.evals.runners.list(),
  registerEvalRunner: (ax) => ax.evals.runners.register("ci-1", "CI worker"),
  revokeEvalRunner: (ax) => ax.evals.runners.revoke("ci-1"),
  getMe: (ax) => ax.me(),
  getApproval: (ax) => ax.approvals.get("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  activatePolicyPack: (ax) => ax.policies.activate("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"),
  listRegistryNamespaces: (ax) => ax.registry.namespaces(),
  claimRegistryNamespace: (ax) => ax.registry.claim("acme"),
  listRegistryKeys: (ax) => ax.registry.keys("acme"),
  addRegistryKey: (ax) => ax.registry.addKey("acme", "k".repeat(43)),
  publishRegistryBlueprint: (ax) =>
    ax.registry.publish("acme", {
      abl: { apiVersion: "abl.axis.dev/v1" } as never,
      signature: { key_id: "k1", signed_at: "2026-01-01T00:00:00Z", sig: "s" },
      provenance: { payloadType: "t", payload: "p", signatures: [{ keyid: "k1", sig: "s" }] },
    }),
  listRegistryVersions: (ax) => ax.registry.versions("acme", "agent-one"),
  listRegistryEvalAttestations: (ax) => ax.registry.evalAttestations("acme", "agent-one", "1.0.0"),
  yankRegistryVersion: (ax) => ax.registry.yank("acme", "agent-one", "1.0.0", "bad"),
  resolveRegistryBlueprint: (ax) => ax.registry.resolve("acme/agent-one@^1"),
  listMarketplaceListings: (ax) => ax.marketplace.listings({ q: "x" }),
  getMarketplaceListing: (ax) => ax.marketplace.listing("acme", "agent-one"),
  previewMarketplaceInstall: (ax) => ax.marketplace.preview("acme", "agent-one", "^1"),
  listMarketplaceInstalls: (ax) => ax.marketplace.installs(),
  installMarketplaceListing: (ax) =>
    ax.marketplace.install({
      namespace: "acme",
      name: "agent-one",
      version: "1.0.0",
      contentHash: "a".repeat(64),
      consentDigest: "d",
    }),
  uninstallMarketplaceListing: (ax) => ax.marketplace.uninstall("acme", "agent-one"),
};

describe("coverage of the spec", () => {
  it("the generated operation table equals the spec's operationIds", () => {
    expect([...OPERATION_IDS].sort()).toEqual(model.operations.map((o) => o.operationId).sort());
    expect(OPERATION_IDS.length).toBeGreaterThanOrEqual(19);
  });

  it.each(OPERATION_IDS)(
    "generated method %s sends a spec-valid request and gets a spec-valid response",
    async (id) => {
      const { server, ax } = mk();
      const method = (ax.api as unknown as Record<string, (p: unknown) => Promise<unknown>>)[
        id
      ] as (p: unknown) => Promise<unknown>;
      const out = await method.call(ax.api, sampleParams(id));
      expect(server.violations).toEqual([]);
      expect(server.calls.map((c) => c.operationId)).toEqual([id]);
      expect(OPERATIONS[id].method).toBe(server.calls[0]?.method);
      expect(out).toBeDefined();
    },
  );

  it.each(OPERATION_IDS)("ergonomic layer reaches %s", async (id) => {
    const { server, ax } = mk();
    await ERGONOMIC[id](ax);
    // the ablDocument placeholders are opaque to the mock; every other request must be valid
    expect(server.violations).toEqual([]);
    expect(server.calls.map((c) => c.operationId)).toEqual([id]);
  });

  it("mutating requests carry an auto-generated Idempotency-Key where the spec allows one", async () => {
    const { server, ax } = mk();
    await ax.runs.start({ blueprint: "a-b@1" });
    const key = server.calls[0]?.headers.get("idempotency-key");
    expect(key).toMatch(/^[0-9a-f-]{36}$/);
    await ax.runs.start({ blueprint: "a-b@1", idempotencyKey: "my-own-key-1" });
    expect(server.calls[1]?.headers.get("idempotency-key")).toBe("my-own-key-1");
  });
});
