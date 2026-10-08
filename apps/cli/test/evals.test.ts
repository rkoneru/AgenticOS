import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { json } from "../../../packages/sdk-ts/test/mock-server.js";
import { EXIT } from "../src/index.js";
import { axis } from "./harness.js";

const HASH = "a".repeat(64);
const RID = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f";
const run = (status: string, extra: Record<string, unknown> = {}) => ({
  id: RID,
  suite: "smoke@1",
  status,
  mode: "ci",
  blueprint: { name: "agent-one", version: "1.0.0", content_hash: HASH },
  ...extra,
});
const calls = async (argv: string[], mock = {}) =>
  (await axis(argv, { mock })).server.calls.map((c) => c.operationId);

describe("axis evals", () => {
  it("run queues a run bound to the blueprint; --wait maps the final status to the exit code", async () => {
    const a = await axis(["evals", "run", "smoke@1", "agent-one@1.0.0", "--mode", "manual"], {
      mock: { overrides: { startEvalRun: () => json(run("queued"), 202) } },
    });
    expect(a.code).toBe(0);
    expect(a.server.calls[0]?.body).toMatchObject({
      suite: "smoke@1",
      mode: "manual",
      blueprint: { name: "agent-one", version: "1.0.0" },
    });
    const passed = await axis(["evals", "run", "smoke@1", "agent-one@1.0.0", "--wait"], {
      mock: {
        overrides: {
          startEvalRun: () => json(run("queued"), 202),
          getEvalRun: () => json(run("passed")),
        },
      },
    });
    expect(passed.code).toBe(0);
    const failed = await axis(["evals", "start", "smoke@1", "agent-one@1.0.0", "--wait"], {
      mock: {
        overrides: {
          startEvalRun: () => json(run("queued"), 202),
          getEvalRun: () => json(run("failed")),
        },
      },
    });
    expect(failed.code).toBe(EXIT.ERROR);
    const slow = await axis(["evals", "wait", RID, "--wait-timeout", "0"], {
      mock: { overrides: { getEvalRun: () => json(run("running")) } },
    });
    expect(slow.code).toBe(EXIT.APPROVAL_PENDING);
    expect((await axis(["evals", "run", "smoke@1"])).code).toBe(EXIT.USAGE);
  });

  it("get, list, compare", async () => {
    const g = await axis(["evals", "get", RID], {
      mock: { overrides: { getEvalRun: () => json(run("passed", { score: 0.9 })) } },
    });
    expect(g.out).toContain("passed");
    const l = await axis(["evals", "list", "--suite", "smoke@1", "--limit", "5"], {
      mock: { overrides: { listEvalRuns: () => json({ items: [run("passed")] }) } },
    });
    expect(l.server.calls[0]?.url.searchParams.get("suite")).toBe("smoke@1");
    expect(l.out).toContain(RID);
    const all = await axis(["evals", "list", "--all", "--json"], {
      mock: { overrides: { listEvalRuns: () => json({ items: [run("passed")] }) } },
    });
    expect(JSON.parse(all.out).items).toHaveLength(1);
    const none = await axis(["evals", "compare", RID], {
      mock: { overrides: { getEvalRunComparison: () => json({}) } },
    });
    expect(none.code).toBe(0);
    expect(none.out).toContain("no baseline");
    const blocked = await axis(["evals", "compare", RID], {
      mock: {
        overrides: {
          getEvalRunComparison: () =>
            json({
              comparison: {
                baseline_run_id: RID,
                comparable: true,
                delta: -0.2,
                tolerance: 0.02,
                regression: true,
                blocking: true,
              },
            }),
        },
      },
    });
    expect(blocked.code).toBe(EXIT.POLICY_DENIED);
  });

  it("gate exits 0 when allowed and 4 with every reason when blocked", async () => {
    const resolve = {
      resolveRegistryBlueprint: () =>
        json({
          namespace: "acme",
          name: "agent-one",
          version: "1.0.0",
          content_hash: HASH,
          abl: {},
        }),
    };
    const allowed = await axis(
      ["evals", "gate", "acme/agent-one@1.0.0", "--suite", "smoke@1:0.8"],
      {
        mock: {
          overrides: {
            ...resolve,
            gateEvalRelease: () => json({ allowed: true, reasons: [], runs: [] }),
          },
        },
      },
    );
    expect(allowed.code).toBe(0);
    expect(allowed.out).toContain("ALLOWED");
    const call = allowed.server.calls.find((c) => c.operationId === "gateEvalRelease");
    expect(call?.body).toMatchObject({
      blueprint: { namespace: "acme", name: "agent-one", content_hash: HASH },
      suites: [{ ref: "smoke@1", threshold: 0.8 }],
    });
    const denied = await axis(["evals", "gate", "acme/agent-one@1.0.0", "--suite", "smoke@1"], {
      mock: {
        overrides: {
          ...resolve,
          gateEvalRelease: () =>
            json({
              allowed: false,
              reasons: [{ code: "missing_run", suite_ref: "smoke@1", message: "no run" }],
              runs: [],
            }),
        },
      },
    });
    expect(denied.code).toBe(EXIT.POLICY_DENIED);
    expect(denied.out).toContain("BLOCKED");
    expect(denied.out).toContain("missing_run");
    expect((await axis(["evals", "gate", "nover"])).code).toBe(EXIT.USAGE);
  });

  it("datasets, suites, baselines, review, sampling and runners call their operations", async () => {
    const dir = mkdtempSync(join(tmpdir(), "axis-evals-"));
    const f = join(dir, "doc.json");
    writeFileSync(f, JSON.stringify({ name: "d", cases: [{ id: "c1", input: "x" }] }));
    const ops = async (argv: string[]) => (await calls(argv)).filter((o) => o !== undefined);
    expect(await ops(["evals", "datasets", "list"])).toEqual(["listEvalDatasets"]);
    expect(await ops(["evals", "datasets", "get", "d", "2"])).toEqual(["getEvalDatasetVersion"]);
    expect(await ops(["evals", "datasets", "create", f])).toEqual(["createEvalDataset"]);
    expect(await ops(["evals", "suites", "list"])).toEqual(["listEvalSuites"]);
    expect(await ops(["evals", "suites", "get", "smoke@1"])).toEqual(["getEvalSuite"]);
    expect(await ops(["evals", "suites", "create", f])).toEqual(["createEvalSuite"]);
    expect(await ops(["evals", "baseline", "list", "agent-one", "smoke@1"])).toEqual([
      "listEvalBaselines",
    ]);
    expect(await ops(["evals", "baseline", "set", RID])).toEqual(["setEvalBaseline"]);
    expect(await ops(["evals", "review", "tasks", "--state", "open"])).toEqual([
      "listEvalReviewTasks",
    ]);
    expect(await ops(["evals", "review", "claim", RID])).toEqual(["claimEvalReviewTask"]);
    expect(
      await ops(["evals", "review", "grade", RID, "--score", "0.5", "--comment", "ok"]),
    ).toEqual(["gradeEvalReviewTask"]);
    expect(await ops(["evals", "review", "skip", RID, "--reason", "conflict"])).toEqual([
      "skipEvalReviewTask",
    ]);
    expect(await ops(["evals", "sampling", "list"])).toEqual(["listEvalSamplingConfigs"]);
    expect(await ops(["evals", "sampling", "summary"])).toEqual(["getEvalOnlineSummary"]);
    expect(await ops(["evals", "runners", "list"])).toEqual(["listEvalRunners"]);
    expect(await ops(["evals", "runners", "register", "runner-1"])).toEqual(["registerEvalRunner"]);
    expect(await ops(["evals", "runners", "revoke", "runner-1"])).toEqual(["revokeEvalRunner"]);
    expect((await axis(["evals", "review", "grade", RID])).code).toBe(EXIT.USAGE);
    expect((await axis(["evals", "datasets", "create", join(dir, "missing.json")])).code).toBe(
      EXIT.ERROR,
    );
  });
});
