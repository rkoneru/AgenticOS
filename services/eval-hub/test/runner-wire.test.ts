/* eslint-disable @typescript-eslint/no-explicit-any -- the runner fixture is untyped JSON */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadWire } from "./wire.js";
import { queuedRunWire } from "../src/index.js";
import { registerRunner, world } from "./helpers.js";

/**
 * The runner's own pinned wire examples (copied from runtime/tests/fixtures/eval-hub-wire-examples.json of branch p8/runner). The hub
 * must accept what the runner sends, and answer in the shapes the runner's strict parsers (`Suite.from_wire`, `Dataset.from_wire`,
 * `QueuedRun.from_wire`, `OnlineConfig.from_wire`) read.
 */
const fx = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/eval-hub-wire-examples.json", import.meta.url)),
    "utf8",
  ),
) as Record<string, any>;
const keys = (o: object): string[] => Object.keys(o).sort();

describe("the hub speaks the runner's wire", () => {
  const wire = loadWire();
  const ex = (name: string) =>
    wire.examples.find((e) => e.name === name) as {
      request: Record<string, any>;
      response: Record<string, any>;
    };

  it("the request bodies of wire-v1.json have exactly the keys the runner sends", () => {
    const results = ex("runner_submits_results").request;
    expect(keys(results)).toEqual(fx.results_request.body_keys);
    expect(keys(results["scores"])).toEqual(fx.results_request.scores_keys);
    expect(keys(results["case_results"][0])).toEqual(fx.results_request.case_result_keys);
    expect(keys(results["case_results"][0]["grades"][0])).toEqual(fx.results_request.grade_keys);
    expect(keys(results["cost"])).toEqual(fx.results_request.cost_keys);
    expect(keys(results["provenance"])).toEqual(fx.results_request.provenance_keys);
    expect(keys(ex("integrity_failed_for_a_claimed_aggregate").request)).toEqual(
      fx.results_request.body_keys,
    );
    expect(keys(ex("runner_reports_a_refused_run").request)).toEqual(fx.failed_request.body_keys);
    const tasks = ex("runner_posts_review_tasks").request;
    expect(keys(tasks)).toEqual(fx.review_tasks_request.body_keys);
    expect(keys(tasks["tasks"][0])).toEqual(fx.review_tasks_request.task_keys);
    expect(keys(ex("online_result").request)).toEqual(fx.online_result_keys);
    expect(keys(ex("runner_reads_online_configs").response["configs"][0])).toEqual(
      keys(fx.online_configs_response.configs[0]),
    );
    expect(keys(ex("runner_claims_next_run").response["run"])).toEqual(
      keys(fx.claim_response.run).filter((k) => k !== "seed" || true),
    );
    expect(keys(ex("runner_claims_next_run").request)).toEqual(keys(fx.claim_request.body));
  });

  it("serves the runner's own suite and dataset and the claim in the shapes its parsers require", async () => {
    const w = world();
    await w.hub.datasets.create(w.builder, { name: "refund-cases", cases: fx.dataset.cases });
    // the runner's suite, verbatim (graders: kind + config; settings; min_case_score absent)
    const suite = await w.hub.suites.create(w.builder, {
      ...fx.suite,
      ref: fx.suite.ref,
      dataset_ref: "refund-cases@1",
    });
    for (const k of [
      "ref",
      "dataset_ref",
      "graders",
      "pass_threshold",
      "tolerance",
      "required_for_release",
      "min_case_score",
      "settings",
    ])
      expect(suite).toHaveProperty(k);
    expect(suite.graders[0]).toMatchObject({
      id: "exact",
      kind: "deterministic",
      weight: 2,
      config: { type: "contains", values: ["$5"] },
      min_mean: null,
    });
    expect(suite.graders[1]).toMatchObject({ kind: "model", min_mean: 0.5 });
    expect(suite.settings).toEqual(fx.suite.settings);
    const ds = await w.hub.datasets.get(w.admin, "refund-cases@1");
    expect(ds.version_hash).toBe(fx.dataset.version_hash);
    expect(ds.ref).toBe("refund-cases@1"); // the hub numbers versions itself (the runner fixture says @3)
    expect(typeof ds.phi).toBe("boolean");
    for (const c of ds.cases)
      expect(keys(c)).toEqual(["expected", "id", "input", "metadata", "tags"]);
    await registerRunner(w);
    const run = await w.hub.runs.request(w.builder, {
      suite_ref: fx.suite.ref,
      blueprint: { ...fx.claim_response.run.blueprint },
    });
    const claimed = await w.hub.runs.claimNext(w.runner);
    expect(claimed?.id).toBe(run.id);
    const q = queuedRunWire(claimed as never, w.tenant);
    expect(keys(q)).toEqual(keys(fx.claim_response.run));
    expect(q).toMatchObject({
      tenant_id: w.tenant,
      suite_ref: fx.suite.ref,
      mode: "ci",
      blueprint: { name: "claims-triage", version: "1.0.0" },
    });
    expect(Number.isInteger(q.seed) && q.seed >= 0 && q.seed < 2 ** 31).toBe(true);
  });
});
