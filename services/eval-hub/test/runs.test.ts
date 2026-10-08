import { hashJson } from "@axis/contracts";
import { describe, expect, it } from "vitest";
import { HubError, recordHashOf, verifyStoredRun, type EvalRunDoc } from "../src/index.js";
import {
  HASH_A,
  HASH_B,
  bp,
  caseResults,
  events,
  payloadFor,
  registerRunner,
  runWithScore,
  runnerOf,
  seedSuite,
  user,
  world,
  type World,
} from "./helpers.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof HubError ? `${e.code}:${e.checks.join(",")}` : `error:${String(e)}`;
  }
};

const IDS = ["c1", "c2", "c3", "c4"];
const G = ["exact", "contains"];

async function started(w: World, hash = HASH_A) {
  await seedSuite(w);
  await registerRunner(w);
  return w.hub.runs.startAsRunner(w.runner, { suite_ref: "smoke@1.0.0", blueprint: bp(hash) });
}

/** Submits the honest payload of `results` with `patch` applied (to tamper with it). */
async function submit(
  w: World,
  run: EvalRunDoc,
  patch?: (p: Record<string, unknown>) => void,
  results = caseResults(IDS, G, 1),
  runner = w.runner,
) {
  const payload = await payloadFor(w, run, results, {
    runnerId: (runner as { runnerId: string }).runnerId,
    ...(patch ? { patch } : {}),
  });
  return w.hub.runs.submitResults(runner, run.id, payload);
}

describe("runners", () => {
  it("are registered by an admin, listed, revoked one-way", async () => {
    const w = world();
    await expect(w.hub.runs.registerRunner(w.builder, "r1")).rejects.toThrow(/may not evals.admin/);
    const r = await w.hub.runs.registerRunner(w.admin, "r1", "ci worker");
    expect(r).toMatchObject({ runner_id: "r1", description: "ci worker", revoked_at: null });
    expect(await code(w.hub.runs.registerRunner(w.admin, "r1"))).toBe("conflict:");
    expect(await code(w.hub.runs.registerRunner(w.admin, "bad id"))).toMatch(/^invalid/);
    expect(await code(w.hub.runs.registerRunner(w.admin, "r2", 5))).toMatch(/^invalid/);
    expect(await w.hub.runs.listRunners(w.admin)).toHaveLength(1);
    expect(await w.hub.runs.runnerActive(w.tenant, "r1")).toBe(true);
    const rv = await w.hub.runs.revokeRunner(w.admin, "r1");
    expect(rv.revoked_at).not.toBeNull();
    expect((await w.hub.runs.revokeRunner(w.admin, "r1")).revoked_at).toBe(rv.revoked_at);
    expect(await w.hub.runs.runnerActive(w.tenant, "r1")).toBe(false);
    expect(await code(w.hub.runs.revokeRunner(w.admin, "ghost"))).toBe("not_found:");
    expect(await code(w.hub.runs.revokeRunner(w.builder, "r1"))).toBe("forbidden:");
    expect(await code(w.hub.runs.registerRunner(w.admin, "r1"))).toBe("conflict:");
  });

  it("an unregistered or revoked runner can start, claim and submit nothing", async () => {
    const w = world();
    await seedSuite(w);
    expect(
      await code(w.hub.runs.startAsRunner(w.runner, { suite_ref: "smoke@1.0.0", blueprint: bp() })),
    ).toBe("forbidden:");
    expect(await code(w.hub.runs.claimNext(w.runner))).toBe("forbidden:");
    await registerRunner(w);
    const run = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(),
    });
    const queued = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    await w.hub.runs.revokeRunner(w.admin, "runner-1");
    expect(await code(submit(w, run))).toBe("forbidden:");
    expect(await code(w.hub.runs.claim(w.runner, queued.id))).toBe("forbidden:");
    expect(await code(w.hub.runs.fail(w.runner, run.id, "x"))).toBe("forbidden:");
  });
});

describe("starting and claiming", () => {
  it("a member queues a run, a registered runner claims it exactly once (oldest first)", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    await registerRunner(w, "runner-2");
    const q1 = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_A, "support-agent", "1.0.0", "acme"),
      mode: "manual",
    });
    w.clock.advance(1000);
    const q2 = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    expect(q1).toMatchObject({
      status: "queued",
      runner_id: null,
      requested_by: "bob-builder",
      mode: "manual",
      blueprint_name: "support-agent",
      pass_threshold: 0.8,
    });
    expect(q1.seed).toBeGreaterThanOrEqual(0);
    expect(q1.seed).toBeLessThan(2 ** 31);
    expect(q1.seed).not.toBe(q2.seed);
    expect(q1.blueprint.namespace).toBe("acme");
    expect((await w.hub.runs.list(w.runner, { status: "queued" })).items.map((r) => r.id)).toEqual([
      q2.id,
      q1.id,
    ]);
    const c = await w.hub.runs.claimNext(w.runner);
    expect(c).toMatchObject({ id: q1.id, status: "running", runner_id: "runner-1" });
    expect(await code(w.hub.runs.claim(runnerOf(w.tenant, "runner-2"), q1.id))).toBe("conflict:");
    expect((await w.hub.runs.claimNext(runnerOf(w.tenant, "runner-2")))?.id).toBe(q2.id);
    expect(await w.hub.runs.claimNext(w.runner)).toBeNull();
    expect(await code(w.hub.runs.claim(w.runner, "ghost"))).toBe("not_found:");
  });

  it("validates the request and needs the right credential", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    const req = (o: Record<string, unknown>) =>
      code(
        w.hub.runs.request(w.builder, { suite_ref: "smoke@1.0.0", blueprint: bp(), ...o } as never),
      );
    expect(await req({ suite_ref: "bad" })).toMatch(/^invalid:suite_ref/);
    expect(await req({ suite_ref: "other@1.0.0" })).toMatch(/^invalid:suite_ref/);
    expect(await req({ blueprint: 5 })).toMatch(/^invalid:blueprint/);
    expect(await req({ blueprint: { ...bp(), name: "Bad" } })).toMatch(/blueprint.name/);
    expect(await req({ blueprint: { ...bp(), version: "" } })).toMatch(/blueprint.version/);
    expect(await req({ blueprint: { ...bp(), content_hash: "abc" } })).toMatch(/content_hash/);
    expect(await req({ blueprint: { ...bp(), namespace: "Bad Ns" } })).toMatch(/namespace/);
    expect(await req({ mode: "online" })).toMatch(/^invalid:mode/);
    expect(
      await code(
        w.hub.runs.request(user(w.tenant, "viewer"), { suite_ref: "smoke@1.0.0", blueprint: bp() }),
      ),
    ).toBe("forbidden:");
    expect(
      await code(w.hub.runs.request(w.runner, { suite_ref: "smoke@1.0.0", blueprint: bp() })),
    ).toBe("forbidden:");
    expect(
      await code(
        w.hub.runs.startAsRunner(w.builder, { suite_ref: "smoke@1.0.0", blueprint: bp() }),
      ),
    ).toBe("forbidden:");
    expect(await code(w.hub.runs.claim(w.builder, "x"))).toBe("forbidden:");
    expect(await code(w.hub.runs.claimNext(w.builder))).toBe("forbidden:");
  });
});

describe("submitting results: the hub recomputes from the grades", () => {
  it("stores the hub's own aggregate, seals the record and audits it", async () => {
    const w = world();
    const run = await started(w);
    const done = await submit(w, run);
    expect(done).toMatchObject({
      status: "passed",
      passed: true,
      pending_human: 0,
      sample_size: 4,
      cost: { total_usd: "0.004", tokens: 40 },
    });
    expect(done.scores).toMatchObject({
      status: "complete",
      overall: 1,
      passed: true,
      failures: [],
      ungraded: 0,
      per_grader: { exact: 1, contains: 1 },
    });
    expect(done.provenance).toMatchObject({ runner_version: "1.0.0", seed: run.seed });
    expect(done.record_hash).toBe(recordHashOf(done));
    expect(done.case_results.every((c) => c.score === 1)).toBe(true);
    expect(await w.hub.runs.get(w.admin, run.id)).toEqual(done);
    const fin = await events(w, "evals.run.final");
    expect(fin).toHaveLength(1);
    expect(fin[0]?.outputs_hash).toBe(
      hashJson({
        status: "passed",
        overall: 1,
        record_hash: done.record_hash,
        runner_id: "runner-1",
      }),
    );
    expect(await w.audit.verify(w.tenant)).toMatchObject({ ok: true });
    expect(await code(submit(w, run))).toBe("conflict:");
    expect(verifyStoredRun(done, await w.hub.suites.get(w.admin, "smoke@1.0.0"))).toEqual([]);
  });

  it("a run below the threshold fails; so does one that breaks a suite rule the mean hides", async () => {
    const w = world();
    await started(w);
    expect(await runWithScore(w, { hash: HASH_B, score: 0.5 })).toMatchObject({
      status: "failed",
      passed: false,
    });
    const w2 = world();
    await seedSuite(w2, { suite: { min_case_score: 0.5 }, pass_threshold: 0.5 });
    await registerRunner(w2);
    const r = await runWithScore(w2, { score: (id) => (id === "c1" ? 0 : 1) });
    expect(r).toMatchObject({ status: "failed", passed: false });
    expect(r.scores?.failures).toEqual(["min_case_score:c1"]);
    expect(r.scores?.overall).toBe(0.75);
  });

  it("REJECTS a reported aggregate that does not match the per-case grades; nothing is stored", async () => {
    const w = world();
    const run = await started(w);
    const results = caseResults(IDS, G, 0.5);
    const tamper = (f: (s: Record<string, unknown>) => void) => (p: Record<string, unknown>) =>
      f(p["scores"] as Record<string, unknown>);
    expect(
      await code(
        submit(
          w,
          run,
          tamper((s) => (s["overall"] = 1)),
          results,
        ),
      ),
    ).toBe("integrity_failed:mismatch.overall");
    expect(
      await code(
        submit(
          w,
          run,
          tamper((s) => (s["per_grader"] = { exact: 0.9, contains: 0.5 })),
          results,
        ),
      ),
    ).toBe("integrity_failed:mismatch.per_grader.exact");
    expect(
      await code(
        submit(
          w,
          run,
          tamper((s) => (s["per_case"] = {})),
          results,
        ),
      ),
    ).toMatch(/mismatch.per_case.c1/);
    expect(
      await code(
        submit(
          w,
          run,
          tamper((s) => (s["passed"] = true)),
          results,
        ),
      ),
    ).toMatch(/mismatch.passed/);
    expect(
      await code(
        submit(
          w,
          run,
          tamper((s) => (s["failures"] = [])),
          results,
        ),
      ),
    ).toMatch(/mismatch.failures/);
    expect(
      await code(
        submit(
          w,
          run,
          tamper((s) => (s["ungraded"] = 2)),
          results,
        ),
      ),
    ).toMatch(/mismatch.ungraded/);
    expect(await code(submit(w, run, (p) => (p["scores"] = "1"), results))).toBe(
      "integrity_failed:mismatch.scores",
    );
    expect(
      await code(
        submit(w, run, (p) => ((p["case_results"] as { score: number }[])[0]!.score = 1), results),
      ),
    ).toBe("integrity_failed:mismatch.case_score.c1");
    expect(await code(submit(w, run, (p) => (p["status"] = "pending_human"), results))).toMatch(
      /mismatch.status/,
    );
    expect((await w.hub.runs.get(w.admin, run.id)).status).toBe("running");
    expect((await submit(w, run, undefined, results)).status).toBe("failed");
  });

  it("a grade that is not `scored` counts as 0 and is reported as ungraded", async () => {
    const w = world();
    const run = await started(w);
    const results = caseResults(IDS, G, 1);
    (results[0] as { grades: { status: string }[] }).grades[1]!.status = "ungraded";
    const done = await submit(w, run, undefined, results);
    expect(done.scores).toMatchObject({
      overall: 0.875,
      ungraded: 1,
      per_grader: { exact: 1, contains: 0.75 },
    });
  });

  it("an errored case scores 0 and the run cannot pass", async () => {
    const w = world();
    const run = await started(w);
    const results = caseResults(IDS, G, 1);
    Object.assign(results[3] as object, {
      status: "error",
      error: "infrastructure",
      output: null,
      grades: [],
      trace: null,
    });
    const done = await submit(w, run, undefined, results);
    expect(done.status).toBe("failed");
    expect(done.scores?.failures).toEqual(["below_pass_threshold", "errored_cases:c4"]);
    expect(done.scores?.ungraded).toBe(2);
  });

  it("rejects a payload that is not about this run, runner, suite, blueprint, dataset or seed", async () => {
    const w = world();
    const run = await started(w);
    await registerRunner(w, "runner-2");
    const t = (patch: (p: Record<string, unknown>) => void) => code(submit(w, run, patch));
    expect(await t((p) => (p["runner_id"] = "runner-2"))).toBe("integrity_failed:runner_id");
    expect(await t((p) => (p["run_id"] = "other"))).toBe("integrity_failed:run_id");
    expect(await t((p) => (p["suite_ref"] = "other@1.0.0"))).toBe("integrity_failed:suite_ref");
    expect(
      await t(
        (p) => (p["blueprint"] = { name: "support-agent", version: "1.0.0", content_hash: HASH_B }),
      ),
    ).toBe("integrity_failed:blueprint");
    expect(await t((p) => (p["mode"] = "manual"))).toBe("integrity_failed:mode");
    expect(await t((p) => (p["status"] = "weird"))).toMatch(/^invalid:status/);
    const prov = (k: string, v: unknown) =>
      t((p) => ((p["provenance"] as Record<string, unknown>)[k] = v));
    expect(await prov("blueprint_content_hash", HASH_B)).toBe(
      "integrity_failed:provenance.blueprint_content_hash",
    );
    expect(await prov("dataset_version_hash", HASH_B)).toBe(
      "integrity_failed:provenance.dataset_version_hash",
    );
    expect(await prov("suite_ref", "other@1.0.0")).toBe("integrity_failed:provenance.suite_ref");
    expect(await prov("runner_id", "runner-2")).toBe("integrity_failed:provenance.runner_id");
    expect(await prov("seed", run.seed + 1)).toBe("integrity_failed:provenance.seed");
    expect(await prov("aggregation_version", 2)).toMatch(/^invalid:provenance.aggregation_version/);
    expect(await prov("runner_version", "")).toMatch(/^invalid:provenance.runner_version/);
    expect(await prov("model_ids", "m")).toMatch(/^invalid:provenance.model_ids/);
    expect(await t((p) => (p["provenance"] = 5))).toMatch(/^invalid:provenance/);
    expect(
      await t((p) => ((p["provenance"] as Record<string, unknown>)["x"] = "y".repeat(100_001))),
    ).toMatch(/^invalid:provenance/);
    expect(await code(w.hub.runs.submitResults(w.runner, run.id, 5 as never))).toMatch(/^invalid/);
  });

  it("rejects malformed cost, results and grades", async () => {
    const w = world();
    const run = await started(w);
    const t = (patch: (p: Record<string, unknown>) => void, results = caseResults(IDS, G, 1)) =>
      code(submit(w, run, patch, results));
    const cost = (k: string, v: unknown) =>
      t((p) => ((p["cost"] as Record<string, unknown>)[k] = v));
    expect(await t((p) => (p["cost"] = 5))).toMatch(/^invalid:cost/);
    expect(await cost("total_usd", "0.005")).toBe("integrity_failed:cost.total_usd");
    expect(await cost("agent_usd", "abc")).toMatch(/^invalid:cost.agent_usd/);
    expect(await cost("agent_usd", 0.004)).toMatch(/^invalid:cost.agent_usd/);
    expect(await cost("tokens", -1)).toMatch(/^invalid:cost.tokens/);
    const rs = (f: (r: ReturnType<typeof caseResults>) => unknown) =>
      t((p) => (p["case_results"] = f(p["case_results"] as ReturnType<typeof caseResults>)));
    expect(await rs(() => "x")).toMatch(/^invalid:case_results/);
    expect(await rs((r) => r.slice(0, 3))).toMatch(/^invalid:case_results/);
    expect(await rs((r) => [...r, r[0]])).toMatch(/duplicate|invalid/);
    expect(await rs((r) => [{ ...r[0], case_id: "zzz" }, ...r.slice(1)])).toMatch(
      /case_results\[0\].case_id/,
    );
    expect(await rs((r) => [5, ...r.slice(1)])).toMatch(/case_results\[0\]/);
    const one = (patch: Record<string, unknown>) =>
      rs((r) => [{ ...r[0], ...patch }, ...r.slice(1)]);
    expect(await one({ status: "" })).toMatch(/\.status/);
    expect(await one({ attempts: -1 })).toMatch(/\.attempts/);
    expect(await one({ seed: 1.5 })).toMatch(/\.seed/);
    expect(await one({ error: 5 })).toMatch(/\.error/);
    expect(await one({ score: "x" })).toMatch(/\.score/);
    expect(await one({ output: 5 })).toMatch(/\.output/);
    expect(await one({ trace: [] })).toMatch(/\.trace/);
    expect(await one({ grades: "x" })).toMatch(/\.grades/);
    const grade = (patch: Record<string, unknown>) =>
      one({
        grades: [
          { ...caseResults(["c1"], G, 1)[0]!.grades[0], ...patch },
          caseResults(["c1"], G, 1)[0]!.grades[1],
        ],
      });
    expect(await grade({ grader_id: "ghost" })).toMatch(/grader_id/);
    expect(await grade({ grader_id: "contains" })).toMatch(/grades\[1\]\.grader_id/);
    expect(await grade({ kind: "human" })).toMatch(/\.kind/);
    expect(await grade({ status: "maybe" })).toMatch(/\.status/);
    expect(await grade({ status: "pending" })).toMatch(/grades\[0\]\.status/);
    expect(await grade({ score: "x" })).toMatch(/\.score/);
    expect(await grade({ detail: 5 })).toMatch(/\.detail/);
    expect(await grade({ provenance: [] })).toMatch(/\.provenance/);
    // too many grades for the suite
    expect(
      await one({
        grades: [
          ...caseResults(["c1"], G, 1)[0]!.grades,
          ...caseResults(["c1"], ["x"], 1)[0]!.grades,
        ],
      }),
    ).toMatch(/\.grades/);
    expect(await code(w.hub.runs.submitResults(w.runner, "ghost", {}))).toBe("not_found:");
  });

  it("an out-of-range score is invalid and counts as 0 (the runner's rule)", async () => {
    const w = world();
    const run = await started(w);
    const results = caseResults(IDS, G, 1);
    (results[0] as { grades: { score: number }[] }).grades[0]!.score = 7;
    const done = await submit(w, run, undefined, results);
    expect(done.scores).toMatchObject({ overall: 0.875, ungraded: 1 });
  });

  it("only the owning, active runner of a running run may submit", async () => {
    const w = world();
    const run = await started(w);
    await registerRunner(w, "runner-2");
    const other = runnerOf(w.tenant, "runner-2");
    expect(await code(submit(w, run, undefined, undefined, other))).toBe("forbidden:");
    expect(await code(w.hub.runs.submitResults(w.builder, run.id, {} as never))).toBe("forbidden:");
    const queued = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    expect(await code(submit(w, queued))).toBe("conflict:");
  });

  it("detects a suite or dataset that changed under a run", async () => {
    const w = world();
    const run = await started(w);
    const d = await w.docs.get(w.tenant, "runs", run.id);
    await w.docs.update(w.tenant, "runs", run.id, d?.rev as number, {
      ...(d?.data as object),
      suite_hash: "0".repeat(64),
    });
    expect(await code(submit(w, run))).toBe("integrity_failed:suite_hash");
  });
});

describe("failed runs", () => {
  it("a failed payload (or /fail) ends the run errored: terminal, never a pass", async () => {
    const w = world();
    const run = await started(w);
    const viaPayload = await submit(w, run, (p) => {
      p["status"] = "failed";
      p["reason"] = "refused:blueprint_hash_mismatch";
    });
    expect(viaPayload).toMatchObject({
      status: "errored",
      passed: false,
      failure_reason: "refused:blueprint_hash_mismatch",
    });
    expect(viaPayload.record_hash).toBe(recordHashOf(viaPayload));
    expect(await code(submit(w, run))).toBe("conflict:");
    const run2 = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    await expect(w.hub.runs.fail(w.runner, run2.id, "")).rejects.toThrow(/reason/);
    expect(await w.hub.runs.fail(w.runner, run2.id, "judge model unreachable")).toMatchObject({
      status: "errored",
      failure_reason: "judge model unreachable",
    });
    expect(await code(w.hub.runs.fail(w.runner, run2.id, "again"))).toBe("conflict:");
    expect(await code(w.hub.runs.fail(w.runner, "ghost", "x"))).toBe("not_found:");
    await registerRunner(w, "runner-2");
    const run3 = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    expect(await code(w.hub.runs.fail(runnerOf(w.tenant, "runner-2"), run3.id, "x"))).toBe(
      "forbidden:",
    );
  });
});

describe("a finished run cannot be changed", () => {
  it("the store refuses to update it, and a tampered copy fails verification", async () => {
    const w = world();
    await started(w);
    const done = await runWithScore(w, { hash: HASH_B, score: 0.5 });
    const d = await w.docs.get<EvalRunDoc>(w.tenant, "runs", done.id);
    await expect(
      w.docs.update(w.tenant, "runs", done.id, d?.rev as number, { ...done, status: "passed" }),
    ).rejects.toThrow(/immutable/);
    const suite = await w.hub.suites.get(w.admin, "smoke@1.0.0");
    const clone = (): EvalRunDoc => JSON.parse(JSON.stringify(done));
    const seal = (r: EvalRunDoc): EvalRunDoc => ((r.record_hash = recordHashOf(r)), r);
    const forged = clone();
    (forged.scores as { overall: number }).overall = 0.99;
    expect(verifyStoredRun(forged, suite)).toContain("record_hash");
    seal(forged);
    expect(verifyStoredRun(forged, suite)).toContain("recompute.overall");
    const flipped = clone();
    flipped.status = "passed";
    flipped.passed = true;
    expect(verifyStoredRun(seal(flipped), suite)).toContain("status");
    const noScores = seal({ ...clone(), scores: null });
    expect(verifyStoredRun(noScores, suite)).toContain("scores_missing");
    const grade = clone();
    grade.case_results[0]!.grades[0]!.score = 1;
    expect(verifyStoredRun(seal(grade), suite)).toEqual(
      expect.arrayContaining(["recompute.per_grader.exact"]),
    );
    const pending = clone();
    pending.case_results[0]!.grades[0]!.status = "pending";
    expect(verifyStoredRun(seal(pending), suite)).toContain("recompute.pending");
    const wrongCase = clone();
    wrongCase.case_results[0]!.case_id = "bad id";
    expect(verifyStoredRun(seal(wrongCase), suite)).toContain("recompute");
    const skew = clone();
    skew.case_results[0]!.score = 0.1;
    expect(verifyStoredRun(seal(skew), suite)).toContain("recompute.case_result.c1");
    expect(
      verifyStoredRun(done, { ...suite, suite_hash: "1".repeat(64), dataset_hash: "2".repeat(64) }),
    ).toEqual(expect.arrayContaining(["suite_hash", "dataset_hash"]));
    const hashMismatch = clone();
    hashMismatch.content_hash = HASH_A;
    expect(verifyStoredRun(seal(hashMismatch), suite)).toContain("content_hash");
    const short = clone();
    short.sample_size = 9;
    expect(verifyStoredRun(seal(short), suite)).toContain("sample_size");
    const errored = seal({ ...clone(), status: "errored", scores: null });
    expect(verifyStoredRun(errored, suite)).toEqual([]);
  });
});

describe("listing and tenancy", () => {
  it("lists newest first with filters and cursor paging", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      w.clock.advance(1000);
      ids.push(
        (
          await w.hub.runs.request(w.builder, {
            suite_ref: "smoke@1.0.0",
            blueprint: bp(i % 2 ? HASH_A : HASH_B),
          })
        ).id,
      );
    }
    const p1 = await w.hub.runs.list(w.admin, { limit: 2 });
    expect(p1.items.map((r) => r.id)).toEqual([ids[4], ids[3]]);
    const p2 = await w.hub.runs.list(w.admin, { limit: 2, cursor: p1.next_cursor as string });
    expect(p2.items.map((r) => r.id)).toEqual([ids[2], ids[1]]);
    const p3 = await w.hub.runs.list(w.admin, { limit: 2, cursor: p2.next_cursor as string });
    expect(p3.items.map((r) => r.id)).toEqual([ids[0]]);
    expect(p3.next_cursor).toBeNull();
    expect((await w.hub.runs.list(w.admin, { content_hash: HASH_A })).items).toHaveLength(2);
    expect((await w.hub.runs.list(w.admin, { status: "running" })).items).toHaveLength(0);
    expect(
      (
        await w.hub.runs.list(w.admin, {
          suite_ref: "smoke@1.0.0",
          blueprint_name: "support-agent",
          mode: "ci",
        })
      ).items,
    ).toHaveLength(5);
    expect(await code(w.hub.runs.list(w.admin, { status: 5 as never }))).toMatch(/^invalid/);
    expect(await code(w.hub.runs.list(w.admin, { cursor: "AAAA" }))).toMatch(/^invalid:cursor/);
    expect((await w.hub.runs.list(w.admin, { limit: 0 })).items).toHaveLength(1);
  });

  it("another tenant sees none of it", async () => {
    const w = world();
    const run = await started(w);
    const other = user("00000000-0000-4000-8000-000000000009", "owner");
    expect(await code(w.hub.runs.get(other, run.id))).toBe("not_found:");
    expect((await w.hub.runs.list(other)).items).toEqual([]);
    expect(await code(w.hub.runs.get(user(w.tenant, "viewer"), run.id))).toBe("ok");
    expect(
      await code(
        w.hub.runs.get(
          { kind: "platform", service: "registry", subject: "x", tenantId: w.tenant },
          run.id,
        ),
      ),
    ).toBe("forbidden:");
  });

  it("attestation needs a signing key and a finished run", async () => {
    const w = world();
    const run = await started(w);
    expect(await code(w.hub.runs.attestation(w.admin, run.id))).toBe("conflict:");
  });
});
