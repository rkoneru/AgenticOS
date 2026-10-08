import { describe, expect, it } from "vitest";
import {
  HubError,
  MemoryDocStore,
  buildEvalStatement,
  recordHashOf,
  verifyStoredRun,
  type DocStore,
  type EvalRunDoc,
} from "../src/index.js";
import {
  DET,
  HASH_A,
  HASH_B,
  HUMAN,
  bp,
  caseResults,
  payloadFor,
  registerRunner,
  runWithScore,
  seedSuite,
  user,
  world,
} from "./helpers.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof HubError ? `${e.code}:${e.checks.join(",")}` : `error:${String(e)}`;
  }
};

describe("publisher lookup", () => {
  it("a lookup that fails means the run is not created (fail closed)", async () => {
    const w = world({
      publishers: { publisherOf: () => Promise.reject(new Error("registry down")) },
    });
    await seedSuite(w);
    await registerRunner(w);
    expect(
      await code(w.hub.runs.request(w.builder, { suite_ref: "smoke@1.0.0", blueprint: bp() })),
    ).toBe("unavailable:");
    expect((await w.hub.runs.list(w.admin)).items).toEqual([]);
  });
});

describe("integrity checks of stored runs", () => {
  it("catch an extra per-case row even when the record is re-sealed", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    const run = await runWithScore(w, { score: 1 });
    const suite = await w.hub.suites.get(w.admin, "smoke@1.0.0");
    const forged: EvalRunDoc = JSON.parse(JSON.stringify(run));
    (forged.scores as { per_case: Record<string, number> }).per_case["ghost"] = 1;
    forged.record_hash = recordHashOf(forged);
    expect(verifyStoredRun(forged, suite)).toEqual(["recompute.per_case.ghost"]);
    const skewed: EvalRunDoc = JSON.parse(JSON.stringify(run));
    (skewed.scores as { per_case: Record<string, number> }).per_case["c1"] = 0.1;
    skewed.record_hash = recordHashOf(skewed);
    expect(verifyStoredRun(skewed, suite)).toEqual(["recompute.per_case.c1"]);
  });
});

describe("failures of the store", () => {
  it("unknown store errors surface as errors, never as a silent success", async () => {
    const inner = new MemoryDocStore();
    const broken: DocStore = {
      get: (...a) => inner.get(...a),
      find: (...a) => inner.find(...a),
      update: (...a) => inner.update(...a),
      insert: () => Promise.reject(new Error("disk full")),
    };
    const w = world({ docs: broken });
    await expect(
      w.hub.datasets.create(w.builder, { name: "ds", cases: [{ id: "a", input: 1 }] }),
    ).rejects.toThrow("disk full");
  });

  it("a baseline lookup that fails blocks the gate (baseline_invalid), and baselines need their suite", async () => {
    const inner = new MemoryDocStore();
    let breakBaselines = false;
    const flaky: DocStore = {
      get: (...a) => inner.get(...a),
      insert: (...a) => inner.insert(...a),
      update: (...a) => inner.update(...a),
      find: (t, c, f) =>
        breakBaselines && c === "baselines" ? Promise.reject(new Error("db")) : inner.find(t, c, f),
    };
    const w = world({ docs: flaky });
    await seedSuite(w);
    await registerRunner(w);
    const run = await runWithScore(w, { score: 1 });
    breakBaselines = true;
    const r = await w.hub.gate.check(w.builder, {
      blueprint: bp(),
      suites: [{ ref: "smoke@1.0.0" }],
    });
    expect(r.allowed).toBe(false);
    expect(r.reasons.map((x) => x.code)).toEqual(["baseline_invalid"]);
    breakBaselines = false;
    // a run whose suite disappeared cannot become a baseline or be compared
    const rows = (inner as unknown as { rows: Map<string, unknown> }).rows;
    for (const k of [...rows.keys()]) if (k.includes("\u0000suites\u0000")) rows.delete(k);
    expect(await code(w.hub.baselines.set(w.admin, { run_id: run.id }))).toBe("not_found:");
    expect(await code(w.hub.baselines.compareRun(w.builder, run.id))).toBe("not_found:");
    void HASH_B;
  });
});

describe("attestation statements", () => {
  it("describe failed runs and runs with no namespace", async () => {
    const w = world();
    const suite = await seedSuite(w);
    await registerRunner(w);
    const failed = await runWithScore(w, { score: 0.1 });
    const st = buildEvalStatement(failed, suite);
    expect(st.predicate).toMatchObject({
      status: "failed",
      overall: 0.1,
      suite_ref: "smoke@1.0.0",
    });
    expect(st.subject[0]).toEqual({ name: "-/support-agent@1.0.0", digest: { sha256: HASH_A } });
    const named = await runWithScore(w, { score: 1, hash: HASH_B, namespace: "acme" });
    expect(buildEvalStatement(named, suite).subject[0]?.name).toBe("acme/support-agent@1.0.0");
    expect(buildEvalStatement(named, suite).predicate.status).toBe("passed");
  });
});

describe("ties, logging and null scores", () => {
  it("two runs finished in the same instant: the gate still picks one deterministically, and the log hook sees an evaluation failure", async () => {
    const logs: string[] = [];
    const inner = new MemoryDocStore();
    let boom = false;
    const flaky: DocStore = {
      get: (...a) => inner.get(...a),
      insert: (...a) => inner.insert(...a),
      update: (...a) => inner.update(...a),
      find: (t, c, f) =>
        boom && c === "runs" ? Promise.reject(new Error("db down")) : inner.find(t, c, f),
    };
    const w = world({ docs: flaky, log: (m) => logs.push(m) });
    await seedSuite(w);
    await registerRunner(w);
    const a = await runWithScore(w, { score: 1 });
    const b = await runWithScore(w, { score: 0.1 }); // same millisecond: the clock did not move
    expect(a.finished_at).toBe(b.finished_at);
    const r = await w.hub.gate.check(w.builder, {
      blueprint: bp(),
      suites: [{ ref: "smoke@1.0.0" }],
    });
    const expected = a.id < b.id ? b : a; // the tie goes to the greater id
    expect(r.runs[0]?.run_id).toBe(expected.id);
    boom = true;
    await w.hub.gate.check(w.builder, { blueprint: bp(), suites: [{ ref: "smoke@1.0.0" }] });
    expect(logs).toEqual(["gate evaluation failed"]);
  });

  it("a final case result without a score fails verification", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    const run = await runWithScore(w, { score: 1 });
    const suite = await w.hub.suites.get(w.admin, "smoke@1.0.0");
    const forged: EvalRunDoc = JSON.parse(JSON.stringify(run));
    forged.case_results[0]!.score = null;
    forged.record_hash = recordHashOf(forged);
    expect(verifyStoredRun(forged, suite)).toEqual(["recompute.case_result.c1"]);
  });
});

describe("edges of the run service", () => {
  const rowsOf = (d: MemoryDocStore) => (d as unknown as { rows: Map<string, unknown> }).rows;
  const drop = (d: MemoryDocStore, coll: string) => {
    for (const k of [...rowsOf(d).keys()])
      if (k.includes(`\u0000${coll}\u0000`)) rowsOf(d).delete(k);
  };

  it("runs created in the same instant list in a stable order across pages", async () => {
    const w = world();
    await seedSuite(w);
    const ids = [];
    for (let i = 0; i < 3; i++)
      ids.push(
        (
          await w.hub.runs.request(w.builder, {
            suite_ref: "smoke@1.0.0",
            blueprint: bp(HASH_A, `agent-${i}x`),
          })
        ).id,
      );
    const p1 = await w.hub.runs.list(w.admin, { limit: 2 });
    const p2 = await w.hub.runs.list(w.admin, { limit: 2, cursor: p1.next_cursor as string });
    expect([...p1.items, ...p2.items].map((r) => r.id)).toEqual([...ids].sort().reverse());
  });

  it("a submission needs the suite and the dataset the run was created for", async () => {
    for (const lost of ["suites", "datasets"]) {
      const docs = new MemoryDocStore();
      const w = world({ docs });
      await seedSuite(w);
      await registerRunner(w);
      const run = await w.hub.runs.startAsRunner(w.runner, {
        suite_ref: "smoke@1.0.0",
        blueprint: bp(),
      });
      const payload = await payloadFor(
        w,
        run,
        caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], 1),
      );
      drop(docs, lost);
      expect(await code(w.hub.runs.submitResults(w.runner, run.id, payload))).toBe(
        lost === "suites" ? "not_found:" : "integrity_failed:dataset_hash",
      );
      expect(await code(w.hub.runs.attestation(w.admin, run.id))).toBe("conflict:");
    }
    const docs = new MemoryDocStore();
    const w = world({ docs });
    await seedSuite(w);
    await registerRunner(w);
    const run = await runWithScore(w, { score: 1 });
    drop(docs, "suites");
    expect(await code(w.hub.runs.attestation(w.admin, run.id))).toBe("conflict:"); // no signing key configured
  });

  it("defaults and malformed pieces of a grade", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    const run = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(),
    });
    const results = caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], 1);
    const t = async (f: (r: typeof results) => void) => {
      const p = await payloadFor(w, run, results);
      f(p["case_results"] as typeof results);
      return code(w.hub.runs.submitResults(w.runner, run.id, p));
    };
    expect(await t((r) => r[0]!.grades.splice(0, 1, 5 as never))).toMatch(
      /^invalid:case_results\[0\]\.grades\[0\]/,
    );
    expect(await t((r) => (r[0]!.grades[0]!.grader_id = 5 as never))).toMatch(
      /^invalid:case_results\[0\]\.grades\[0\]\.grader_id/,
    );
    // detail and provenance may be omitted by a lean runner
    const lean = JSON.parse(JSON.stringify(results)) as typeof results;
    for (const r of lean)
      for (const g of r.grades) Object.assign(g, { detail: undefined, provenance: undefined });
    const done = await w.hub.runs.submitResults(w.runner, run.id, {
      ...(await payloadFor(w, run, lean)),
      started_at: "2026-10-08T11:59:59Z",
    });
    expect(done.status).toBe("passed");
    expect(done.started_at).toBe("2026-10-08T11:59:59Z");
    expect(done.case_results[0]!.grades[0]).toMatchObject({ detail: "", provenance: {} });
  });

  it("review tasks: only pending cells, optional parts default, and a resolution for a finished run is ignored", async () => {
    const w = world();
    await seedSuite(w, { graders: [DET, HUMAN], cases: [{ id: "c1", input: "q" }] });
    await registerRunner(w);
    const run = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(),
    });
    const results = caseResults(["c1"], ["exact", "human"], (_i, g) => (g === "human" ? null : 1));
    await w.hub.runs.submitResults(w.runner, run.id, await payloadFor(w, run, results));
    expect(
      await code(
        w.hub.runs.createReviewTasks(w.runner, run.id, {
          tasks: [{ case_id: "c1", grader_id: "exact" }],
        }),
      ),
    ).toMatch(/^invalid:tasks\[0\]/);
    // rubric, output, input and expected may be omitted: the rubric falls back to the grader's own
    expect(
      await w.hub.runs.createReviewTasks(w.runner, run.id, {
        tasks: [{ case_id: "c1", grader_id: "human" }],
      }),
    ).toEqual({ created: 1, existing: 0 });
    const task = (await w.hub.reviews.list(user(w.tenant, "operator", "rita"), {}))[0]!;
    expect(task).toMatchObject({
      rubric: "Is the answer helpful?",
      case_input: null,
      case_output: null,
      case_expected: null,
    });
    await w.hub.runs.humanResolved(w.tenant, "ghost");
    await w.hub.runs.fail(w.runner, run.id, "gave up");
    await w.hub.runs.humanResolved(w.tenant, run.id); // finished: nothing to do
    expect((await w.hub.runs.get(w.admin, run.id)).status).toBe("errored");
  });
});
