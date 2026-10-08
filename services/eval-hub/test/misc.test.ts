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
import { HASH_A, HASH_B, bp, registerRunner, runWithScore, seedSuite, world } from "./helpers.js";

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
