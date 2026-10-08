import { hashJson } from "@axis/contracts";
import { SCORE_EPSILON, aggregate, mismatches } from "./scoring.js";
import type { EvalRunDoc, Suite } from "./types.js";

const plain = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** SHA-256 over the canonical JSON of the run without its own `record_hash`. */
export function recordHashOf(run: EvalRunDoc): string {
  return hashJson({ ...plain(run), record_hash: null });
}

/**
 * Re-verifies a stored FINAL run (the gate and the baseline logic call this every time, so a row edited behind the service is caught):
 * record hash, suite and dataset binding, and the scores recomputed from the case results. Returns the failed checks (empty = intact).
 */
export function verifyStoredRun(run: EvalRunDoc, suite: Suite): string[] {
  const bad: string[] = [];
  if (run.record_hash === null || run.record_hash !== recordHashOf(run)) bad.push("record_hash");
  if (run.suite_hash !== suite.suite_hash) bad.push("suite_hash");
  if (run.dataset_hash !== suite.dataset_hash) bad.push("dataset_hash");
  if (run.content_hash !== run.blueprint.content_hash) bad.push("content_hash");
  if (run.status === "errored") return bad;
  if (run.scores === null) return [...bad, "scores_missing"];
  if (run.case_results.length === 0 || run.sample_size !== run.case_results.length)
    bad.push("sample_size");
  try {
    const scored = run.case_results.map((c) => {
      const scores: Record<string, number> = {};
      for (const [g, v] of Object.entries(c.scores)) {
        if (typeof v !== "number") throw new Error("pending score in a final run");
        scores[g] = v;
      }
      return { case_id: c.case_id, scores };
    });
    const again = aggregate(suite.graders, scored);
    for (const m of mismatches(
      { overall: run.scores.overall, per_grader: run.scores.per_grader },
      again,
    ))
      bad.push(`recompute.${m}`);
    for (const [id, v] of Object.entries(again.per_case))
      if (Math.abs((run.scores.per_case[id] ?? NaN) - v) > SCORE_EPSILON)
        bad.push(`recompute.per_case.${id}`);
    if (Object.keys(run.scores.per_case).length !== Object.keys(again.per_case).length)
      bad.push("recompute.per_case");
    const shouldPass = again.overall >= suite.pass_threshold;
    if (run.passed !== shouldPass || run.status !== (shouldPass ? "passed" : "failed"))
      bad.push("status");
  } catch {
    bad.push("recompute");
  }
  return bad;
}
