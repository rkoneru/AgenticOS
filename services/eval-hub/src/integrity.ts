import { hashJson } from "@axis/contracts";
import {
  SCORE_EPSILON,
  aggregateGrid,
  mismatches,
  type Aggregate,
  type GradeCell,
} from "./scoring.js";
import type { CaseResult, EvalRunDoc, Suite } from "./types.js";

const plain = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** SHA-256 over the canonical JSON of the run without its own `record_hash`. */
export function recordHashOf(run: EvalRunDoc): string {
  return hashJson({ ...plain(run), record_hash: null });
}

/** The grid of grades the aggregation reads: `grid[case][grader]`. The LAST grade of a grader for a case wins; none = missing cell. */
export function gridOf(results: readonly CaseResult[]): Record<string, Record<string, GradeCell>> {
  const grid: Record<string, Record<string, GradeCell>> = {};
  for (const r of results) {
    const row: Record<string, GradeCell> = {};
    for (const g of r.grades) row[g.grader_id] = { status: g.status, score: g.score };
    grid[r.case_id] = row;
  }
  return grid;
}

/** Cases whose run never produced a trace (infrastructure failure after retries): scored 0 and the run cannot pass. */
export const erroredCases = (results: readonly CaseResult[]): string[] =>
  results.filter((r) => r.status === "error").map((r) => r.case_id);

/** The hub's own aggregate of a set of case results under a suite. Throws AggregationError on a result set that does not fit the suite. */
export function recompute(results: readonly CaseResult[], suite: Suite): Aggregate {
  return aggregateGrid(suite.graders, gridOf(results), {
    pass_threshold: suite.pass_threshold,
    min_case_score: suite.min_case_score,
    errored: erroredCases(results),
  });
}

/**
 * Re-verifies a stored FINAL run (the gate and the baseline logic call this every time, so a row edited behind the service is caught):
 * record hash, suite and dataset binding, and the scores recomputed from the per-case grades. Returns the failed checks (empty = intact).
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
    const again = recompute(run.case_results, suite);
    if (again.status !== "complete") return [...bad, "recompute.pending"];
    for (const m of mismatches(run.scores, again)) bad.push(`recompute.${m}`);
    for (const r of run.case_results)
      // `!(x <= eps)` so that a missing score (NaN) fails too
      if (
        !(
          Math.abs((r.score ?? Number.NaN) - (again.per_case[r.case_id] ?? Number.NaN)) <=
          SCORE_EPSILON
        )
      )
        bad.push(`recompute.case_result.${r.case_id}`);
    if (run.passed !== again.passed || run.status !== (again.passed ? "passed" : "failed"))
      bad.push("status");
  } catch {
    bad.push("recompute");
  }
  return bad;
}
