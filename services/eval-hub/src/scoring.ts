import { createHash } from "node:crypto";
import type { Comparison, Grader, RunScores, Significance } from "./types.js";

/**
 * Aggregation and comparison. Pure functions; every number the hub stores or gates on comes from here, never from a runner's claim.
 *
 * Aggregation rules (docs/spec/eval-hub.md):
 *   case_score(c)   = sum_g w_g * s(c,g) / sum_g w_g          over EVERY grader of the suite
 *   per_grader(g)   = mean_c s(c,g)
 *   overall         = mean_c case_score(c)
 * Cases are summed in case-id order and graders in grader-id order, so the result does not depend on the order a runner listed them.
 * Results are rounded to 9 decimals (stable canonical JSON).
 */
export const SCORE_EPSILON = 1e-6;
export const round9 = (x: number): number => Math.round(x * 1e9) / 1e9;

const byId = <T extends { id: string }>(a: T, b: T): number =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

export interface ScoredCase {
  case_id: string;
  scores: Record<string, number>;
}

/** Throws when a case lacks a grader's score (callers validate completeness first; this keeps the arithmetic honest). */
export function aggregate(
  graders: readonly Pick<Grader, "id" | "weight">[],
  cases: readonly ScoredCase[],
): RunScores {
  const gs = [...graders].sort(byId);
  const cs = [...cases].sort((a, b) =>
    a.case_id < b.case_id ? -1 : a.case_id > b.case_id ? 1 : 0,
  );
  if (gs.length === 0 || cs.length === 0) throw new Error("aggregate: no graders or no cases");
  const wsum = gs.reduce((s, g) => s + g.weight, 0);
  const per_case: Record<string, number> = {};
  const gsum: Record<string, number> = Object.fromEntries(gs.map((g) => [g.id, 0]));
  let total = 0;
  for (const c of cs) {
    let weighted = 0;
    for (const g of gs) {
      const s = c.scores[g.id];
      if (typeof s !== "number" || !Number.isFinite(s))
        throw new Error(`aggregate: case ${c.case_id} has no score for ${g.id}`);
      weighted += g.weight * s;
      gsum[g.id] = (gsum[g.id] as number) + s;
    }
    const cscore = round9(weighted / wsum);
    per_case[c.case_id] = cscore;
    total += cscore;
  }
  const per_grader: Record<string, number> = {};
  for (const g of gs) per_grader[g.id] = round9((gsum[g.id] as number) / cs.length);
  return { overall: round9(total / cs.length), per_grader, per_case };
}

/** Failed checks when a claimed aggregate disagrees with the recomputed one (empty = consistent). */
export function mismatches(
  claimed: { overall?: unknown; per_grader?: unknown },
  computed: RunScores,
): string[] {
  const bad: string[] = [];
  const close = (a: unknown, b: number): boolean =>
    typeof a === "number" && Number.isFinite(a) && Math.abs(a - b) <= SCORE_EPSILON;
  if (!close(claimed.overall, computed.overall)) bad.push("overall");
  if (claimed.per_grader !== undefined) {
    const pg = claimed.per_grader;
    if (typeof pg !== "object" || pg === null || Array.isArray(pg)) bad.push("per_grader");
    else {
      const m = pg as Record<string, unknown>;
      for (const k of Object.keys(m)) if (!(k in computed.per_grader)) bad.push(`per_grader.${k}`);
      for (const [k, v] of Object.entries(computed.per_grader))
        if (!close(m[k], v)) bad.push(`per_grader.${k}`);
    }
  }
  return bad;
}

// ---------------------------------------------------------------- paired significance

export const EXACT_MAX_N = 16;
export const MONTE_CARLO_ROUNDS = 20_000;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Paired sign-flip randomization test on per-case score differences (two-sided). Under the null hypothesis that candidate and baseline
 * are exchangeable, each non-zero difference is equally likely to carry either sign. n <= 16 non-zero pairs: ALL 2^n sign patterns are
 * enumerated (exact p-value). More: 20 000 flips from a PRNG seeded by `seedText` (so the result is reproducible), p = (k+1)/(N+1).
 * Differences are compared in integer micro-units, so there is no floating point drift.
 */
export function pairedSignFlip(
  diffs: readonly number[],
  alpha: number,
  seedText: string,
): Significance {
  const d = diffs.map((x) => Math.round(x * 1e6)).filter((x) => x !== 0);
  const n = diffs.length;
  const mean = n === 0 ? 0 : diffs.reduce((s, x) => s + x, 0) / n;
  if (d.length === 0)
    return {
      test: "paired_sign_flip",
      method: "degenerate",
      n,
      mean_diff: round9(mean),
      p_value: 1,
      alpha,
      significant: false,
    };
  const obs = Math.abs(d.reduce((s, x) => s + x, 0));
  let p: number;
  let method: Significance["method"];
  if (d.length <= EXACT_MAX_N) {
    method = "exact";
    let ge = 0;
    const total = 1 << d.length;
    for (let mask = 0; mask < total; mask++) {
      let s = 0;
      for (let i = 0; i < d.length; i++)
        s += (mask >> i) & 1 ? (d[i] as number) : -(d[i] as number);
      if (Math.abs(s) >= obs) ge++;
    }
    p = ge / total;
  } else {
    method = "monte_carlo";
    const seed = parseInt(createHash("sha256").update(seedText).digest("hex").slice(0, 8), 16);
    const rnd = mulberry32(seed);
    let ge = 0;
    for (let r = 0; r < MONTE_CARLO_ROUNDS; r++) {
      let s = 0;
      for (const x of d) s += rnd() < 0.5 ? x : -x;
      if (Math.abs(s) >= obs) ge++;
    }
    p = (ge + 1) / (MONTE_CARLO_ROUNDS + 1);
  }
  return {
    test: "paired_sign_flip",
    method,
    n,
    mean_diff: round9(mean),
    p_value: round9(p),
    alpha,
    significant: p < alpha,
  };
}

export interface ComparedRun {
  id: string;
  record_hash: string;
  suite_hash: string;
  dataset_hash: string;
  scores: RunScores;
}

/**
 * Candidate vs baseline. A regression is a drop of the overall score LARGER than `tolerance` (a drop of exactly the tolerance is not a
 * regression). It BLOCKS when `requiresSignificance` is false, or when the paired test finds the drop significant. Runs of another
 * suite or dataset version are not comparable (the gate treats that as a failure, never as a pass).
 */
export function compareRuns(
  cand: ComparedRun,
  base: ComparedRun,
  o: { tolerance: number; alpha: number; requiresSignificance: boolean },
): Comparison {
  const empty: Comparison = {
    comparable: false,
    baseline_run_id: base.id,
    delta: null,
    per_grader_delta: {},
    tolerance: o.tolerance,
    regression: false,
    blocking: false,
    significance: null,
  };
  if (cand.suite_hash !== base.suite_hash || cand.dataset_hash !== base.dataset_hash) return empty;
  const ids = Object.keys(cand.scores.per_case).sort();
  const bids = Object.keys(base.scores.per_case).sort();
  if (ids.length === 0 || ids.join("\u0000") !== bids.join("\u0000")) return empty;
  const delta = round9(cand.scores.overall - base.scores.overall);
  const per_grader_delta: Record<string, number> = {};
  for (const [g, v] of Object.entries(cand.scores.per_grader)) {
    const b = base.scores.per_grader[g];
    if (b !== undefined) per_grader_delta[g] = round9(v - b);
  }
  const diffs = ids.map(
    (id) => (cand.scores.per_case[id] as number) - (base.scores.per_case[id] as number),
  );
  const significance = pairedSignFlip(diffs, o.alpha, `${cand.record_hash}:${base.record_hash}`);
  // 1e-9 absorbs the 9-decimal rounding: "exactly the tolerance" is not a regression.
  const regression = delta < -o.tolerance - 1e-9;
  return {
    comparable: true,
    baseline_run_id: base.id,
    delta,
    per_grader_delta,
    tolerance: o.tolerance,
    regression,
    blocking: regression && (!o.requiresSignificance || significance.significant),
    significance,
  };
}
