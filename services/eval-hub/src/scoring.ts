import { createHash } from "node:crypto";
import type { Comparison, Significance } from "./types.js";

/**
 * Aggregation and comparison. Pure functions; every number the hub stores or gates on comes from here, never from a runner's claim.
 *
 * The aggregation is the runner's (docs/spec/evals-runner.md section 6, pinned by the shared vectors in test/fixtures): one algorithm in
 * Python and TypeScript, plain IEEE-754 doubles, cases visited in ascending id and graders in the suite's declared order, a grade that
 * is not `scored` counting as 0 (never excluded), outputs rounded half-up to 6 decimals.
 */
export const SCORE_EPSILON = 1e-6;
export const SCALE = 1_000_000;
/** Rounds a value to [0, 1] and half-up to 6 decimals: `floor(x * 1e6 + 0.5) / 1e6`. */
export const r6 = (x: number): number => Math.floor(Math.min(1, Math.max(0, x)) * SCALE + 0.5) / SCALE;
export const round9 = (x: number): number => Math.round(x * 1e9) / 1e9;

export class AggregationError extends Error {}

export interface AggGrader {
  id: string;
  weight: number;
  min_mean?: number | null;
}
export interface GradeCell {
  status: string;
  score: unknown;
}
export interface Aggregate {
  status: "complete" | "pending_human";
  overall: number | null;
  per_grader: Record<string, number>;
  per_case: Record<string, number>;
  passed: boolean | null;
  failures: string[];
  ungraded: number;
}

export const CASE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const validScore = (g: GradeCell): number | undefined => {
  if (g.status !== "scored") return undefined;
  const s = g.score;
  return typeof s === "number" && Number.isFinite(s) && s >= 0 && s <= 1 ? s : undefined;
};

export function aggregateGrid(
  graders: readonly AggGrader[],
  grades: Readonly<Record<string, Readonly<Record<string, GradeCell>>>>,
  o: { pass_threshold: number; min_case_score?: number | null; errored?: Iterable<string> },
): Aggregate {
  if (graders.length === 0) throw new AggregationError("a suite needs at least one grader");
  const ids = graders.map((g) => g.id);
  if (new Set(ids).size !== ids.length) throw new AggregationError("duplicate grader id");
  for (const [cid, row] of Object.entries(grades)) {
    if (!CASE_ID_RE.test(cid)) throw new AggregationError("invalid case id");
    for (const gid of Object.keys(row))
      if (!ids.includes(gid)) throw new AggregationError("grade for a grader the suite does not declare");
  }
  const caseIds = Object.keys(grades).sort();
  const errored = [...(o.errored ?? [])];
  if (!errored.every((e) => e in grades)) throw new AggregationError("errored case is not in the results");
  if (Object.values(grades).some((row) => Object.values(row).some((c) => c.status === "pending")))
    return { status: "pending_human", overall: null, per_grader: {}, per_case: {}, passed: null, failures: [], ungraded: 0 };

  let totalWeight = 0;
  for (const g of graders) totalWeight += g.weight;
  let ungraded = 0;
  const perCaseRaw: Record<string, number> = {};
  const sums: Record<string, number> = Object.fromEntries(ids.map((i) => [i, 0]));
  for (const cid of caseIds) {
    let weighted = 0;
    for (const g of graders) {
      const cell = (grades[cid] as Record<string, GradeCell>)[g.id];
      let s = cell === undefined ? undefined : validScore(cell);
      if (s === undefined) {
        ungraded++;
        s = 0;
      }
      weighted += g.weight * s;
      sums[g.id] = (sums[g.id] as number) + s;
    }
    perCaseRaw[cid] = weighted / totalWeight;
  }
  const n = caseIds.length;
  if (n === 0)
    return { status: "complete", overall: 0, per_grader: Object.fromEntries(ids.map((i) => [i, 0])), per_case: {}, passed: false, failures: ["no_cases"], ungraded: 0 };
  const perGraderRaw = Object.fromEntries(ids.map((i) => [i, (sums[i] as number) / n]));
  let overallSum = 0;
  for (const g of graders) overallSum += g.weight * (perGraderRaw[g.id] as number);
  const overall = r6(overallSum / totalWeight);
  const per_grader = Object.fromEntries(ids.map((i) => [i, r6(perGraderRaw[i] as number)]));
  const per_case = Object.fromEntries(caseIds.map((c) => [c, r6(perCaseRaw[c] as number)]));
  const failures: string[] = [];
  if (overall < o.pass_threshold) failures.push("below_pass_threshold");
  if (o.min_case_score !== null && o.min_case_score !== undefined) {
    const low = caseIds.filter((c) => (per_case[c] as number) < (o.min_case_score as number));
    if (low.length > 0) failures.push(`min_case_score:${low.slice(0, 5).join(",")}`);
  }
  for (const g of graders)
    if (g.min_mean !== null && g.min_mean !== undefined && (per_grader[g.id] as number) < g.min_mean)
      failures.push(`grader_min_mean:${g.id}`);
  if (errored.length > 0) failures.push(`errored_cases:${[...errored].sort().slice(0, 5).join(",")}`);
  return { status: "complete", overall, per_grader, per_case, passed: failures.length === 0, failures, ungraded };
}

/** Failed checks when a claimed aggregate disagrees with the recomputed one (empty = consistent). */
export function mismatches(claimed: unknown, computed: Aggregate): string[] {
  if (typeof claimed !== "object" || claimed === null || Array.isArray(claimed)) return ["scores"];
  const c = claimed as Record<string, unknown>;
  const bad: string[] = [];
  const close = (a: unknown, b: number | null): boolean =>
    b === null ? a === null : typeof a === "number" && Number.isFinite(a) && Math.abs(a - b) <= SCORE_EPSILON;
  if (c["status"] !== computed.status) bad.push("status");
  if (!close(c["overall"], computed.overall)) bad.push("overall");
  if (c["passed"] !== computed.passed) bad.push("passed");
  if (c["ungraded"] !== computed.ungraded) bad.push("ungraded");
  if (JSON.stringify(c["failures"]) !== JSON.stringify(computed.failures)) bad.push("failures");
  for (const k of ["per_grader", "per_case"] as const) {
    const mine = computed[k];
    const theirs = c[k];
    if (typeof theirs !== "object" || theirs === null || Array.isArray(theirs)) {
      bad.push(k);
      continue;
    }
    const t = theirs as Record<string, unknown>;
    for (const key of Object.keys(t)) if (!(key in mine)) bad.push(`${k}.${key}`);
    for (const [key, v] of Object.entries(mine)) if (!close(t[key], v)) bad.push(`${k}.${key}`);
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
  scores: { overall: number; per_grader: Record<string, number>; per_case: Record<string, number> };
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
