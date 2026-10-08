import type { Role } from "@axis/control-plane";

export const NAME_RE = /^[a-z][a-z0-9-]{1,62}$/;
/** A stored suite: `[namespace/]name@major.minor.patch`. */
export const SUITE_REF_RE =
  /^((?:[a-z][a-z0-9-]{1,62}\/)?[a-z][a-z0-9-]{1,62})@(\d{1,9}\.\d{1,9}\.\d{1,9})$/;
/** What a blueprint's `spec.evals.suites[].ref` may say: `[namespace/]name@<version or semver range>`. The gate resolves ranges. */
export const GATE_REF_RE = /^((?:[a-z][a-z0-9-]{1,62}\/)?[a-z][a-z0-9-]{1,62})@(.{1,60})$/;
export const DATASET_REF_RE = /^([a-z][a-z0-9-]{1,62})@([1-9][0-9]{0,8})$/;
/** Case, grader, run and task ids: ASCII only, so "sorted by id" means the same thing in every language. */
export const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const GRADER_ID_RE = ID_RE;
export const HASH_RE = /^[0-9a-f]{64}$/;

export type HubRole = Role | "reviewer";

/** Who is calling. The tenant always comes from the credential, never from a request body. */
export type HubPrincipal = TenantActor | RunnerActor | PlatformActor;
export interface TenantActor {
  kind: "tenant";
  tenantId: string;
  subject: string;
  role: HubRole;
}
/** An eval runner (CI worker, scheduled job). Only a runner registered for the tenant is accepted. */
export interface RunnerActor {
  kind: "runner";
  tenantId: string;
  runnerId: string;
}
/** The registry / marketplace calling the gate on behalf of the owner tenant. Never producible from an HTTP credential. */
export interface PlatformActor {
  kind: "platform";
  service: "registry" | "marketplace";
  subject: string;
  tenantId: string;
}

// ---------------------------------------------------------------- datasets and suites

export interface EvalCase {
  id: string;
  input: unknown;
  /** `null` when the case has no expected answer (the wire shape always carries the key). */
  expected: unknown;
  tags: string[];
  metadata: Record<string, unknown>;
}

export interface DatasetVersion {
  name: string;
  version: number;
  ref: string;
  description: string | null;
  phi: boolean;
  /** True when PHI redaction ran before the cases were persisted. */
  redacted: boolean;
  case_count: number;
  /**
   * SHA-256 of the canonical (sorted keys, compact, ASCII-escaped) JSON of the cases AS STORED (after redaction), sorted by id: the
   * runner recomputes it and refuses a dataset that does not match. Same value as `version_hash`.
   */
  content_hash: string;
  version_hash: string;
  cases: EvalCase[];
  created_at: string;
  created_by: string;
}

/** `config.type` of a deterministic grader (docs/spec/evals-runner.md section 4). */
export const DETERMINISTIC_TYPES = [
  "exact",
  "contains",
  "not_contains",
  "regex",
  "json_schema",
  "numeric_tolerance",
  "tool_sequence",
  "tool_subsequence",
  "policy_decision",
  "budget",
] as const;
export type GraderKind = "deterministic" | "model" | "human";
export const GRADER_KINDS: readonly GraderKind[] = ["deterministic", "model", "human"];

/** A suite grader as the runner speaks it: `{id, kind, weight, config, min_mean?}`. */
export interface Grader {
  id: string;
  kind: GraderKind;
  weight: number;
  config: Record<string, unknown>;
  min_mean: number | null;
}

export interface Suite {
  ref: string;
  name: string;
  version: string;
  dataset_ref: string;
  dataset_hash: string;
  graders: Grader[];
  /** Overall score a run needs to be `passed` (and the floor of the release threshold). */
  pass_threshold: number;
  /** When set, any case scoring below it fails the run. */
  min_case_score: number | null;
  /** Runner settings (concurrency, case timeout, allow_sandboxed_targets, budgets). Opaque to the hub. */
  settings: Record<string, unknown>;
  /** A score drop vs the baseline larger than this is a regression. */
  tolerance: number;
  required_for_release: boolean;
  /** Blueprint names for which the gate adds this suite when `required_for_release`. */
  applies_to: string[];
  min_samples: number | null;
  max_age_days: number;
  regression_requires_significance: boolean;
  alpha: number;
  suite_hash: string;
  created_at: string;
  created_by: string;
}

// ---------------------------------------------------------------- runs

export type RunStatus = "queued" | "running" | "passed" | "failed" | "errored";
export const FINAL: readonly RunStatus[] = ["passed", "failed", "errored"];
export type RunMode = "ci" | "manual";

export interface BlueprintRef {
  namespace: string | null;
  name: string;
  version: string;
  content_hash: string;
}

export interface GradeRecord {
  grader_id: string;
  kind: GraderKind;
  /** scored | ungraded | pending | error: only `scored` counts, everything else aggregates as 0 (a pending human grade holds the run). */
  status: string;
  score: number;
  detail: string;
  provenance: Record<string, unknown>;
}

/** One case of a run as the runner reports it (per-case grades are the evidence the hub recomputes from). */
export interface CaseResult {
  case_id: string;
  status: string;
  attempts: number;
  seed: number;
  error: string | null;
  score: number | null;
  output: string | null;
  grades: GradeRecord[];
  trace: Record<string, unknown> | null;
}

/** The aggregate, stored exactly as the hub recomputed it. */
export interface RunScores {
  status: "complete" | "pending_human";
  overall: number | null;
  per_grader: Record<string, number>;
  per_case: Record<string, number>;
  passed: boolean | null;
  failures: string[];
  ungraded: number;
}

export interface RunCost {
  agent_usd: string;
  judge_usd: string;
  total_usd: string;
  tokens: number;
  judge_tokens: number;
}

export interface EvalRunDoc {
  id: string;
  suite_ref: string;
  suite_hash: string;
  dataset_ref: string;
  dataset_hash: string;
  /** Snapshot of the suite's pass_threshold when the run was created (the suite is immutable). */
  pass_threshold: number;
  blueprint: BlueprintRef;
  /** Copies of `blueprint.name` and `blueprint.content_hash` (indexed). */
  blueprint_name: string;
  content_hash: string;
  mode: RunMode;
  /** Seed handed to the runner (every model call of every case derives its seed from it). */
  seed: number;
  status: RunStatus;
  requested_by: string;
  /** Who published the blueprint version (ineligible as a human reviewer). Supplied by a trusted caller or the registry. */
  publisher: string | null;
  runner_id: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  scores: RunScores | null;
  case_results: CaseResult[];
  sample_size: number;
  cost: RunCost;
  /** As reported by the runner (validated against the run: blueprint hash, dataset hash, suite, runner id). */
  provenance: Record<string, unknown> | null;
  pending_human: number;
  passed: boolean | null;
  failure_reason: string | null;
  /** SHA-256 over this record (without this field), set when the run becomes final. */
  record_hash: string | null;
}

// ---------------------------------------------------------------- baselines, comparison

export interface Significance {
  test: "paired_sign_flip";
  method: "exact" | "monte_carlo" | "degenerate";
  n: number;
  mean_diff: number;
  p_value: number;
  alpha: number;
  significant: boolean;
}

export interface Comparison {
  comparable: boolean;
  baseline_run_id: string;
  delta: number | null;
  per_grader_delta: Record<string, number>;
  tolerance: number;
  regression: boolean;
  /** Regression that blocks a release under the suite's rule. */
  blocking: boolean;
  significance: Significance | null;
}

export interface BaselineDoc {
  blueprint_name: string;
  suite_ref: string;
  seq: number;
  run_id: string;
  overall: number;
  record_hash: string;
  set_by: string;
  at: string;
}

// ---------------------------------------------------------------- human review

export type TaskState = "open" | "claimed" | "needs_adjudication" | "resolved";

export interface ReviewGrade {
  reviewer: string;
  score: number;
  comment: string;
  at: string;
  /** True for the third, deciding grade. */
  adjudication: boolean;
}

export interface ReviewTaskDoc {
  id: string;
  run_id: string;
  suite_ref: string;
  case_id: string;
  grader_id: string;
  rubric: string;
  blueprint: BlueprintRef;
  /** What the reviewer sees, already redacted by the runner. */
  case_input: unknown;
  case_output: string | null;
  case_expected: unknown;
  state: TaskState;
  created_at: string;
  sla_deadline: string;
  double_grade: boolean;
  agreement_tolerance: number;
  /** Subjects that may never grade this task (starter, publisher). */
  conflicts: string[];
  claimed_by: string | null;
  claim_expires_at: string | null;
  skipped_by: string[];
  grades: ReviewGrade[];
  resolution: { score: number; method: "single" | "agreed" | "adjudicated" } | null;
  resolved_at: string | null;
  sla_breached_at: string | null;
}

// ---------------------------------------------------------------- online sampling

export interface SamplingConfig {
  id: string;
  blueprint_name: string;
  suite_ref: string;
  /** 0..1 fraction of production runs the sampler grades. */
  rate: number;
  max_per_hour: number;
  /** phi: redact when the blueprint or run is PHI; always: redact everything. */
  redaction: "phi" | "always";
  enabled: boolean;
  /** Mean score below this over the recent window raises an alert. */
  alert_threshold: number | null;
  updated_by: string;
  updated_at: string;
}

export interface OnlineResult {
  id: string;
  sampling_id: string;
  blueprint: BlueprintRef;
  suite_ref: string;
  source_run_id: string | null;
  trace_id: string | null;
  scores: Record<string, number>;
  score: number | null;
  status: "complete" | "pending_human";
  runner_id: string;
  at: string;
  /** Set on the record that completes a `pending_human` result once its review tasks resolved (the pending record is append-only). */
  resolves?: string | null;
}
