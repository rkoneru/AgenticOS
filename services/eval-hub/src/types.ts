import type { Role } from "@axis/control-plane";

export const NAME_RE = /^[a-z][a-z0-9-]{1,62}$/;
/** A stored suite: `[namespace/]name@major.minor.patch`. */
export const SUITE_REF_RE =
  /^((?:[a-z][a-z0-9-]{1,62}\/)?[a-z][a-z0-9-]{1,62})@(\d{1,9}\.\d{1,9}\.\d{1,9})$/;
/** What a blueprint's `spec.evals.suites[].ref` may say: `[namespace/]name@<version or semver range>`. The gate resolves ranges. */
export const GATE_REF_RE = /^((?:[a-z][a-z0-9-]{1,62}\/)?[a-z][a-z0-9-]{1,62})@(.{1,60})$/;
export const DATASET_REF_RE = /^([a-z][a-z0-9-]{1,62})@([1-9][0-9]{0,8})$/;
export const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/;
export const GRADER_ID_RE = /^[a-z][a-z0-9_-]{0,40}$/;
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
  expected?: unknown;
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
  /** SHA-256 of the canonical JSON of the cases AS STORED (after redaction). */
  content_hash: string;
  cases: EvalCase[];
  created_at: string;
  created_by: string;
}

export const DETERMINISTIC_KINDS = [
  "exact",
  "contains",
  "regex",
  "json_schema",
  "numeric_tolerance",
  "tool_call_sequence",
  "policy_decision",
  "cost_latency_budget",
] as const;
export type DeterministicKind = (typeof DETERMINISTIC_KINDS)[number];

export interface DeterministicGrader {
  id: string;
  type: "deterministic";
  kind: DeterministicKind;
  weight: number;
  params: Record<string, unknown>;
}
export interface ModelGrader {
  id: string;
  type: "model";
  rubric: string;
  judge_model: string;
  weight: number;
}
export interface HumanGrader {
  id: string;
  type: "human";
  rubric: string;
  weight: number;
  sla_hours: number;
  double_grade: boolean;
  /** Two grades closer than this are accepted (mean); farther apart needs a third reviewer. */
  agreement_tolerance: number;
}
export type Grader = DeterministicGrader | ModelGrader | HumanGrader;

export interface Suite {
  ref: string;
  name: string;
  version: string;
  dataset_ref: string;
  dataset_hash: string;
  graders: Grader[];
  /** Overall score a run needs to be `passed` (and the floor of the release threshold). */
  pass_threshold: number;
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

export interface CaseResult {
  case_id: string;
  /** grader id -> score in [0, 1]; null for a human grader still pending. */
  scores: Record<string, number | null>;
  case_score: number | null;
  cost_usd: number;
  latency_ms: number | null;
  trace_id: string | null;
  error: string | null;
}

export interface RunScores {
  overall: number;
  per_grader: Record<string, number>;
  per_case: Record<string, number>;
}

export interface RunProvenance {
  runner_version: string;
  model_ids: string[];
  seed: string;
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
  cost: { total_usd: number };
  provenance: RunProvenance | null;
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
  /** Excerpts for the reviewer; redacted when the dataset is PHI. */
  case_input: unknown;
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
  redaction: "redact" | "hash_only";
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
  score: number;
  runner_id: string;
  at: string;
}
