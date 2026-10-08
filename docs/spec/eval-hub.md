# Eval Hub (`@axis/eval-hub`)

Status: Prototype (see `docs/NEEDS.md` #293-#305). ADR 0056 (service), 0057 (OpenAPI 1.3.0). Runner side: `docs/spec/evals-runner.md`.

## Model

- **Dataset**: immutable numbered version (`name@N`, assigned by the hub). `version_hash` = SHA-256 of ASCII-escaped canonical JSON of the
  cases (sorted by id, sorted keys, compact, `\uXXXX` outside space..`~`, `expected` null when absent). PHI datasets are redacted before persist.
- **Suite**: immutable `name@N`: dataset ref, graders (`deterministic|model|human`, weight, config, `min_mean`), `pass_threshold`,
  `tolerance`, `min_case_score`, `max_age_days`, `min_samples`; `suite_hash` covers all of it.
- **Run**: queued -> running -> passed|failed|errored. Append-only except while queued/running (DB trigger). Bound to the blueprint
  `content_hash`, dataset hash and suite hash. Executed only by a registered, non-revoked runner.
- **Baseline**: append-only history per (blueprint, suite); the latest passed run promoted at release (`released()`) or set by an admin.

## Scoring (hub recompute, never trust the runner)

`aggregateGrid` visits cases in ascending id and graders in declared order; a grade that is not `scored` counts as 0 and is tallied in
`ungraded`; any `pending` grade makes the result `pending_human`. Output rounding `r6(x)=floor(clamp(x)*1e6+0.5)/1e6`. Failures, in order:
`below_pass_threshold`, `min_case_score:<ids>`, `grader_min_mean:<id>`, `errored_cases:<ids>`, `no_cases`. `passed` = no failures. A result
whose claimed status/overall/passed/ungraded/failures/per_grader/per_case differ by more than 1e-6 is rejected. Pinned by the runner's
13 aggregation vectors (`test/fixtures/eval-aggregation-vectors.json`) and wire examples.

## Results validation

Provenance must match the run (runner id, aggregation version 1, content hash, dataset hash, suite ref, seed). Costs are Decimal strings
with total = agent + judge. Human grades are submitted `pending`; review tasks resolve them and the hub finalizes. Runner POST bodies carry
`x-axis-runner-id` and `x-axis-runner-signature: v1=<hex HMAC-SHA256 of the exact body>`.

## Regression and significance

`compareRuns` is comparable only for identical dataset and suite hashes. A drop larger than `tolerance` (exactly the tolerance is not a
regression) is a regression. The paired sign-flip test is exact for <=16 nonzero paired differences, else 20000 seeded Monte Carlo flips
(seed from the run record hashes), so results are deterministic. `regression_requires_significance` optionally requires p < alpha to block.

## Gate (`POST /evals/gate`)

Input: blueprint (name, version, content_hash, optional namespace) and suites (`ref` or a semver range, optional `threshold`). Required
suites = declared + tenant-required (`required_for_release` + `applies_to`). For each, the latest run by a registered non-revoked runner
for this content hash decides, and must be: final (ci/manual mode), bound to suite and dataset hashes, fresh, sufficiently sampled,
re-verified (`verifyStoredRun`), `overall >= max(declared threshold, suite pass_threshold)`, not `run_failed`, and without a blocking
regression (baseline invalid = blocked). A newer run awaiting human review is `run_in_progress`. Reason codes: `missing_run`,
`no_run_for_content_hash`, `runner_not_registered`, `run_in_progress`, `run_errored`, `stale_run`, `insufficient_samples`,
`below_threshold`, `run_failed`, `regression`, `baseline_invalid`, `integrity_failed`, `suite_not_found`, `gate_error`. Any error ->
deny. Every decision is audited first; an audit failure means no decision is returned.

## Registry and marketplace hooks

`EvalGatePort` (default `DENY_ALL_EVAL_GATE`). `RegistryService.setVersionPublic`, marketplace `submit` and `decide` (approval) call it;
refusal is 409 `evals_gate_failed` with `reasons`. A blueprint declaring no suites is allowed. Eval-result attestations (DSSE, Ed25519)
are attached append-only to registry versions after verification against the trusted hub key, subject = ns/name@version + content hash.

## Human review

Tasks: open -> claimed -> resolved | needs_adjudication. SLA from the grader's `sla_hours`; sweeps mark breaches. The reviewer must not be the
blueprint's publisher or the run's starter. `double_grade` needs two reviewers; disagreement beyond `agreement_tolerance` goes to an
admin adjudicator. Claim, grade and skip are audited.

## Online sampling

Config per (blueprint, suite): rate, max_per_hour, redaction `phi|always`. Ingestion stores scores and ids only; alerts at most hourly.
Online data is never used by the gate.

## Roles

owner/admin all; builder read/write/review/run; operator read/review; auditor, viewer read; billing none; `reviewer` read+review. The
runner role may only claim, fetch datasets/suites, and post results for its own runs. Tenant comes from the credential only; RLS forced.
