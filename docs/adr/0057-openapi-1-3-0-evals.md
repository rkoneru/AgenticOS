# 0057. OpenAPI 1.3.0: Eval Hub operations (additive)

Status: Accepted · Date: 2026-10-08 · Related: 0007 (freeze), 0053, 0056

## Context

`startEvalRun` was a 501 placeholder in 1.2.0. The Eval Hub (ADR 0056) needs a public surface so the console, CLI and both SDKs can run
suites, read scores, ask the release gate, manage datasets, suites and baselines, work the human review queue and configure online sampling.

## Decision

One additive bump, `info.version` 1.2.0 -> 1.3.0, per the 0007 procedure. No existing path, parameter, schema, status code or enum value
changes; `FREEZE.json` is regenerated; SDKs are regenerated with `make sdk-generate`.

- Runs: `listEvalRuns`, `startEvalRun` (now real: 202, idempotent, bound to the blueprint version's content hash), `getEvalRun`,
  `getEvalRunComparison` (baseline delta, tolerance, paired sign-flip significance).
- Gate: `gateEvalRelease` (`POST /evals/gate`). Fail-closed; 200 with `allowed` and every `reasons[]` entry (code, suite_ref, message).
- Datasets: `listEvalDatasets`, `createEvalDataset` (next immutable version; PHI redacted before it is stored), `getEvalDatasetVersion`.
- Suites: `listEvalSuites`, `createEvalSuite`, `getEvalSuite`. Baselines: `listEvalBaselines`, `setEvalBaseline`.
- Review: `listEvalReviewTasks`, `claimEvalReviewTask`, `gradeEvalReviewTask`, `skipEvalReviewTask`.
- Online: `listEvalSamplingConfigs`, `putEvalSamplingConfig`, `getEvalOnlineSummary`. Online scores never feed the gate.
- Runners: `listEvalRunners`, `registerEvalRunner`, `revokeEvalRunner`.
- Control-plane pack actions `api.evals.read|write|admin|review` (existing `api.evals.run` kept); scopes `evals:read`, `evals:write`.

No new problem `code` values: `evals_gate_failed` is a problem `type` slug returned by the registry/marketplace with code `conflict`
(409) and a `reasons` array; the public gateway has no release route, so the gate result is data in `gateEvalRelease`.

## Consequences

- Gateway route table (60 operations), contract tests, SDK generator output, both ergonomic layers (`ax.evals.*`) and the CLI
  (`axis evals ...`) are extended in the same change; the drift and spec-coverage tests stay green.
- Mock servers needed pattern samples for the new id patterns.
- The gateway standalone composition hosts the hub on Postgres with an ephemeral attestation key (NEEDS #293-#305).
