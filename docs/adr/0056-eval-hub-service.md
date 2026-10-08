# 0056. Eval Hub service (`services/eval-hub`) and migration 0013

Status: Accepted · Date: 2026-10-08 · Related: 0007 (freeze), 0030, 0031, 0053, 0055; docs/plans/phase-8.md

## Context

Phase 8 blocks blueprint releases when evals regress. The ABL already declares `spec.evals.suites[{ref, threshold}]`; nothing stored
datasets, suites or run results, nothing decided whether a release may proceed, and `POST /v1/evals/runs` answered 501.

## Decision

`@axis/eval-hub` is a TypeScript service (library + loopback dev HTTP server) that owns datasets, suites, runners, eval runs, baselines,
the human review queue, the release gate and online sampling. Decisions that shape it:

1. **Storage: one document table with forced RLS** (migration 0013, `eval_hub_docs`, same shape as `marketplace_docs`, tenant path only,
   no platform path: the hub never reads across tenants). Immutability is enforced by a trigger, not only in code: datasets, suites,
   baselines, online results and events are append-only; a run is updatable only while `queued`/`running` (a finished run, and so its
   scores, never changes); runner revocation and resolved tasks are one-way. Memory and Postgres stores sit behind the same `DocStore`
   port and run one contract suite.
2. **The hub recomputes every score.** A runner submits per-case grader scores; the aggregate it also sends is only a claim. The hub
   recomputes `per_case`, `per_grader` and `overall` with the suite's declared aggregation (documented in docs/spec/eval-hub.md), rejects
   a mismatch (`integrity_failed`, 422) and stores its own numbers. The recomputation is order-independent (sorted before summing).
   The gate recomputes again from the stored case results, so a tampered stored aggregate blocks too.
3. **The gate is fail-closed and bound to content.** A run counts only if it is final, was produced by a runner that is registered for the
   tenant (and not revoked), is for the blueprint's `content_hash`, covers the whole dataset, is fresh, and passes
   `score >= threshold AND no regression beyond tolerance vs the baseline`. Anything missing, stale, errored, tampered or unreachable
   blocks. The registry and marketplace call the gate through an injected `EvalGatePort` whose default denies; a blueprint that declares
   no suites is allowed without calling it.
4. **Online results never gate.** Sampled production results are stored apart from runs, can raise alerts and show history, and are not
   read by the gate or by any decision path.
5. **Human review is separated from the publisher.** Reviewers must not be the run's starter or the blueprint's publisher; double grading
   is adjudicated by a third person; claims expire; SLAs are explicit.
6. **Attestations.** Each finished run yields an Ed25519-signed summary (DSSE-style) which the registry verifies against the trusted hub
   key and stores, append-only, next to the version record (`attachEvalAttestation`).
7. **Public API: OpenAPI 1.3.0** (ADR 0057) exposes the tenant side; the runner side is the hub's own authenticated surface.

## Consequences

- Dev servers use static bearer tokens (role `runner`, `reviewer`, `admin`, ...) and refuse `NODE_ENV=production`.
- Postgres audit for hub events goes to the same `AuditSink` as the registry (`ServiceAudit`, service `eval-hub`).
- Gaps (docs/NEEDS.md #293+): no KMS-held attestation key, no real judge-model runs, runners are registered by id and authenticated by a
  static token in dev.
