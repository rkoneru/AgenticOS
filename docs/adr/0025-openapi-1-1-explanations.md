# 0025. OpenAPI 1.1.0: AGIL explanation endpoints (additive)

Status: Accepted · Date: 2026-10-02 · Related: 0007 (freeze), 0024, 0027

## Context

Phase 7 asks for an AGIL explanation panel beside every run and denial (console) and `axis` CLI/SDK access. The frozen v1 contract has
no endpoint for it.

## Decision

Additive, no breaking change, per the 0007 procedure (`info.version` 1.0.0 -> 1.1.0, new tag `Explanations`, FREEZE.json regenerated):

- `GET /v1/runs/{runId}/explanation` (`explainRun`)
- `GET /v1/audit/events/{seq}/explanation` (`explainAuditEvent`; the path key is the tenant's gapless audit `seq`, which the audit log
  can read without a new index)
- schema `Explanation` = `{summary, steps[], decision_refs[], remediation[], narrative?}`

No existing path, parameter, schema or status code changes; generated SDKs only gain methods.

## Consequences

`freeze-guard` passes with the regenerated manifest. The registry/marketplace proxies the registry component might want are NOT added
here; that component records its own ADR (0030+) if it needs them.
