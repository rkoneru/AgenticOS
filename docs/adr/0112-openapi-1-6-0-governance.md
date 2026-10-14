# 0112. OpenAPI 1.6.0: data-governance operations

Status: Accepted · Date: 2026-10-14 · Related: 0111, 0072 (compliance, 1.5.0)

## Context

The data-governance engine had no public surface (NEEDS 362). The API freeze (ADR 0007, with the additive-minor rule used by 0024/0053/0058/0071)
allows new operations and schemas in a minor version when no existing operation, schema or code changes.

## Decision

OpenAPI **1.6.0** adds 15 operations under `/governance` (tag `Governance`, 90 operations in total), all additive:

| Operation                                            | Method and path                                                             | Role            |
| ---------------------------------------------------- | --------------------------------------------------------------------------- | --------------- |
| listGovernanceDsarRequests, getGovernanceDsarRequest | GET `/governance/dsar-requests[/{requestId}]`                               | read            |
| createGovernanceDsarRequest                          | POST `/governance/dsar-requests`                                            | privacy_officer |
| verify / export / erase / restrict                   | POST `/governance/dsar-requests/{requestId}/{verify,export,erase,restrict}` | privacy_officer |
| listGovernanceHolds                                  | GET `/governance/holds`                                                     | read            |
| placeGovernanceHold, releaseGovernanceHold           | POST `/governance/holds`, `.../{holdId}/release`                            | privacy_officer |
| getGovernanceRetention, listGovernanceRetentionRuns  | GET `/governance/retention`, `/governance/retention-runs`                   | read            |
| setGovernanceRetention                               | PUT `/governance/retention/{dataClass}`                                     | privacy_officer |
| runGovernanceRetention                               | POST `/governance/retention-runs` (`dry_run` defaults to true)              | privacy_officer |
| getGovernanceResidency                               | GET `/governance/residency`                                                 | read            |

"read" is `owner | admin | auditor | privacy_officer`. Identifiers are request-only: a response carries the opaque `subject_ref`, never an
identifier. Mutations take `Idempotency-Key`. The generated TypeScript and Python clients were regenerated (the Python generator now emits `None`
for a nullable enum), both SDKs gained ergonomic `governance` wrappers, the CLI gained `axis governance ...`, and the console gained read-only
pages. `packages/contracts/FREEZE.json` records the new document hash and the migrations 0016 and 0017.

## Consequences

Clients written against 1.5.0 keep working. A gateway that does not wire the kit answers every governance operation with 503 (documented
response), so a client can tell "not configured" from "denied". There are no webhooks for SLA events (NEEDS 375): the sweep is externally scheduled.
