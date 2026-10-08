# 0081. A governance database role and scoped scrub guards (migration 0020)

Status: Accepted · Date: 2026-10-08 · Related: 0004, 0008, 0056, 0080

## Context

Subject data sits in tables that are append-only or immutable by design: `run_events` (gapless event log), `runs.input` (terminated runs are
absorbing), `usage_events` (financial ledger), decided `approvals`, `eval_hub_docs` (immutable datasets and finished runs). Erasure and retention
must be able to change exactly the personal-data columns of those rows and nothing else.

## Decision

Migration 0020 (additive) creates NOLOGIN role `axis_governance` (NOBYPASSRLS; FORCED RLS still scopes every statement to one tenant) and replaces
five guard functions so that **only `current_user = 'axis_governance'`** may:

| Table                 | Governance may change               | Everyone else         |
| --------------------- | ----------------------------------- | --------------------- |
| `run_events`          | UPDATE `data` only                  | forbidden (unchanged) |
| `usage_events`        | UPDATE `actor`, `dimensions` only   | forbidden (unchanged) |
| `runs` (terminated)   | UPDATE `input` only                 | forbidden (unchanged) |
| `approvals` (decided) | UPDATE `decided_by`, `comment` only | forbidden (unchanged) |
| `eval_hub_docs`       | UPDATE with rev+1, DELETE           | unchanged rules       |

No DELETE on the run log, the ledger or any audit table is granted. The role has no write privilege on `audit_events`/`audit_checkpoints`
(SELECT only). `axis_app` gets only SELECT on the new governance tables; the governance service connects as a member of `axis_governance`.
The trigger checks the role, not a GUC, so application code cannot reach the scrub path by setting a session variable.

## Consequences

Tested in `test/pg.test.ts`: the app role still cannot mutate those tables; the governance role cannot touch audit tables, other columns or other tenants.
Granting `axis_governance` is a privileged operation for ops (runbook). A compromised governance service can scrub personal-data columns of one
tenant at a time, which is its job; it cannot rewrite quantities, hashes or the chain.
