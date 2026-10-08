# 0070. Compliance service (`@axis/compliance`) and its tenant store (migration 0016)

Status: Accepted · Date: 2026-10-08 · Related: 0006, 0056, 0071, 0073, 0074

## Context

Phase 9 component A needs three things the platform did not have: a checked control matrix, sealed technical documentation per blueprint
version, and ISO/IEC 42001 records (AI system inventory, AI impact assessments with an independent review). The records are tenant data and
must obey the same invariants as everything else: forced row-level security, every mutation audited into the tenant's chain, fail-closed when the
audit append fails.

## Decision

`services/compliance` is a new TypeScript service (library plus a loopback dev server), following the pattern of the registry and the Eval Hub:
ports for everything outside it, a memory store as the reference and a Postgres store, one contract test suite for both.

- **One table, forced RLS (migration 0016, additive).** `compliance_docs(tenant_id, coll, key, rev, data jsonb)` with collections `systems`,
  `system_versions` (append-only), `assessments` and `documents` (append-only). A trigger forbids DELETE and, for `assessments`, any change to an
  approved or rejected version. A CHECK constraint states reviewer independence at the data layer: an approved or rejected row needs a `reviewed_by`
  that is neither `author` nor in `contributors`. The service enforces the same rule first; the database is the backstop, so a bug in the service
  cannot approve a member's own work. The policy is `tenant_id = axis.current_tenant()` on both read and write; there is no platform path.
- **Versions, not edits.** Inventory heads are updated with an optimistic revision and every version is also written to `system_versions`.
  An assessment version is its own row (`<id>@<n>`); revising a reviewed version creates the next row. Nothing is deleted: a system is retired.
- **Roles.** read: every role except billing; write: owner, admin, builder; review: owner, admin, auditor. The gateway has decided the
  `api.compliance.*` action first (ADR 0072); the service checks again because the dev server has no gateway in front of it.
- **Audit.** `ComplianceAudit` writes into the tenant's chain (enforcement point `admin`, blueprint `compliance`). The sequence is the registry's:
  authorize, record the decision, perform, record the outcome. A decision that cannot be recorded is not performed (503).
- **Sources behind ports.** The document generator reads five ports (blueprint, evals, policies, audit, limitations), each asked on behalf of the
  caller (tenant, subject, role). The gateway builds them from its own ports (ADR 0074).
- Ids: `0016` is used because the Phase 9 plan reserves 0014 and 0015 for the other components developed in parallel; the parent renumbers on merge.

## Consequences

The compliance records need no new infrastructure. Tenant isolation is tested against real Postgres as the application role, with the table owner
path and the raw constraint tests in `test/stores.test.ts`. The service has no network surface of its own in production: the gateway composes it.
Limits are in `docs/NEEDS.md` #346 onward.
