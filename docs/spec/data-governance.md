# Data governance (DSAR, retention, holds, residency, PHI verification)

Status: **Prototype** (`services/data-governance`; real-Postgres tests, fakes for the verifier, KMS and control-plane settings). Designed for
GDPR/HIPAA-style obligations; this is evidence-ready engineering, not a compliance certification. ADRs 0080-0083.

## 1. Model

Tenant-scoped, role-gated (`privacy_officer` of that tenant; the tenant and roles come from the credential). Tables (migration 0015, FORCED RLS):
`governance_subjects`, `governance_subject_identifiers`, `governance_requests`, `governance_steps`, `governance_holds`,
`governance_retention_policies`, `governance_retention_runs`. A subject is a random id; identifiers are keyed HMAC lookups (ADR 0080).

## 2. SubjectDataProvider

`find / export / erase / count (+ purge)` per store and a declaration {exports, erases, retains(+legal basis), pseudonymises, dataClasses}
(ADR 0082 table). `erase` is idempotent; `count` returns `{residual, retained, pseudonymised}`.

## 3. DSAR lifecycle

`received -> verified -> processing -> completed | rejected | cancelled`.

- **open**: identifiers normalised, subject resolved, identifiers sealed, due date = received + 30 days, audit `dsar.received`.
- **verify**: `RequesterVerifier` hook (evidence is opaque to the engine). Nothing exports or erases before `verified`. `main.ts` ships a verifier that always refuses.
- **extend**: once, +60 days, before the deadline, with a reason (Art. 12(3)). **sweepSla**: emits `dsar.sla.at_risk` (<= 7 days) and `dsar.sla.breached` once each.
- **export**: signed (Ed25519) bundle: `manifest {request, subject_ref, stores[{provider, declaration, collections[{name,count,sha256}]}], total_records, records_sha256}`
  - `records` + `signature`. `verifyBundle` checks signature, counts, hashes and totals offline. Destination must pass the residency egress check.
- **erase**: audit `started`, identifier closure, per provider `erase` (skipped when a legal hold covers the provider's classes), then the **verification pass**
  (re-queries every non-held provider; any residual -> `ResidualDataError`, audited DENY, request stays `processing`, nothing is shredded), then audit
  `completed`, crypto-shred, `completed` with the per-provider proof stored in `result.verification`. Re-calling `erase` resumes from any crash point
  (idempotent providers, sealed identifiers, cumulative step counts) and after a hold is released.
- **restrict**: Art. 18 restriction recorded as a `restriction` hold; `HoldRegistry.isRestricted(tenant, identifiers)` is the check processing paths call (not yet called by any service, NEEDS 362).

## 4. Retention

Classes: conversation, memory, run_logs, transcripts, eval_data, telemetry, billing, audit. Requested period: control-plane settings (audit, transcript->conversation+transcripts,
memory) or `governance_retention_policies` (run_logs, eval_data, telemetry, billing); default otherwise. Effective period = clamp into [min, max]
(`CLASS_BOUNDS`; audit floor 365 days, 2190 for PHI tenants; billing floor 2190). `audit` is never purged. A class under a tenant hold (or a case hold naming no
subjects) is skipped; subject/case holds pass a protection list to providers so held subjects' rows survive. No settings -> nothing purged (fail-closed). `dryRun`
reports matches only. Every run is stored (`governance_retention_runs`) and audited (counts per class only). Billing "purge" scrubs `actor`; financial rows stay.

## 5. Holds

`legal_hold` scopes: tenant, subject, case (with or without subjects), optional class list; they suspend purge and erasure of matching data. Identifiers are sealed;
events carry the subject ref only.

## 6. PHI verification

ADR 0083, `src/phi-canary.ts`, `test/phi-canary.test.ts`, `runtime/tests/test_phi_canary.py`.

## 7. Residency

ADR 0083, `src/residency.ts`, `test/residency*.test.ts`, `runtime/tests/test_model_residency.py`.

## 8. Audit events (no raw PII)

`dsar.received|verified|verification.failed|extended|rejected|export.completed|export.refused|erase.started|erase.resumed|erase.held|erase.verification_failed|erase.completed|sla.at_risk|sla.breached`,
`governance.hold.placed|released`, `governance.restriction.placed|lifted`, `retention.policy.set|dry_run.completed|purge.completed`.

## 9. Admin surface

Internal only: `/admin/v1` on a loopback dev server (`src/dev-server.ts`, `src/main.ts`). Not in OpenAPI, SDKs, CLI or console (NEEDS 362, 370).

## 10. Honest limits

Exact-match discovery only; backups not covered; KMS not built; eval hashes break by design; see NEEDS 362-379.
