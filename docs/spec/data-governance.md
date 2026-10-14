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
- **verify**: `RequesterVerifier` hook (evidence is opaque to the engine). Nothing exports or erases before `verified`. The gateway ships `EvidenceVerifier` (ADR 0111): two signed tokens, a `requester_token` and an `admin_attestation` by an independent active owner/admin; the loopback `main.ts` still ships a verifier that always refuses.
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

Public: OpenAPI 1.6.0 `/governance/*` served by the gateway (ADR 0111, 0112), `axis governance ...`, `ax.governance` in both SDKs, read-only console pages
(`/governance`). Roles: reads `owner | admin | auditor | privacy_officer`; every write, export and erasure `privacy_officer` only, checked by the control-plane
pack AND by the gateway adapter. The gateway answers **503** until `GW_GOV_MASTER_KEY` wires the kit (no residency guard is installed either).
Operations: DSAR list/open/get/verify/export/erase/restrict, holds list/place/release, retention get/set/runs/run (`dry_run` defaults to true), residency.
Responses carry the opaque `subject_ref`, never an identifier. Status mapping: not found 404, forbidden/restricted/residency 403, conflict/not verified/held 409,
invalid 422, unavailable 503, residual data 500; an erasure stopped by a hold is a 200 with outcome `held`. The loopback `/admin/v1` dev server
(`src/dev-server.ts`, `src/main.ts`) remains for local use.

### Verification of the requester

`evidence = { requester_token, admin_attestation }`, both HMAC-signed with a per-tenant key (HKDF from the governance master key), bound to tenant, request and
expiry (at most 7 days). The attester must differ from the member who opened the request and from the member verifying, and must be an active `owner` or
`admin` of the tenant (looked up in Postgres under forced RLS). Anything else leaves the request `received`.

## 10. Honest limits

Exact-match discovery only; backups not covered; KMS not built; eval hashes break by design; see NEEDS 362-379 and 407-421.

## 11. Proof on the real stack

`make e2e-governance` (membership subject, dual control, holds) and `make e2e-phase9` (`e2e/test_phase9_hardening.py`, ADR 0113): one person across seven providers exported and
erased through the public API with the verification pass, the audit chain intact and free of raw data, another tenant byte-identical; retention with and without a hold; PHI canaries
through the channel, memory, Eval Hub and run paths (the run log of a PHI run passes `axis_runtime.phi_net` before every event is sealed); residency refusals in the registry,
the Eval Hub and billing, and in the ModelGateway. `runs`, `run_events` and `approvals` have no writer on the dev stack and are seeded by SQL (NEEDS 413).
