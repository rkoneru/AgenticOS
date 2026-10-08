# 0080. Audit chain and erasure: keyed pseudonyms, crypto-shred, no raw PII in events

Status: Accepted · Date: 2026-10-08 · Related: 0003, 0008, 0010, 0081

## Context

GDPR Art. 17 (erasure) conflicts with an append-only, hash-chained audit log: rewriting an event breaks every later hash. The chain must stay
verifiable after an erasure, and a regulator must still be able to see that the erasure happened and what it covered.

## Decision

1. **Audit events never contain raw personal data.** `inputs_hash`/`outputs_hash` are SHA-256 of canonical JSON; free text (`reason`) is limited
   to coded values. Governance events are built by `GovernanceAudit`, which throws (`assertNoRawPii`) if an event would contain any identifier
   value of the request, and which refuses to proceed when the append fails (fail-closed, no mutation without its audit event).
2. **A subject is an opaque random id.** `governance_subjects.subject_id` is random. Which person it is lives only in
   `governance_subject_identifiers` as `HMAC-SHA256(per-tenant lookup key, kind || 0x00 || normalised value)`. The reference that goes into
   events is `sub_` + `HMAC(per-tenant audit key, subject_id)` (128 bits), bound into `inputs_hash`.
3. **Erasure = delete the data in the stores + crypto-shred the link.** After the verification pass, the lookup rows are deleted and the
   per-subject `salt` is nulled. The salt feeds the pseudonym tokens written into rows that must be retained (billing actor, member email,
   approvals): without it neither the token nor the audit subject ref can be recomputed from an identifier, even by a holder of the tenant key.
   A later request for the same person gets a new subject id (unlinkable to the old one).
4. **Identifiers a crashed erase needs are sealed**, not stored: AES-256-GCM under a per-tenant key (AAD = tenant), nulled on completion/rejection.
5. **The chain is never rewritten.** `audit_events`, `audit_checkpoints` and their triggers are untouched by migration 0015. A test
   (`test/pg.test.ts`) runs an erase over every store on real Postgres and then verifies the tenant chain (`PgAuditLog.verify`, `verifyChain`) and
   scans it for the subject's identifiers.

## Consequences

- Opaque actor ids that other components already put in events (WorkOS `user_ref`) stay in the chain; they are personal data only while the
  member row's email/name link exists, and erasure deprovisions the member and scrubs those columns (ADR 0081). This relies on components never putting
  emails or names into events (checked for governance events; the audit schema has no free-text field except `reason`, max 1000 chars).
- Duplicate `dsar.erase.completed` events can occur if a crash happens between the event and the request update; the resume re-emits. Documented, harmless.
- Backups still contain erased data until they expire; restoring one re-introduces it. A tombstone ledger of erased lookup hashes would let a restore
  re-erase; it is not built (NEEDS 378).
