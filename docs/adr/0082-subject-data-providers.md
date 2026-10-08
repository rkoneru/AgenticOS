# 0082. SubjectDataProvider port: declared scope per store

Status: Accepted · Date: 2026-10-08 · Related: 0080, 0081

## Decision

Every store that can hold subject data registers a `SubjectDataProvider` (`find/export/erase/count`, optional `purge`) and a **declaration**:
what it exports, what it erases, what it must retain (with legal basis) and what it pseudonymises. The declaration is copied into every export manifest.
Providers are tenant-scoped by construction (Postgres providers run in `withTenant` under FORCED RLS as `axis_governance`).

| Provider              | Erases                                                                         | Retains / pseudonymises                                                     |
| --------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| memory                | chunks/documents by `subject`                                                  | `created_by` of other rows -> token                                         |
| channels              | messages, threads, conversations, identities, end user, link challenges        | audit events (no PII)                                                       |
| voice-transcripts     | messages with channel `voice`                                                  |                                                                             |
| control-plane-members | email, name, external id scrubbed; sessions and API keys revoked (deprovision) | member row + opaque `user_ref` (admin history); sole owner cannot be erased |
| billing               | nothing                                                                        | ledger rows retained (Art. 17(3)(b)); `actor`/dimension values -> token     |
| eval-hub              | dataset cases tombstoned in place; run outputs/traces of those cases nulled    | version records, ids, grades                                                |
| run-logs              | `runs.input`, `run_events.data` scrubbed                                       | row skeleton, audit refs                                                    |
| approvals             | comment/reason removed                                                         | decision records, actor -> token                                            |

Linkage conventions (exact match only): memory `subject`; eval `metadata.subject_ref`; runs/events top-level keys `subject, subject_ref, principal,
end_user_id, user_ref, email, requested_by` (principal `enduser:<id>`); billing `actor` or any dimension value. Providers can return `discovered`
identifiers (an email resolves to the end user and all their channel identities); the engine takes the closure (<= 3 rounds) before acting.

## Consequences

Free-text mentions of a person inside someone else's data are not found (NEEDS 3202). Eval tombstoning invalidates the content hash of the
affected dataset version, so the hub refuses to run it until a new version is ingested (NEEDS 3206).
