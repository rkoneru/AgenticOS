# STRIDE: Audit service (hash-chained, append-only)

Status: Built as a library (`docs/spec/audit-log.md`, ADR 0008 and 0010). Invariant 4: everything is auditable, append-only, hash-chained, replayable.

## Assets

- The per-tenant chain of decisions and mutations (integrity, order, completeness).
- Confidentiality of what the rows could reveal (inputs and outputs are hashes only, PHI stays out).
- Signed head checkpoints and the WORM export that make tail deletion detectable.

## Trust boundaries

1. Writers (kernel, control plane, gateway, channels, registry, marketplace, billing, eval hub) to the append API: tenant from the caller's authenticated binding, `seq`/`prev_hash`/`hash` never supplied (`services/audit/src/chain.ts`).
2. Service to Postgres: forced RLS, trigger-enforced append-only and head linkage under a per-tenant advisory lock (`packages/db/migrations/0003_audit_and_memory.sql`).
3. Readers (AGIL, the gateway `audit` routes, verifiers) get a read-only view: the reader module is architecture-tested to import no writer (`services/audit/src/reader.ts`).
4. The table owner and superusers are trusted until a checkpoint or export exists (tamper-evident, not tamper-proof).

## Data flow

Writer builds an event -> `prepare` assigns `id`/`ts`, validates against the audit schema -> append under the tenant lock with `seq = head + 1` and `prev_hash = head.hash` -> COMMIT then acknowledgement. Checkpoints sign `{tenant, seq, hash, ts}`; export writes NDJSON segments with a manifest of per-segment hashes.

## STRIDE

| Category | Threat | Mitigation (code path) | Test | Residual / NEEDS |
| --- | --- | --- | --- | --- |
| Spoofing | A writer appends rows for another tenant | Tenant bound by the store connection under RLS; the chain splice is a reported break type (`services/audit/src/pg.ts`, `services/audit/src/chain.ts`) | `services/audit/test/pg.test.ts` | Per-tenant credentials for regulated tiers (NEEDS #11) |
| Tampering | Editing or deleting a row | UPDATE/DELETE/TRUNCATE blocked by triggers; `verifyChain` reports the first broken `seq` (gap, link, content) (`packages/db/migrations/0003_audit_and_memory.sql`, `packages/contracts/src/audit-chain.ts`) | `services/audit/test/pg.test.ts`, `packages/contracts/test/audit-chain.test.ts` | Owner/superuser can disable triggers and cut the tail |
| Tampering | Silent tail truncation by the owner | Signed head checkpoints and a WORM export that a third party re-verifies offline (`services/audit/src/checkpoint.ts`, `services/audit/src/export.ts`) | `services/audit/test/checkpoint.test.ts`, `services/audit/test/export.test.ts` | KMS signer and S3 Object Lock not built (NEEDS #12, #13, #14) |
| Tampering | Concurrent appends fork the chain | Per-tenant advisory lock, `seq = head + 1` trigger (`packages/db/migrations/0003_audit_and_memory.sql`) | `services/audit/test/store-contract.ts` | none known |
| Repudiation | A writer denies an action or a replayed append double-counts | Client-supplied `id` makes append idempotent (same content returns the stored event, different content is a conflict) (`services/audit/src/prepare.ts`) | `services/audit/test/memory.test.ts` | Idempotency keys are the caller's discipline |
| Information disclosure | Raw payloads or PHI in audit rows | Rows carry `inputs_hash`/`outputs_hash` over canonical JSON, not payloads (`packages/contracts/src/canonical.ts`) | `packages/contracts/test/audit-chain.test.ts` | Plain hashes of low-entropy text are guessable; channels use keyed digests (NEEDS #156) |
| Information disclosure | A reader leaks another tenant's rows | Reads under RLS; the reader exposes a frozen `listEvents` surface only (`services/audit/src/reader.ts`, `services/audit/src/query.ts`) | `services/audit/test/reader.architecture.test.ts`, `e2e/redteam_probes.py` | none known |
| Denial of service | Append stalls decisions | Callers fail closed (a failed append is a DENY, a failed mutation audit refuses the mutation); the lock is per tenant (`services/audit/src/pg.ts`) | `services/audit/test/pg.test.ts` | A tenant hot spot serialises on its own lock |
| Elevation of privilege | A reader or AGIL influences decisions | AGIL reads the log only and is never on the decision path; architecture test over imports (`services/audit/src/reader.ts`) | `services/agil/test/architecture.test.ts` | none |
| Elevation of privilege | Kernel row with an actor shape the table rejects crashes the append | Constraint violation is a DENY at the kernel (`packages/db/migrations/0003_audit_and_memory.sql`) | `services/risk-kernel/test/kernel.test.ts` | Pid validation mismatch (NEEDS #111) |

## Prompt injection

The audit service stores no model text and takes no instructions from content: events are structured and schema-validated before storage, and free-text fields are not interpreted. An injected instruction can only appear as a hash. The red-team oracle reads audit-adjacent evidence (decisions, tool results) from the Hub run, not from model text (`evals/redteam/oracle.py`). Explanations built from the log by AGIL treat reasons as data and sanitise them (`services/agil/src/sanitize.ts`).

## Tool misuse

There is no tool surface. Misuse here is an abuse of the append API: oversized or malformed events are refused by schema validation and caps (`services/audit/src/prepare.ts`), and an attempt to append with chosen `seq`/`prev_hash`/`hash` is ignored because the service assigns them.
