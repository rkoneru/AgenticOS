# STRIDE: Memory service (run, session, long-term, knowledge bases)

Status: Built, dev surface only (`docs/spec/memory.md`; loopback dev HTTP, hash embedder). Memory is a persistent prompt-injection channel, so this file has the most detailed injection section.

## Assets

- Per-tenant memory entries and knowledge-base documents (confidentiality by ACL, tenant isolation by RLS).
- Integrity of what the agent later reads back as "facts".
- PHI: redaction before embedding and persistence; data-subject linkage for forget requests.

## Trust boundaries

1. Runtime (agent action, gated by the kernel as `memory_write`/`memory_search`) to the service: tenant and principal come from the bearer token (`services/memory/src/dev-server.ts`).
2. Admin routes (ingest, set-acl, forget, purge) need an `admin` token, separate from agent routes (`services/memory/src/dev-server.ts`).
3. Service to Postgres: forced RLS, ACL predicate in the same WHERE as the vector search (`services/memory/src/store.ts`, `packages/db/migrations/0006_memory_service.sql`).

## Data flow

Agent `memory_write` -> kernel decision (audited) -> redaction paths applied -> PHI scrub before embedding when PHI -> store with ACL (default: writer alone), owner, TTL. `memory_search` -> kernel -> ACL-filtered similarity -> results returned to the agent as data.

## STRIDE

| Category               | Threat                                                                                 | Mitigation (code path)                                                                                                                                                                                                    | Test                                                                 | Residual / NEEDS                                          |
| ---------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------- |
| Spoofing               | An agent claims another principal or scope (`principal`, `acl`, `phi:false` arguments) | The runtime accepts only declared memory arguments; scope, ACL, PHI flag and owner are wiring (`runtime/src/axis_runtime/run.py`, `runtime/src/axis_runtime/memory.py`)                                                   | `runtime/tests/test_run_tools.py`, `runtime/tests/test_memory.py`    | none known                                                |
| Tampering              | Memory poisoning: a persisted instruction acts later                                   | Writes are gated and audited; recalled text is data and any action it provokes meets the gate again. Red-team cases write instruction-like and subtle notes then recall them (`evals/redteam/datasets/redteam-core.json`) | `e2e/redteam_harness.py`, `e2e/test_phase4_tools.py`                 | A stored note can still mislead an answer (NEEDS #398)    |
| Tampering              | A deduped write rewrites ownership or subject                                          | Dedupe key includes scope, owner and canonical ACL (`services/memory/src/store.ts`)                                                                                                                                       | `services/memory/test/store.test.ts`                                 | First data subject is kept (NEEDS #113)                   |
| Repudiation            | A write or forget without a record                                                     | Runtime writes pass the kernel and are audited; admin routes are not (`runtime/src/axis_runtime/actions.py`)                                                                                                              | `e2e/test_phase4_tools.py`                                           | Admin routes and DSAR forget are not audited (NEEDS #76)  |
| Information disclosure | Reading rows the principal may not                                                     | Fail-closed ACL (empty ACL is readable by nobody) evaluated in SQL; property test against `aclAllows` (`services/memory/src/acl.ts`)                                                                                      | `services/memory/test/isolation.test.ts`                             | No deny rules or ACL-change audit (NEEDS #78)             |
| Information disclosure | PHI persisted or embedded                                                              | Redaction runs before embedding, hashing and persistence; shared vectors with the runtime (`services/memory/src/redact.ts`)                                                                                               | `services/memory/test/redact.test.ts`                                | Path-based plus heuristic net, not a detector (NEEDS #77) |
| Information disclosure | Cross-tenant read                                                                      | Forced RLS and tenant-scoped queries (`packages/db/migrations/0006_memory_service.sql`)                                                                                                                                   | `services/memory/test/isolation.test.ts`, `e2e/test_phase4_tools.py` | none known                                                |
| Denial of service      | Oversized or numerous writes                                                           | Chunking with size bounds, TTL, caps (`services/memory/src/chunk.ts`)                                                                                                                                                     | `services/memory/test/chunk.test.ts`                                 | No TTL sweeper or rate limit (NEEDS #80, #75)             |
| Elevation of privilege | An agent writes tenant-wide memory                                                     | `tenant` scope is never agent-writable; writes need the manifest flag (`runtime/src/axis_runtime/run.py`)                                                                                                                 | `runtime/tests/test_run_tools.py`                                    | none known                                                |

## Prompt injection

Persistent injection (memory poisoning) is the main risk: text an attacker got stored once is returned in later runs, possibly with higher trust than the original source. Controls: (1) the write is a gated action, so a policy can deny instruction-like content (the red-team pack does, with `deny-instruction-like-memory` in `evals/redteam/policy/pack.yaml`), (2) recalled text is returned as tool data and never as system content, (3) whatever the model then attempts is gated again under the current policy, (4) ACLs keep one principal's notes from reaching another's context (`services/memory/src/acl.ts`). Residual: a stored note can still bias an answer that triggers no gated action (NEEDS #398). The suite checks 13 poisoning scenarios; a persisted instruction must never lead to a performed harmful action.

## Tool misuse

`memory_write` and `memory_search` are fixed definitions whose schema forbids extra properties (`runtime/src/axis_runtime/tooldefs.py`); invalid scope, limit or extra keys are a tool error with no gate request and no service call (test `test_invalid_memory_arguments_are_a_tool_error_with_no_gate_request` in `runtime/tests/test_run_tools.py`).
