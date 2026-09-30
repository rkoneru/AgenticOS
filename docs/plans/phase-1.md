# Phase 1 plan — Contracts (freeze point)

Deliverables, each with a machine check:

| Contract                                           | Location                                                                                                     | Check                                                                                           |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| ABL v1 JSON Schema + spec + examples               | `packages/abl`, `docs/spec/abl-v1.md`                                                                        | ajv: every valid example passes, every invalid example fails for the stated reason              |
| Policy DSL v1 schema + decision model              | `packages/contracts/schemas/policy-v1.schema.json`, `docs/spec/policy-dsl-v1.md`                             | ajv on examples                                                                                 |
| Process model (states, signals, PID, IPC envelope) | `packages/contracts/process-model.json`, `schemas/ipc-envelope-v1.schema.json`, `docs/spec/process-model.md` | transition-table tests                                                                          |
| Audit event schema + hash chain                    | `schemas/audit-event-v1.schema.json`, `src/audit-chain.ts`                                                   | chain/tamper tests, 95% coverage                                                                |
| gRPC                                               | `proto/axis/runtime/v1`                                                                                      | `buf lint` + `buf build`                                                                        |
| REST `/v1`                                         | `packages/contracts/openapi/axis-v1.yaml`                                                                    | Redocly lint (OpenAPI 3.1)                                                                      |
| Postgres schema + RLS + migrations                 | `packages/db`                                                                                                | real PG16+pgvector; cross-tenant isolation tests; "every tenant table has forced RLS" meta-test |
| ADRs                                               | `docs/adr/0003-0007`                                                                                         | review                                                                                          |
| Freeze                                             | `packages/contracts/FREEZE.json`                                                                             | test fails if a frozen file changes without regenerating the manifest (which requires an ADR)   |

Exit: contracts versioned and frozen; contract tests scaffolded; RLS isolation tests passing.
Reconciliation: the original kernel/docs were not supplied (see `docs/NEEDS.md` #1). These contracts derive
from the master prompt only. If the originals surface, reconcile via an ADR; that is a post-freeze change.
