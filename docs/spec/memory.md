# Memory service

Status: **Prototype** (real Postgres + pgvector, fake embedder, loopback dev HTTP only) · Code: `services/memory` (`@axis/memory`),
`runtime/src/axis_runtime/memory.py` · Tests: `services/memory/test` (real Postgres), `runtime/tests/test_memory.py` ·
ADR: `docs/adr/0013-memory-service-schema.md` · Gaps: `docs/NEEDS.md` #400-#407.

## What it stores

All memory lives in `memory_chunks` (migration 0003, extended by 0006), tenant-scoped with FORCED row-level security.

| Kind                | `scope`   | `owner_ref` | Written by                    | Typical reader           |
| ------------------- | --------- | ----------- | ----------------------------- | ------------------------ |
| Run (scratchpad)    | `run`     | run id      | `write`                       | the run (`recall`)       |
| Session             | `session` | session id  | `write`                       | the session              |
| Long-term           | `agent`   | agent name  | `write` (gated `MemoryWrite`) | the agent, `search`      |
| Tenant-wide         | `tenant`  | -           | `write`                       | principals the ACL names |
| Knowledge base (KB) | `kb`      | -           | `ingestDocument` (admin)      | NEXUS RAG, `search`      |

Every row has an embedding (`vector(1536)`), ACL, metadata, optional `subject` (data subject), optional `expires_at`.
KB content is a `memory_documents` row plus ordered chunks.

## Guarantees (and the tests that pin them)

- **Tenancy.** Every method runs in a `withTenant` transaction (`axis.set_tenant`), and every statement also names `tenant_id`.
  Raw-SQL tests as `axis_app` prove RLS alone isolates tenants; a mutation test disables RLS and shows the same query leaks.
- **ACL (fail closed).** A principal `{id, groups}` reads a row iff `acl.users` has its id, `acl.roles` intersects its groups, or
  `acl.tenant` is true. Empty ACL = nobody. The predicate is in the same WHERE as similarity ORDER BY/LIMIT, so unreadable rows are
  never fetched, scored or counted; there is no total or "hidden" count; metadata/scope/kb filters only narrow readable rows;
  unknown and foreign ids give the same `NOT_FOUND`. A property test checks the SQL predicate against `aclAllows` for random
  ACLs/principals (no leak, no loss); a side-channel test compares results with a world lacking the restricted rows.
- **PHI.** If the tenant has `phi_mode` or the request sets `phi`, redaction runs BEFORE embedding, hashing and persistence
  (`redact.ts`: same path semantics as `runtime/redaction.py`, shared vectors; plus a heuristic scrub; see NEEDS #403).
- **Dedupe.** Documents: `(kb, sha256 of persisted content, canonical ACL)`. Entries: `(scope, owner, content hash, ACL)`; a repeat
  refreshes TTL/metadata. The hash is over the redacted content.
- **Chunking** (`chunk.ts`): by code points, `size` 800 / `overlap` 100 by default, ends snap to whitespace. Property-tested:
  coverage, size bound, exact overlap, strict progress, reassembly.
- **TTL.** Reads ignore expired rows (injected clock); `purgeExpired(tenant)` deletes them.
- **Forget (DSAR hook).** `forgetSubject(tenant, subject)` hard-deletes entries, documents and chunks of that subject in that tenant.

## API (TypeScript)

`PgMemoryService({pool, embedder, role?, now?, chunking?})`: `write`, `ingestDocument`, `ensureKnowledgeBase`, `search`, `recall`,
`setDocumentAcl`, `deleteDocument`, `forgetSubject`, `purgeExpired`. `Embedder {id, dimensions: 1536, embed(texts)}`; `HashEmbedder`
is the deterministic test double. A write from an agent is authorised by the Risk Kernel gate in the runtime, not by the service.

## Dev HTTP wire (loopback, NOT production, NEEDS #401)

`POST /v1/memory/<route>`, JSON, `Authorization: Bearer <token>`. Tenant from the token (a different `tenant_id` in the body: 403).
Agent routes: `write`, `search`, `recall`. Admin routes (token `admin: true`): `ingest`, `set-acl`, `delete-document`, `forget`, `purge`.
Examples: `services/memory/contract/wire-v1.json`, checked by the server tests and by the Python client tests. Errors:
401 / 403 / 400 `INVALID` / 404 `NOT_FOUND` / 502 `EMBEDDER` / opaque 500.

## Runtime

`HttpMemoryBackend` implements `tools.MemoryStore`: `MemoryWrite(scope=run|session|long_term|tenant, args={content, metadata?, acl?,
subject?, ttl_seconds?, phi?})` goes gate -> audit -> `write`. The gate's redaction paths are applied to `args` by the executor
before the call. `MemoryRagRetriever` implements `nexus.rag.Retriever` (tenant + principal on every call, tenant mismatch refused,
service-side ACL filter, `RagStage` re-checks). `memory.py` is allowlisted in the bypass scanner for `httpx` only.
