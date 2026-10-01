# Runbook: Memory service

Status: **Prototype**. Spec: `docs/spec/memory.md`. Gaps: `docs/NEEDS.md` #400-#407.

## Run the dev server (NOT production)

```bash
pnpm --filter @axis/memory build
AXIS_MEMORY_DATABASE_URL=postgres://... \
AXIS_MEMORY_ROLE=axis_app \            # only when connecting as a superuser; production connects as axis_app directly
AXIS_MEMORY_TOKENS='{"tok-agent":{"tenantId":"<uuid>","admin":false},"tok-admin":{"tenantId":"<uuid>","admin":true}}' \
node services/memory/dist/main.js     # prints `listening <port>`, loopback only
```

Migrations (`0001`-`0006`) must already be applied (`pnpm --filter @axis/db migrate`). Uses the deterministic `HashEmbedder`.

## Operations

- **Expiry:** reads ignore expired rows; delete them with `purgeExpired(tenantId)` on a schedule per tenant (no built-in sweeper).
- **DSAR delete:** `forgetSubject(tenantId, subject)` (admin route `forget`). Returns counts only. It is not audited yet (NEEDS #402).
- **Change who can read a document:** `setDocumentAcl` (rewrites the document's chunks atomically).
- **Changing the embedder:** rows carry `embedding_model`; searches only match the active id. Old rows become invisible to search
  until re-embedded (no re-embed job yet, NEEDS #406).
- **Suspected ACL/tenant leak:** run `pnpm --filter @axis/memory test`; the isolation tests include an RLS-off mutation check and an
  ACL oracle property test. Check `pg_class.relforcerowsecurity` on `memory_chunks`, `memory_documents`, `knowledge_bases`.

## Verifying

```bash
pnpm --filter @axis/memory cov      # real Postgres via infra/scripts/with-pg.sh
uv run pytest runtime/tests/test_memory.py
```
