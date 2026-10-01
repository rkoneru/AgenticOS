# 0013. Memory service schema extension (migration 0006)

Status: Accepted · Date: 2026-10-01 · Amends: 0007 (post-freeze addition, same procedure as 0008 and 0010)

## Context

Phase 4 component A (`services/memory`) stores run, session, long-term and knowledge-base memory in the `memory_chunks` table of
migration 0003. That table has no document concept, no content hash (dedupe), no data subject (DSAR forget), no expiry (TTL), no
PHI marker, no embedding model id, and no `run` scope. We prefer what exists, and keep: `scope`, `owner_ref`, `content`,
`embedding vector(1536)`, `acl` (`roles` are treated as groups, `users` as principal ids), `metadata`, FORCED tenant RLS.

## Decision

Additive migration `0006_memory_service.sql` (migrations are append-only, ADR-0007/0008; `FREEZE.json` regenerated):

- New `memory_documents` (tenant RLS FORCED, `axis.enable_tenant_rls`): the unit of ingestion, ACL labelling, dedupe
  (`UNIQUE (tenant_id, kb_id, content_hash, acl_key)`) and deletion. Chunks reference it with `ON DELETE CASCADE`.
- New `memory_chunks` columns: `document_id, ordinal, content_hash, acl_key, subject, phi, embedding_model, expires_at, created_by`,
  indexes for owner/subject/expiry/document lookups, and a partial unique index making entry writes idempotent.
- The scope CHECK is replaced by one that also allows `run`. This only widens it: every row valid before stays valid. It is the one
  statement that touches an existing constraint, hence this ADR.
- ACL model (enforced in the service, inside the SQL that selects rows, not after): a principal `{id, groups}` may read a row iff
  `acl.users` contains `id`, or `acl.roles` intersects `groups`, or `acl.tenant = true`. An empty ACL is readable by nobody
  (fail closed). Writers must label explicitly; the default for an entry write is the writer alone.

## Consequences

- Embedding width stays 1536 (the frozen column type). An embedder with another width must project to 1536; recorded in NEEDS.
- `embedding_model` is stored and searches filter on it, so vectors from different models are never compared.
- Existing db tests: seed covers the new table, migration list updated; no frozen file was edited.
