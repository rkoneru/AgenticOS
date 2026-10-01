-- 0006: columns and a documents table for the memory service (docs/adr/0013). ADDITIVE: no column is dropped or retyped.
-- The one non-additive-looking change widens the scope CHECK with 'run' (run-scoped scratch memory); nothing that was valid
-- before becomes invalid.

ALTER TABLE memory_chunks DROP CONSTRAINT memory_chunks_scope_check;
ALTER TABLE memory_chunks ADD CONSTRAINT memory_chunks_scope_check
  CHECK (scope IN ('run', 'session', 'agent', 'tenant', 'kb'));

-- A knowledge-base document: the unit of ingestion, ACL labelling, dedupe and deletion. Chunks reference it.
CREATE TABLE memory_documents (
  tenant_id    uuid NOT NULL,
  id           uuid NOT NULL DEFAULT gen_random_uuid(),
  kb_id        uuid NOT NULL,
  source       text,                                  -- caller-supplied origin (URL, path, ticket id); informational
  title        text,
  content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),  -- sha256 of the persisted (post-redaction) content
  acl          jsonb NOT NULL,                        -- {"users": [...], "roles": [...], "tenant": bool}; empty = nobody
  acl_key      text NOT NULL,                         -- canonical JSON of acl: dedupe key component
  metadata     jsonb NOT NULL DEFAULT '{}',
  subject      text,                                  -- data subject, for DSAR forget
  phi          boolean NOT NULL DEFAULT false,        -- content passed through PHI redaction before persistence
  expires_at   timestamptz,
  created_by   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, kb_id) REFERENCES knowledge_bases (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, kb_id, content_hash, acl_key)
);
CREATE INDEX memory_documents_subject_idx ON memory_documents (tenant_id, subject) WHERE subject IS NOT NULL;
CREATE INDEX memory_documents_expiry_idx ON memory_documents (tenant_id, expires_at) WHERE expires_at IS NOT NULL;
SELECT axis.enable_tenant_rls('memory_documents', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');

ALTER TABLE memory_chunks
  ADD COLUMN document_id     uuid,
  ADD COLUMN ordinal         integer CHECK (ordinal IS NULL OR ordinal >= 0),
  ADD COLUMN content_hash    text CHECK (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN acl_key         text,
  ADD COLUMN subject         text,
  ADD COLUMN phi             boolean NOT NULL DEFAULT false,
  ADD COLUMN embedding_model text,
  ADD COLUMN expires_at      timestamptz,
  ADD COLUMN created_by      text,
  ADD CONSTRAINT memory_chunks_document_fk
    FOREIGN KEY (tenant_id, document_id) REFERENCES memory_documents (tenant_id, id) ON DELETE CASCADE,
  ADD CONSTRAINT memory_chunks_document_ordinal CHECK ((document_id IS NULL) = (ordinal IS NULL));

CREATE INDEX memory_chunks_owner_idx ON memory_chunks (tenant_id, scope, owner_ref, created_at DESC);
CREATE INDEX memory_chunks_document_idx ON memory_chunks (tenant_id, document_id) WHERE document_id IS NOT NULL;
CREATE INDEX memory_chunks_subject_idx ON memory_chunks (tenant_id, subject) WHERE subject IS NOT NULL;
CREATE INDEX memory_chunks_expiry_idx ON memory_chunks (tenant_id, expires_at) WHERE expires_at IS NOT NULL;
-- Entry (non-document) writes are idempotent per (scope, owner, content, acl): the same write refreshes instead of duplicating.
CREATE UNIQUE INDEX memory_chunks_entry_dedupe_idx
  ON memory_chunks (tenant_id, scope, COALESCE(owner_ref, ''), content_hash, acl_key) WHERE document_id IS NULL;
