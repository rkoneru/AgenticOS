-- 0003: tamper-evident audit log and vector memory.

CREATE TABLE audit_events (
  tenant_id          uuid NOT NULL REFERENCES tenants (id),
  seq                bigint NOT NULL CHECK (seq >= 1),
  id                 uuid NOT NULL,
  ts                 timestamptz NOT NULL,
  trace_id           text NOT NULL CHECK (trace_id ~ '^[0-9a-f]{32}$'),
  actor_type         text NOT NULL CHECK (actor_type IN ('human', 'agent', 'system')),
  actor_id           text NOT NULL,
  actor_pid          text CHECK (actor_pid IS NULL OR actor_pid ~ '^axp_[0-9A-HJKMNP-TV-Z]{26}$'),
  blueprint_name     text NOT NULL,
  blueprint_version  text NOT NULL,
  policy_version     text NOT NULL,
  enforcement_point  text NOT NULL,
  action             text NOT NULL,
  decision           text NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'ALLOW_WITH_REDACTION')),
  reason             text,
  inputs_hash        text NOT NULL CHECK (inputs_hash ~ '^[0-9a-f]{64}$'),
  outputs_hash       text NOT NULL CHECK (outputs_hash ~ '^[0-9a-f]{64}$'),
  prev_hash          text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash               text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, seq),
  UNIQUE (tenant_id, id),
  CHECK ((actor_type = 'agent') = (actor_pid IS NOT NULL))
);

-- Chain continuity is enforced in the database: seq must be head+1 and prev_hash must be head's hash
-- (or 64 zeros at genesis). The hash itself is verified by the audit service/verifier (packages/contracts).
CREATE FUNCTION axis.audit_chain_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE head audit_events%ROWTYPE;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 0));
  SELECT * INTO head FROM audit_events WHERE tenant_id = NEW.tenant_id ORDER BY seq DESC LIMIT 1;
  IF NOT FOUND THEN
    IF NEW.seq <> 1 OR NEW.prev_hash <> repeat('0', 64) THEN
      RAISE EXCEPTION 'audit chain: genesis event must have seq 1 and zero prev_hash' USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.seq <> head.seq + 1 OR NEW.prev_hash <> head.hash THEN
    RAISE EXCEPTION 'audit chain: expected seq % and prev_hash %', head.seq + 1, head.hash USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER audit_chain_guard BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION axis.audit_chain_guard();
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION axis.forbid_mutation();
SELECT axis.enable_tenant_rls('audit_events', 'tenant_id', 'SELECT, INSERT');

CREATE TABLE knowledge_bases (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,62}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);
SELECT axis.enable_tenant_rls('knowledge_bases', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');

CREATE TABLE memory_chunks (
  tenant_id  uuid NOT NULL,
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  kb_id      uuid,
  scope      text NOT NULL CHECK (scope IN ('session', 'agent', 'tenant', 'kb')),
  owner_ref  text,                            -- session id / agent name, depending on scope
  content    text NOT NULL,
  embedding  vector(1536),
  acl        jsonb NOT NULL DEFAULT '{}',     -- {"roles": [...], "users": [...]}; enforced by the memory service
  metadata   jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, kb_id) REFERENCES knowledge_bases (tenant_id, id) ON DELETE CASCADE,
  CHECK ((scope = 'kb') = (kb_id IS NOT NULL))
);
CREATE INDEX memory_chunks_embedding_idx ON memory_chunks USING hnsw (embedding vector_cosine_ops);
SELECT axis.enable_tenant_rls('memory_chunks', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');
