-- 0005: signed audit head checkpoints (ADR-0010). Additive post-freeze change.
-- A checkpoint pins (tenant, seq, hash) of the audit chain head under an Ed25519 signature made by a key the
-- database does not hold. Verifying the log against a checkpoint detects tail truncation and history rewrite,
-- which verifyChain alone cannot (ADR-0008).

CREATE TABLE audit_checkpoints (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  id         uuid NOT NULL DEFAULT gen_random_uuid(),
  seq        bigint NOT NULL CHECK (seq >= 1),
  hash       text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  ts         timestamptz NOT NULL,
  signature  text NOT NULL CHECK (signature ~ '^[A-Za-z0-9+/]+={0,2}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX audit_checkpoints_tenant_seq_idx ON audit_checkpoints (tenant_id, seq DESC, created_at DESC);

-- Reuses axis.forbid_mutation (search_path pinned in 0004): checkpoints are append-only.
CREATE TRIGGER audit_checkpoints_append_only BEFORE UPDATE OR DELETE ON audit_checkpoints
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
CREATE TRIGGER audit_checkpoints_no_truncate BEFORE TRUNCATE ON audit_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION axis.forbid_mutation();

-- A checkpoint must refer to an existing chain event with the same hash (so the service cannot
-- checkpoint a head that does not exist). Definer-free: runs as the inserting role under RLS (same tenant).
CREATE FUNCTION axis.audit_checkpoint_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.audit_events e
    WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq AND e.hash = NEW.hash
  ) THEN
    RAISE EXCEPTION 'audit checkpoint: no audit event at seq % with that hash', NEW.seq
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER audit_checkpoint_guard BEFORE INSERT ON audit_checkpoints
  FOR EACH ROW EXECUTE FUNCTION axis.audit_checkpoint_guard();

SELECT axis.enable_tenant_rls('audit_checkpoints', 'tenant_id', 'SELECT, INSERT');
