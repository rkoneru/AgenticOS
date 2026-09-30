-- 0004: hardening from the Phase 1 independent review (see docs/adr/0008).

-- 1. search_path hijack: guard functions resolved `audit_events` via pg_temp first, so an axis_app session could
--    shadow the table with a TEMP table and forge chain continuity. Pin search_path (pg_temp last), qualify names,
--    and remove the TEMP privilege from PUBLIC.
DO $$ BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END $$;

CREATE OR REPLACE FUNCTION axis.current_tenant() RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE v text := pg_catalog.current_setting('axis.tenant_id', true);
BEGIN
  IF v IS NULL OR v = '' THEN RETURN NULL; END IF;
  RETURN v::pg_catalog.uuid;
EXCEPTION WHEN invalid_text_representation THEN
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION axis.set_tenant(t uuid) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$ SELECT pg_catalog.set_config('axis.tenant_id', t::pg_catalog.text, true) $$;

-- Namespaced two-int advisory key (class 727275) so it cannot collide with other lock users.
-- NOTE: any session can still request this lock; a hostile axis_app can stall audit writes (availability, not integrity).
CREATE OR REPLACE FUNCTION axis.audit_chain_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE head public.audit_events%ROWTYPE;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(727275, pg_catalog.hashtext(NEW.tenant_id::pg_catalog.text));
  SELECT * INTO head FROM public.audit_events WHERE tenant_id = NEW.tenant_id ORDER BY seq DESC LIMIT 1;
  IF NOT FOUND THEN
    IF NEW.seq <> 1 OR NEW.prev_hash <> pg_catalog.repeat('0', 64) THEN
      RAISE EXCEPTION 'audit chain: genesis event must have seq 1 and zero prev_hash' USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.seq <> head.seq + 1 OR NEW.prev_hash <> head.hash THEN
    RAISE EXCEPTION 'audit chain: expected seq % and prev_hash %', head.seq + 1, head.hash USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION axis.forbid_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION '% on % is forbidden: table is append-only', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$;

ALTER FUNCTION axis.enable_tenant_rls(regclass, text, text) SET search_path = pg_catalog, pg_temp;

-- 2. API key prefix must not leak cross-tenant existence. (Auth lookup by prefix needs a dedicated, audited
--    definer path; that is a Phase 6 deliverable, tracked in docs/NEEDS.md.)
ALTER TABLE api_keys DROP CONSTRAINT api_keys_prefix_key;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_tenant_prefix_key UNIQUE (tenant_id, prefix);

-- 3. Gapless run event log: sequence must be head+1 per run.
CREATE FUNCTION axis.run_event_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE head bigint;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(727276, pg_catalog.hashtext(NEW.tenant_id::pg_catalog.text || NEW.run_id::pg_catalog.text));
  SELECT COALESCE(MAX(sequence), 0) INTO head FROM public.run_events WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;
  IF NEW.sequence <> head + 1 THEN
    RAISE EXCEPTION 'run_events: expected sequence %', head + 1 USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER run_events_guard BEFORE INSERT ON run_events FOR EACH ROW EXECUTE FUNCTION axis.run_event_guard();

-- 4. Process/run state: `terminated` is absorbing; identity columns are immutable.
CREATE FUNCTION axis.terminal_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.state = 'terminated' THEN
    RAISE EXCEPTION '% is terminated; no further changes', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER processes_terminal BEFORE UPDATE ON processes FOR EACH ROW EXECUTE FUNCTION axis.terminal_guard();
CREATE TRIGGER runs_terminal BEFORE UPDATE ON runs FOR EACH ROW EXECUTE FUNCTION axis.terminal_guard();

CREATE FUNCTION axis.immutable_columns_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE col text;
BEGIN
  FOREACH col IN ARRAY TG_ARGV LOOP
    IF pg_catalog.to_jsonb(NEW) -> col IS DISTINCT FROM pg_catalog.to_jsonb(OLD) -> col THEN
      RAISE EXCEPTION '%.% is immutable', TG_TABLE_NAME, col USING ERRCODE = 'check_violation';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;
CREATE TRIGGER processes_immutable BEFORE UPDATE ON processes
  FOR EACH ROW EXECUTE FUNCTION axis.immutable_columns_guard('tenant_id', 'pid', 'ppid', 'run_id', 'created_at');
CREATE TRIGGER runs_immutable BEFORE UPDATE ON runs
  FOR EACH ROW EXECUTE FUNCTION axis.immutable_columns_guard('tenant_id', 'id', 'blueprint_name', 'blueprint_version', 'trace_id', 'input', 'idempotency_key', 'created_at');

-- 5. Approvals: only pending/escalated rows can be decided; request fields (incl. SLA and roles) are immutable.
CREATE FUNCTION axis.approval_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.status NOT IN ('pending', 'escalated') THEN
    RAISE EXCEPTION 'approval already %', OLD.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approvals_decided_once BEFORE UPDATE ON approvals FOR EACH ROW EXECUTE FUNCTION axis.approval_guard();
CREATE TRIGGER approvals_immutable BEFORE UPDATE ON approvals
  FOR EACH ROW EXECUTE FUNCTION axis.immutable_columns_guard('tenant_id', 'id', 'run_id', 'pid', 'action', 'roles', 'requested_at', 'sla_deadline');
ALTER TABLE approvals ADD CONSTRAINT approvals_decision_complete
  CHECK ((status IN ('approved', 'rejected')) = (decided_by IS NOT NULL AND decided_at IS NOT NULL));

-- 6. A version row's risk_level must equal the ABL document's riskClassification.level.
ALTER TABLE blueprint_versions ADD CONSTRAINT blueprint_versions_risk_matches_abl
  CHECK (abl #>> '{spec,riskClassification,level}' = risk_level);
