-- 0013: Eval Hub documents for services/eval-hub (docs/adr/0056). ADDITIVE: one new table with FORCED RLS, tenant path only.
-- Collections: datasets, suites, runners, runs, baselines, tasks (human review), sampling, online, events.
-- Tenant isolation is at the database: a row is visible and writable only when tenant_id = the transaction's tenant (set by the
-- service from the CREDENTIAL). There is no platform path: the hub never reads across tenants.
-- Nothing is deleted. Immutability is enforced here, not only in code:
--   datasets, suites, baselines, online, events : append-only
--   runs    : updatable only while queued/running (a finished run, and so its scores, can never change)
--   runners : revocation is one-way
--   tasks   : updatable until resolved

CREATE TABLE eval_hub_docs (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  coll        text NOT NULL CHECK (coll ~ '^[a-z_]{1,40}$'),
  key         text NOT NULL CHECK (length(key) BETWEEN 1 AND 300),
  rev         integer NOT NULL CHECK (rev >= 1),
  data        jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object'),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, coll, key)
);
CREATE INDEX eval_hub_docs_run_idx ON eval_hub_docs (coll, (data ->> 'suite_ref'), (data ->> 'content_hash'));
CREATE INDEX eval_hub_docs_state_idx ON eval_hub_docs (coll, (data ->> 'status'));

CREATE FUNCTION axis.eval_hub_docs_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DELETE on eval_hub_docs is forbidden' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll IN ('datasets', 'suites', 'baselines', 'online', 'events') THEN
    RAISE EXCEPTION 'collection % is append-only', OLD.coll USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll = 'runs' AND OLD.data ->> 'status' NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'a finished eval run is immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll = 'runners' AND OLD.data ->> 'revoked_at' IS NOT NULL THEN
    RAISE EXCEPTION 'a revoked runner stays revoked' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll = 'tasks' AND OLD.data ->> 'state' = 'resolved' THEN
    RAISE EXCEPTION 'a resolved review task is immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.coll <> OLD.coll OR NEW.key <> OLD.key OR NEW.rev <> OLD.rev + 1 THEN
    RAISE EXCEPTION 'stale or identity-changing update' USING ERRCODE = 'serialization_failure';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER eval_hub_docs_guard BEFORE UPDATE OR DELETE ON eval_hub_docs FOR EACH ROW EXECUTE FUNCTION axis.eval_hub_docs_guard();

ALTER TABLE eval_hub_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE eval_hub_docs FORCE ROW LEVEL SECURITY;
CREATE POLICY eval_docs_tenant ON eval_hub_docs USING (tenant_id = axis.current_tenant()) WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT, UPDATE ON eval_hub_docs TO axis_app;
