-- 0021: marketplace documents for services/marketplace (docs/adr/0031). ADDITIVE: one new table + two helper functions.
-- Collections (publishers, evidence, listings, reviews, events, installs, takedowns, baselines, metering) share one table with FORCED RLS.
-- Three read/write paths, all explicit in code and all visible here:
--   tenant    : tenant_id = current tenant (set per transaction by the service from the CREDENTIAL, never from a request)
--   platform  : axis.platform = 'on' (set ONLY by the reviewer/moderator/catalog code paths of the marketplace service)
--   catalog   : SELECT of listings whose status is 'listed' (anonymous catalog reads set neither tenant nor platform)
-- Nothing is deleted. Append-only collections (events, evidence, takedowns) also forbid UPDATE.

CREATE FUNCTION axis.is_platform() RETURNS boolean
LANGUAGE sql STABLE AS $$ SELECT coalesce(current_setting('axis.platform', true), '') = 'on' $$;
CREATE FUNCTION axis.set_platform(on_ boolean) RETURNS void
LANGUAGE sql AS $$ SELECT set_config('axis.platform', CASE WHEN on_ THEN 'on' ELSE 'off' END, true) $$;
GRANT EXECUTE ON FUNCTION axis.is_platform(), axis.set_platform(boolean) TO axis_app;

CREATE TABLE marketplace_docs (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  coll        text NOT NULL CHECK (coll ~ '^[a-z_]{1,40}$'),
  key         text NOT NULL CHECK (length(key) BETWEEN 1 AND 300),
  rev         integer NOT NULL CHECK (rev >= 1),
  data        jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object'),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, coll, key)
);
CREATE INDEX marketplace_docs_state_idx ON marketplace_docs (coll, (data ->> 'state'));
CREATE INDEX marketplace_docs_listing_idx ON marketplace_docs (coll, (data ->> 'namespace'), (data ->> 'name'));

CREATE FUNCTION axis.marketplace_docs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DELETE on marketplace_docs is forbidden' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll IN ('events', 'evidence', 'takedowns') THEN
    RAISE EXCEPTION 'collection % is append-only', OLD.coll USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.coll <> OLD.coll OR NEW.key <> OLD.key OR NEW.rev <> OLD.rev + 1 THEN
    RAISE EXCEPTION 'stale or identity-changing update' USING ERRCODE = 'serialization_failure';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER marketplace_docs_guard BEFORE UPDATE OR DELETE ON marketplace_docs FOR EACH ROW EXECUTE FUNCTION axis.marketplace_docs_guard();

ALTER TABLE marketplace_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE marketplace_docs FORCE ROW LEVEL SECURITY;
CREATE POLICY docs_tenant ON marketplace_docs USING (tenant_id = axis.current_tenant()) WITH CHECK (tenant_id = axis.current_tenant());
CREATE POLICY docs_platform ON marketplace_docs USING (axis.is_platform()) WITH CHECK (axis.is_platform());
CREATE POLICY docs_catalog ON marketplace_docs FOR SELECT USING (coll = 'listings' AND data ->> 'status' = 'listed');
GRANT SELECT, INSERT, UPDATE ON marketplace_docs TO axis_app;
