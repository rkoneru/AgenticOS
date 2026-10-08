-- 0016: Compliance records for services/compliance (docs/adr/0070). ADDITIVE: one new table with FORCED RLS, tenant path only.
-- Collections: systems (AI system inventory heads), system_versions (append-only snapshots), assessments (AI impact assessment
-- versions, `<id>@<n>`), documents (generated, sealed technical documentation).
-- Tenant isolation is at the database: a row is visible and writable only when tenant_id = the transaction's tenant (set by the
-- service from the CREDENTIAL). There is no platform path: the service never reads across tenants.
-- Nothing is deleted. Immutability and independence are enforced here, not only in code:
--   system_versions, documents : append-only
--   assessments                : updatable until approved / rejected; an approved or rejected version never changes (a new
--                                version is a new row); an approving / rejecting reviewer is never the author or a contributor.

CREATE TABLE compliance_docs (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  coll        text NOT NULL CHECK (coll IN ('systems', 'system_versions', 'assessments', 'documents')),
  key         text NOT NULL CHECK (length(key) BETWEEN 1 AND 300),
  rev         integer NOT NULL CHECK (rev >= 1),
  data        jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object'),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, coll, key),
  -- Independence of review at the data layer (defence in depth for the service check).
  CONSTRAINT compliance_reviewer_independent CHECK (
    coll <> 'assessments'
    OR data ->> 'state' NOT IN ('approved', 'rejected')
    OR (
      coalesce(data ->> 'reviewed_by', '') <> ''
      AND data ->> 'reviewed_by' IS DISTINCT FROM data ->> 'author'
      AND NOT (coalesce(data -> 'contributors', '[]'::jsonb) ? (data ->> 'reviewed_by'))
    )
  )
);
CREATE INDEX compliance_docs_assessment_idx ON compliance_docs (coll, (data ->> 'assessment_id'));
CREATE INDEX compliance_docs_system_idx ON compliance_docs (coll, (data ->> 'system_id'));

CREATE FUNCTION axis.compliance_docs_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DELETE on compliance_docs is forbidden' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll IN ('system_versions', 'documents') THEN
    RAISE EXCEPTION 'collection % is append-only', OLD.coll USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.coll = 'assessments' AND OLD.data ->> 'state' IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'a reviewed impact assessment version is immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.coll <> OLD.coll OR NEW.key <> OLD.key OR NEW.rev <> OLD.rev + 1 THEN
    RAISE EXCEPTION 'stale or identity-changing update' USING ERRCODE = 'serialization_failure';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER compliance_docs_guard BEFORE UPDATE OR DELETE ON compliance_docs FOR EACH ROW EXECUTE FUNCTION axis.compliance_docs_guard();

ALTER TABLE compliance_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_docs FORCE ROW LEVEL SECURITY;
CREATE POLICY compliance_docs_tenant ON compliance_docs USING (tenant_id = axis.current_tenant()) WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT, UPDATE ON compliance_docs TO axis_app;
