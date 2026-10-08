-- 0012: a registry version becomes public ONE VERSION AT A TIME (docs/adr/0055). ADDITIVE table + a replacement of three read policies.
-- Before: once the marketplace listed a namespace (migration 0010: registry_public_namespaces) every name, version and yank event in it was
-- readable by every tenant, including blueprints the owner never submitted and versions published after the review. After: the namespace row
-- and its publisher KEYS stay readable once listed (a verifier needs the keys), but a name, a version and its events are readable by a
-- non-owner only when that exact version was released by the marketplace (reviewed, approved, pinned by hash).
CREATE TABLE registry_public_versions (
  namespace  text NOT NULL,
  name       text NOT NULL,
  version    text NOT NULL,
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  listed_at  timestamptz NOT NULL,
  listed_by  text NOT NULL,
  PRIMARY KEY (namespace, name, version),
  FOREIGN KEY (namespace, name, version) REFERENCES registry_versions (namespace, name, version)
);
CREATE TRIGGER registry_public_versions_immutable BEFORE UPDATE OR DELETE ON registry_public_versions
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
ALTER TABLE registry_public_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_public_versions FORCE ROW LEVEL SECURITY;
-- The marker rows name only versions that were released on purpose.
CREATE POLICY pubv_read ON registry_public_versions FOR SELECT USING (true);
CREATE POLICY pubv_insert ON registry_public_versions FOR INSERT WITH CHECK (axis.registry_owns(namespace, tenant_id));
GRANT SELECT, INSERT ON registry_public_versions TO axis_app;

-- Plain SQL, inlined and evaluated under the caller's RLS (like axis.registry_visible).
CREATE FUNCTION axis.registry_version_visible(ns text, nm text, ver text, owner uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT owner = axis.current_tenant()
      OR EXISTS (SELECT 1 FROM public.registry_public_versions p WHERE p.namespace = ns AND p.name = nm AND p.version = ver)
$$;
CREATE FUNCTION axis.registry_name_visible(ns text, nm text, owner uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT owner = axis.current_tenant()
      OR EXISTS (SELECT 1 FROM public.registry_public_versions p WHERE p.namespace = ns AND p.name = nm)
$$;
GRANT EXECUTE ON FUNCTION axis.registry_version_visible(text, text, text, uuid), axis.registry_name_visible(text, text, uuid) TO axis_app;

DROP POLICY names_read ON registry_names;
CREATE POLICY names_read ON registry_names FOR SELECT USING (axis.registry_name_visible(namespace, name, tenant_id));
DROP POLICY versions_read ON registry_versions;
CREATE POLICY versions_read ON registry_versions FOR SELECT USING (axis.registry_version_visible(namespace, name, version, tenant_id));
DROP POLICY events_read ON registry_version_events;
CREATE POLICY events_read ON registry_version_events FOR SELECT USING (axis.registry_version_visible(namespace, name, version, tenant_id));
