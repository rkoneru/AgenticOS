-- 0020: blueprint registry for services/registry (docs/adr/0030, 0031). ADDITIVE: new tables only.
-- A namespace is owned by ONE tenant. Everything in it is visible to its owner; once the marketplace lists the namespace in
-- registry_public_namespaces, everything in it is READABLE by every tenant and by anonymous catalog readers (no tenant set).
-- Writes are always the owner's (WITH CHECK tenant_id = current tenant). Versions are immutable and nothing is ever deleted.

CREATE TABLE registry_namespaces (
  namespace   text PRIMARY KEY CHECK (namespace ~ '^[a-z][a-z0-9-]{1,62}$' AND namespace !~ '-$' AND namespace !~ '--'),
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  normalized  text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL,
  created_by  text NOT NULL
);
CREATE TRIGGER registry_namespaces_immutable BEFORE UPDATE OR DELETE ON registry_namespaces
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
ALTER TABLE registry_namespaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_namespaces FORCE ROW LEVEL SECURITY;
-- Namespace names are global (uniqueness, typosquat checks), so existence is readable; contents are protected by their own tables.
CREATE POLICY ns_read ON registry_namespaces FOR SELECT USING (true);
CREATE POLICY ns_insert ON registry_namespaces FOR INSERT WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT ON registry_namespaces TO axis_app;

CREATE TABLE registry_public_namespaces (
  namespace  text PRIMARY KEY REFERENCES registry_namespaces (namespace),
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  listed_at  timestamptz NOT NULL,
  listed_by  text NOT NULL
);
CREATE TRIGGER registry_public_namespaces_immutable BEFORE UPDATE OR DELETE ON registry_public_namespaces
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
ALTER TABLE registry_public_namespaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_public_namespaces FORCE ROW LEVEL SECURITY;
CREATE POLICY pub_read ON registry_public_namespaces FOR SELECT USING (true);
CREATE POLICY pub_insert ON registry_public_namespaces FOR INSERT WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT ON registry_public_namespaces TO axis_app;

-- True when the row belongs to the current tenant or lives in a public namespace. Plain SQL: inlined, evaluated under the caller's RLS.
CREATE FUNCTION axis.registry_visible(ns text, owner uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT owner = axis.current_tenant() OR EXISTS (SELECT 1 FROM public.registry_public_namespaces p WHERE p.namespace = ns)
$$;
GRANT EXECUTE ON FUNCTION axis.registry_visible(text, uuid) TO axis_app;

-- Publisher signing keys. Only two monotonic transitions are allowed: valid_until NULL -> value, revoked_* NULL -> value.
CREATE TABLE registry_keys (
  namespace      text NOT NULL REFERENCES registry_namespaces (namespace),
  key_id         text NOT NULL CHECK (key_id ~ '^k1-[0-9a-f]{32}$'),
  tenant_id      uuid NOT NULL REFERENCES tenants (id),
  public_key     text NOT NULL CHECK (public_key ~ '^[A-Za-z0-9_-]{43}$'),
  valid_from     timestamptz NOT NULL,
  valid_until    timestamptz,
  revoked_at     timestamptz,
  revoke_reason  text CHECK (revoke_reason IN ('retired', 'compromised')),
  created_at     timestamptz NOT NULL,
  created_by     text NOT NULL,
  PRIMARY KEY (namespace, key_id),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
  CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE FUNCTION axis.registry_key_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DELETE on registry_keys is forbidden' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.namespace <> OLD.namespace OR NEW.key_id <> OLD.key_id OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.public_key <> OLD.public_key OR NEW.valid_from <> OLD.valid_from
     OR NEW.created_at <> OLD.created_at OR NEW.created_by <> OLD.created_by THEN
    RAISE EXCEPTION 'registry key identity is immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.valid_until IS NOT NULL AND NEW.valid_until IS DISTINCT FROM OLD.valid_until THEN
    RAISE EXCEPTION 'key validity end is already set' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION 'key is already revoked' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER registry_keys_guard BEFORE UPDATE OR DELETE ON registry_keys FOR EACH ROW EXECUTE FUNCTION axis.registry_key_guard();
ALTER TABLE registry_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY keys_read ON registry_keys FOR SELECT USING (axis.registry_visible(namespace, tenant_id));
CREATE POLICY keys_insert ON registry_keys FOR INSERT WITH CHECK (tenant_id = axis.current_tenant());
CREATE POLICY keys_update ON registry_keys FOR UPDATE USING (tenant_id = axis.current_tenant()) WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT, UPDATE ON registry_keys TO axis_app;

-- Blueprint names. UNIQUE (namespace, normalized) is the typosquat guard (case/hyphen/look-alike-digit collisions).
CREATE TABLE registry_names (
  namespace   text NOT NULL REFERENCES registry_namespaces (namespace),
  name        text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,62}$'),
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  normalized  text NOT NULL,
  created_at  timestamptz NOT NULL,
  PRIMARY KEY (namespace, name),
  UNIQUE (namespace, normalized)
);
CREATE TRIGGER registry_names_immutable BEFORE UPDATE OR DELETE ON registry_names
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
ALTER TABLE registry_names ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_names FORCE ROW LEVEL SECURITY;
CREATE POLICY names_read ON registry_names FOR SELECT USING (axis.registry_visible(namespace, tenant_id));
CREATE POLICY names_insert ON registry_names FOR INSERT WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT ON registry_names TO axis_app;

-- A published version. IMMUTABLE: no update, no delete, primary key = no overwrite. `abl` is the canonical JSON TEXT that was hashed
-- and signed (text, not jsonb: jsonb would renormalise it and the bytes are what the signature covers).
CREATE TABLE registry_versions (
  namespace     text NOT NULL,
  name          text NOT NULL,
  version       text NOT NULL CHECK (length(version) <= 128),
  tenant_id     uuid NOT NULL REFERENCES tenants (id),
  abl           text NOT NULL CHECK (length(abl) <= 1048576),
  content_hash  text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
  risk_level    text NOT NULL CHECK (risk_level IN ('minimal', 'limited', 'high')),
  signature     jsonb NOT NULL,
  provenance    jsonb NOT NULL,
  published_at  timestamptz NOT NULL,
  published_by  text NOT NULL,
  PRIMARY KEY (namespace, name, version),
  FOREIGN KEY (namespace, name) REFERENCES registry_names (namespace, name)
);
CREATE TRIGGER registry_versions_immutable BEFORE UPDATE OR DELETE ON registry_versions
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
ALTER TABLE registry_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY versions_read ON registry_versions FOR SELECT USING (axis.registry_visible(namespace, tenant_id));
CREATE POLICY versions_insert ON registry_versions FOR INSERT WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT ON registry_versions TO axis_app;

-- Yank / deprecate. Append-only: the latest event of a version is its status. Versions are never deleted.
CREATE TABLE registry_version_events (
  seq        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  namespace  text NOT NULL,
  name       text NOT NULL,
  version    text NOT NULL,
  kind       text NOT NULL CHECK (kind IN ('yank', 'deprecate')),
  reason     text NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
  actor      text NOT NULL,
  at         timestamptz NOT NULL,
  FOREIGN KEY (namespace, name, version) REFERENCES registry_versions (namespace, name, version)
);
CREATE INDEX registry_version_events_idx ON registry_version_events (namespace, name, version, seq);
CREATE TRIGGER registry_version_events_immutable BEFORE UPDATE OR DELETE ON registry_version_events
  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();
ALTER TABLE registry_version_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_version_events FORCE ROW LEVEL SECURITY;
CREATE POLICY events_read ON registry_version_events FOR SELECT USING (axis.registry_visible(namespace, tenant_id));
CREATE POLICY events_insert ON registry_version_events FOR INSERT WITH CHECK (tenant_id = axis.current_tenant());
GRANT SELECT, INSERT ON registry_version_events TO axis_app;
GRANT USAGE ON SEQUENCE registry_version_events_seq_seq TO axis_app;
