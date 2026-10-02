-- 0008: control plane (identity, sessions, SCIM, key envelope, policy assignment, settings, placement). docs/adr/0018.
-- ADDITIVE: new tables, new nullable/defaulted columns on members and api_keys, narrow lookup policies, one definer function.
-- (Number chosen on branch p6/controlplane; the integrating branch renumbers on collision, together with the version.)
-- Every new tenant table: tenant_id NOT NULL + FORCED RLS via axis.enable_tenant_rls; composite (tenant_id, id) references.

-- 1. members: lifecycle + directory link; role is now a closed set (RBAC roles of docs/spec/control-plane.md).
ALTER TABLE members
  ADD COLUMN status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deprovisioned')),
  ADD COLUMN display_name     text,
  ADD COLUMN external_id      text,
  ADD COLUMN directory_id     uuid,
  ADD COLUMN deprovisioned_at timestamptz,
  ADD COLUMN updated_at       timestamptz NOT NULL DEFAULT now();
ALTER TABLE members ADD CONSTRAINT members_role_known
  CHECK (role IN ('owner', 'admin', 'builder', 'operator', 'auditor', 'viewer', 'billing'));
CREATE UNIQUE INDEX members_tenant_email_key ON members (tenant_id, lower(email));
CREATE UNIQUE INDEX members_tenant_external_key ON members (tenant_id, directory_id, external_id) WHERE external_id IS NOT NULL;

-- 2. api_keys: expiry, usage, ownership (ABAC resource owner) and environment.
ALTER TABLE api_keys
  ADD COLUMN expires_at      timestamptz,
  ADD COLUMN last_used_at    timestamptz,
  ADD COLUMN created_by      uuid,
  ADD COLUMN owner_member_id uuid,
  ADD COLUMN environment     text NOT NULL DEFAULT 'dev' CHECK (environment IN ('dev', 'staging', 'prod')),
  ADD COLUMN rotated_from    uuid;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_hash_len CHECK (octet_length(key_hash) IN (1, 2, 32));

-- Authentication by key happens BEFORE the tenant is known. Instead of a definer function (which a non-superuser owner could not
-- run under FORCED RLS), a second permissive SELECT policy releases a row only to a session that presents BOTH the prefix and
-- the exact hash of the secret (transaction-local settings). Without them the setting is NULL and no row matches. The hash is
-- HMAC-SHA256(pepper, secret): knowing a prefix reveals nothing, and a row cannot be enumerated.
CREATE POLICY api_key_lookup ON api_keys FOR SELECT
  USING (prefix = current_setting('axis.lookup_prefix', true)
     AND key_hash = decode(nullif(current_setting('axis.lookup_hash', true), ''), 'hex'));

-- 3. Sessions: server-side record behind every access token; refresh tokens rotate and a replayed one revokes the session.
CREATE TABLE sessions (
  tenant_id         uuid NOT NULL REFERENCES tenants (id),
  id                uuid NOT NULL DEFAULT gen_random_uuid(),
  member_id         uuid NOT NULL,
  refresh_hash      bytea NOT NULL CHECK (octet_length(refresh_hash) = 32),
  prev_refresh_hash bytea CHECK (prev_refresh_hash IS NULL OR octet_length(prev_refresh_hash) = 32),
  counter           integer NOT NULL DEFAULT 0,
  auth_method       text NOT NULL CHECK (auth_method IN ('sso', 'dev')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  expires_at        timestamptz NOT NULL,
  refreshed_at      timestamptz NOT NULL DEFAULT now(),
  revoked_at        timestamptz,
  revoked_reason    text,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, member_id) REFERENCES members (tenant_id, id)
);
CREATE INDEX sessions_member_idx ON sessions (tenant_id, member_id) WHERE revoked_at IS NULL;
SELECT axis.enable_tenant_rls('sessions', 'tenant_id', 'SELECT, INSERT, UPDATE');

-- 4. Directories (SCIM / directory sync): one bearer token per directory, hash only, found before the tenant is known (same lookup policy).
CREATE TABLE directories (
  tenant_id        uuid NOT NULL REFERENCES tenants (id),
  id               uuid NOT NULL DEFAULT gen_random_uuid(),
  name             text NOT NULL,
  idp_directory_id text,
  token_prefix     text NOT NULL,
  token_hash       bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  default_role     text NOT NULL DEFAULT 'viewer' CHECK (default_role IN ('admin', 'builder', 'operator', 'auditor', 'viewer', 'billing')),
  status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  revoked_at       timestamptz,
  last_used_at     timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_prefix)
);
SELECT axis.enable_tenant_rls('directories', 'tenant_id', 'SELECT, INSERT, UPDATE');
CREATE POLICY directory_lookup ON directories FOR SELECT
  USING (token_prefix = current_setting('axis.lookup_prefix', true)
     AND token_hash = decode(nullif(current_setting('axis.lookup_hash', true), ''), 'hex'));

CREATE TABLE scim_groups (
  tenant_id     uuid NOT NULL REFERENCES tenants (id),
  id            uuid NOT NULL DEFAULT gen_random_uuid(),
  directory_id  uuid NOT NULL,
  display_name  text NOT NULL,
  external_id   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, directory_id, display_name),
  FOREIGN KEY (tenant_id, directory_id) REFERENCES directories (tenant_id, id)
);
SELECT axis.enable_tenant_rls('scim_groups', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');

CREATE TABLE scim_group_members (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  group_id   uuid NOT NULL,
  member_id  uuid NOT NULL,
  PRIMARY KEY (tenant_id, group_id, member_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES scim_groups (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, member_id) REFERENCES members (tenant_id, id)
);
SELECT axis.enable_tenant_rls('scim_group_members', 'tenant_id', 'SELECT, INSERT, DELETE');

-- Group display name -> role, configured by a tenant admin (never by the IdP): SCIM cannot mint roles, and never `owner`.
CREATE TABLE directory_role_mappings (
  tenant_id     uuid NOT NULL REFERENCES tenants (id),
  directory_id  uuid NOT NULL,
  group_name    text NOT NULL,
  role          text NOT NULL CHECK (role IN ('admin', 'builder', 'operator', 'auditor', 'viewer', 'billing')),
  PRIMARY KEY (tenant_id, directory_id, group_name),
  FOREIGN KEY (tenant_id, directory_id) REFERENCES directories (tenant_id, id)
);
SELECT axis.enable_tenant_rls('directory_role_mappings', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');

-- 5. SSO: the IdP organization/connection a tenant owns, and the e-mail domains it has verified (JIT provisioning only for those).
CREATE TABLE identity_connections (
  tenant_id          uuid NOT NULL REFERENCES tenants (id),
  id                 uuid NOT NULL DEFAULT gen_random_uuid(),
  idp_org_id         text NOT NULL,
  idp_connection_id  text,
  connection_type    text NOT NULL CHECK (connection_type IN ('saml', 'oidc')),
  jit_enabled        boolean NOT NULL DEFAULT false,
  jit_default_role   text NOT NULL DEFAULT 'viewer' CHECK (jit_default_role IN ('admin', 'builder', 'operator', 'auditor', 'viewer', 'billing')),
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (idp_org_id)
);
SELECT axis.enable_tenant_rls('identity_connections', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');
CREATE POLICY identity_connection_lookup ON identity_connections FOR SELECT
  USING (idp_org_id = current_setting('axis.lookup_idp_org', true));

CREATE TABLE verified_domains (
  tenant_id         uuid NOT NULL REFERENCES tenants (id),
  domain            text NOT NULL CHECK (domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'),
  status            text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified')),
  challenge_hash    bytea,
  created_at        timestamptz NOT NULL DEFAULT now(),
  verified_at       timestamptz,
  PRIMARY KEY (tenant_id, domain),
  CHECK ((status = 'verified') = (verified_at IS NOT NULL))
);
-- A domain verifies for at most one tenant, platform wide.
CREATE UNIQUE INDEX verified_domains_one_owner ON verified_domains (domain) WHERE status = 'verified';
SELECT axis.enable_tenant_rls('verified_domains', 'tenant_id', 'SELECT, INSERT, UPDATE, DELETE');

-- 6. Envelope encryption. One data key per tenant (wrapped by the KMS; the plaintext key never reaches Postgres) and the
-- ciphertext of each BYO model secret. `secret_ref` (0002) now points at the row itself ('cp:<id>').
CREATE TABLE tenant_keys (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  version      integer NOT NULL CHECK (version >= 1),
  kms_key_id   text NOT NULL,
  wrapped_dek  bytea NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  retired_at   timestamptz,
  PRIMARY KEY (tenant_id, version)
);
SELECT axis.enable_tenant_rls('tenant_keys', 'tenant_id', 'SELECT, INSERT, UPDATE');
ALTER TABLE model_credentials
  ADD COLUMN key_version integer,
  ADD COLUMN nonce       bytea,
  ADD COLUMN ciphertext  bytea,
  ADD COLUMN created_by  uuid,
  ADD COLUMN rotated_at  timestamptz;

-- 7. Policy pack assignment: which immutable pack version is in force for the tenant. One active version per pack.
CREATE TABLE policy_assignments (
  tenant_id       uuid NOT NULL REFERENCES tenants (id),
  id              uuid NOT NULL DEFAULT gen_random_uuid(),
  pack_id         uuid NOT NULL,
  version_id      uuid NOT NULL,
  active          boolean NOT NULL DEFAULT true,
  activated_by    text NOT NULL,
  activated_at    timestamptz NOT NULL DEFAULT now(),
  deactivated_at  timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, pack_id) REFERENCES policy_packs (tenant_id, id),
  FOREIGN KEY (tenant_id, version_id) REFERENCES policy_pack_versions (tenant_id, id),
  CHECK (active = (deactivated_at IS NULL))
);
CREATE UNIQUE INDEX policy_assignments_one_active ON policy_assignments (tenant_id, pack_id) WHERE active;
SELECT axis.enable_tenant_rls('policy_assignments', 'tenant_id', 'SELECT, INSERT, UPDATE');

-- 8. Tenant settings (retention) and placement (isolation tier). Region itself is tenants.region (read-only to the app role).
CREATE TABLE tenant_settings (
  tenant_id                 uuid PRIMARY KEY REFERENCES tenants (id),
  retention_audit_days      integer NOT NULL DEFAULT 2555 CHECK (retention_audit_days BETWEEN 365 AND 3650),
  retention_transcript_days integer NOT NULL DEFAULT 30 CHECK (retention_transcript_days BETWEEN 1 AND 3650),
  retention_memory_days     integer NOT NULL DEFAULT 365 CHECK (retention_memory_days BETWEEN 1 AND 3650),
  updated_at                timestamptz NOT NULL DEFAULT now(),
  updated_by                text
);
SELECT axis.enable_tenant_rls('tenant_settings', 'tenant_id', 'SELECT, INSERT, UPDATE');

CREATE TABLE tenant_placements (
  tenant_id       uuid PRIMARY KEY REFERENCES tenants (id),
  isolation_tier  text NOT NULL DEFAULT 'shared_rls' CHECK (isolation_tier IN ('shared_rls', 'dedicated_db', 'single_tenant_vpc')),
  pool_key        text,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK ((isolation_tier = 'shared_rls') = (pool_key IS NULL))
);
SELECT axis.enable_tenant_rls('tenant_placements', 'tenant_id', 'SELECT, INSERT, UPDATE');

-- 9. Signup. Only this function creates a tenant (axis_app has SELECT on tenants). It sets the tenant for the transaction so the
-- FORCED policy's WITH CHECK passes even for a non-superuser owner. Slug collisions raise unique_violation to the caller.
CREATE FUNCTION axis.provision_tenant(p_id uuid, p_slug text, p_name text, p_region text, p_phi boolean)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM pg_catalog.set_config('axis.tenant_id', p_id::pg_catalog.text, true);
  INSERT INTO public.tenants (id, slug, name, region, phi_mode) VALUES (p_id, p_slug, p_name, p_region, p_phi);
  RETURN p_id;
END $$;
REVOKE ALL ON FUNCTION axis.provision_tenant(uuid, text, text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axis.provision_tenant(uuid, text, text, text, boolean) TO axis_app;
