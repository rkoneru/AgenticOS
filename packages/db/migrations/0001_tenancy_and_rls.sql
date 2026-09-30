-- 0001: extensions, roles, tenancy primitives, RLS helper. See docs/adr/0006.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

-- Application role: no login here (ops grants LOGIN + credentials per environment), never bypasses RLS.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'axis_app') THEN
    CREATE ROLE axis_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS axis;
GRANT USAGE ON SCHEMA axis TO axis_app;

-- Tenant of the current transaction. Unset, empty or malformed => NULL => no rows match (fail-closed).
CREATE FUNCTION axis.current_tenant() RETURNS uuid
LANGUAGE plpgsql STABLE AS $$
DECLARE v text := current_setting('axis.tenant_id', true);
BEGIN
  IF v IS NULL OR v = '' THEN RETURN NULL; END IF;
  RETURN v::uuid;
EXCEPTION WHEN invalid_text_representation THEN
  RETURN NULL;
END $$;

-- Transaction-local only (is_local = true): safe with transaction-level connection pooling.
CREATE FUNCTION axis.set_tenant(t uuid) RETURNS void
LANGUAGE sql AS $$ SELECT set_config('axis.tenant_id', t::text, true) $$;

GRANT EXECUTE ON FUNCTION axis.current_tenant(), axis.set_tenant(uuid) TO axis_app;

-- Forced RLS + one isolation policy on a tenant table, and least-privilege grants to axis_app.
-- `tenant_col` is the column holding the tenant id ('id' for the tenants table itself).
CREATE FUNCTION axis.enable_tenant_rls(tbl regclass, tenant_col text, privileges text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
  EXECUTE format(
    'CREATE POLICY tenant_isolation ON %s USING (%I = axis.current_tenant()) WITH CHECK (%I = axis.current_tenant())',
    tbl, tenant_col, tenant_col);
  EXECUTE format('GRANT %s ON %s TO axis_app', privileges, tbl);
END $$;

-- Generic guard: rows of immutable / append-only tables cannot be updated or deleted.
CREATE FUNCTION axis.forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% on % is forbidden: table is append-only', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TABLE tenants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z][a-z0-9-]{1,62}$'),
  name        text NOT NULL,
  tier        text NOT NULL DEFAULT 'standard' CHECK (tier IN ('standard', 'regulated', 'dedicated')),
  region      text NOT NULL,
  phi_mode    boolean NOT NULL DEFAULT false,
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  created_at  timestamptz NOT NULL DEFAULT now()
);
-- Tenants can be read (own row only) but only the admin path creates/changes them.
SELECT axis.enable_tenant_rls('tenants', 'id', 'SELECT');
