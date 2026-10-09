-- Phase 9 (ADR 0111): the `privacy_officer` role. Additive: every role CHECK constraint that lists the known roles gains the new value.
-- The constraints created inline in 0009 have generated names, so they are found by what they check (a column of the table, listing
-- 'auditor') rather than by name; the old constraint is dropped and an equivalent one with the extra role is added under a stable name.
DO $$
DECLARE
  spec record;
  con  record;
BEGIN
  FOR spec IN
    SELECT * FROM (VALUES
      ('members', 'role', 'members_role_known', false),
      ('directories', 'default_role', 'directories_default_role_known', true),
      ('directory_role_mappings', 'role', 'directory_role_mappings_role_known', true),
      ('identity_connections', 'jit_default_role', 'identity_connections_jit_default_role_known', true)
    ) AS t(tbl, col, new_name, external_only)
  LOOP
    FOR con IN
      SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class r ON r.oid = c.conrelid
       WHERE r.relname = spec.tbl AND c.contype = 'c'
         AND pg_get_constraintdef(c.oid) LIKE '%' || spec.col || '%auditor%'
    LOOP
      EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', spec.tbl, con.conname);
    END LOOP;
    IF spec.external_only THEN
      EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (%I IN (''admin'', ''builder'', ''operator'', ''auditor'', ''viewer'', ''billing'', ''privacy_officer''))',
                     spec.tbl, spec.new_name, spec.col);
    ELSE
      EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (%I IN (''owner'', ''admin'', ''builder'', ''operator'', ''auditor'', ''viewer'', ''billing'', ''privacy_officer''))',
                     spec.tbl, spec.new_name, spec.col);
    END IF;
  END LOOP;
END
$$;

-- The governance service reads a tenant's retention settings and PHI flag (tenants is already readable): the control plane owns them.
GRANT SELECT ON tenant_settings TO axis_governance;
