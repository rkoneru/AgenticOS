-- Phase 9 (ADR 0111): the data-governance service resolves a tenant's retention periods from tenant_settings. 0015 granted it
-- tenants but not tenant_settings; without this the retention engine could not read the periods and would purge nothing.
-- Read only, and forced RLS still applies (the role has no BYPASSRLS): one tenant at a time.
GRANT SELECT ON tenant_settings TO axis_governance;
