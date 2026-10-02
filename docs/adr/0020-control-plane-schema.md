# 0020. Control plane schema (migration 0009) and authentication lookups

Status: Accepted · Date: 2026-10-02 · Amends: 0007 (post-freeze addition, same procedure as 0008, 0010, 0013, 0015)
(Number chosen on branch p6/controlplane; the integrating branch renumbers on collision, together with the migration version.)

## Context

Phase 6 component A (`services/control-plane`) needs sessions, SCIM directories, SSO connections, verified domains, envelope-encrypted
BYO keys, policy pack assignment, settings and placement. Migrations 0001-0007 have `members`, `api_keys`, `model_credentials`,
`policy_packs(+versions)` and `budgets`, but no session, directory, key-envelope, assignment, settings or placement tables.
Contracts stay frozen (the OpenAPI `/v1` file has no admin paths; see ADR 0021).

## Decision

Additive migration `0009_control_plane.sql`. New tenant tables with FORCED RLS and composite `(tenant_id, id)` references:
`sessions`, `directories`, `scim_groups`, `scim_group_members`, `directory_role_mappings`, `identity_connections`, `verified_domains`,
`tenant_keys`, `policy_assignments`, `tenant_settings`, `tenant_placements`. Added columns: `members` (status, display_name,
external_id, directory_id, deprovisioned_at, updated_at; role CHECK limited to the seven RBAC roles; unique case-insensitive e-mail),
`api_keys` (expires_at, last_used_at, created_by, owner_member_id, environment, rotated_from), `model_credentials` (key_version,
nonce, ciphertext, created_by, rotated_at).

Pre-tenant lookups (the 0004 note on API key prefix): authentication happens before the tenant is known (API key, SCIM bearer token,
IdP organization). Rather than a SECURITY DEFINER function (a non-superuser owner is itself subject to FORCED RLS), each of
`api_keys`, `directories` and `identity_connections` gets a second permissive SELECT policy that releases a row only when the session
sets transaction-local `axis.lookup_prefix` AND `axis.lookup_hash` equal to the row (HMAC-SHA256 of the secret under a service
pepper), or `axis.lookup_idp_org` equal to the organization id. Unset settings are NULL and match nothing. A row cannot be
enumerated, and knowing a prefix reveals nothing.

Signup: the only function is `axis.provision_tenant` (SECURITY DEFINER, pinned search_path, EXECUTE to axis_app only). It sets the
tenant for the transaction so the WITH CHECK of the FORCED policy passes. Everything else about a new tenant is inserted by the app
role under that tenant.

## Consequences

- `packages/db` tests: seed covers every new table; `control-plane.test.ts` proves the lookup policies and `provision_tenant`.
- Region is `tenants.region` (read-only for axis_app). A region move is a migration procedure, not an API (NEEDS).
- `FREEZE.json` regenerated; no frozen file was edited.
