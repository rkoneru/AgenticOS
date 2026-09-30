# 0006. Tenancy tiers and database-enforced isolation

Status: Accepted (amended by 0008: trust boundaries; `axis_admin` and owner role are planned, not built) · Date: 2026-09-30

## Context

Three tiers: Standard (shared Postgres), Regulated (dedicated DB + node pool), Enterprise dedicated (customer VPC). Isolation must be enforced by the database, not only the app.

## Decision

- **One schema for all tiers.** Every tenant-owned table has `tenant_id uuid NOT NULL`, `ENABLE` and `FORCE ROW LEVEL SECURITY`, and a policy `tenant_id = axis.current_tenant()` for both `USING` and `WITH CHECK`.
- `axis.current_tenant()` reads the transaction-local setting `axis.tenant_id`; unset or malformed returns NULL, so no rows match and inserts fail (**fail-closed**).
- The application connects as `axis_app`, a non-superuser, `NOBYPASSRLS` role that owns nothing. Migrations run as a separate owner role. Services set the tenant with `SELECT axis.set_tenant($1)` (transaction-local) at the start of each transaction.
- A privileged `axis_admin` path (control-plane tenant lifecycle only) is a distinct role and every use is audited.
- `audit_events` is append-only: UPDATE/DELETE/TRUNCATE are blocked by triggers, and `seq`/`prev_hash` continuity is enforced by a trigger.
- A meta-test fails the build if any table with a `tenant_id` column lacks forced RLS and a policy.
- Regulated and dedicated tiers run the _same migrations_ against their own database; RLS stays on as defense in depth.
- Tenant ids are UUIDs; region/residency is a tenant attribute routed at the gateway.

## Consequences

Connection pooling must use transaction-level pooling with `set_config(..., true)`. Session-level settings are forbidden (they leak across pooled clients).
