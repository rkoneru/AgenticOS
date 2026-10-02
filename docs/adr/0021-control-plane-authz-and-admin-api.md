# 0021. Control plane: authorization on the policy toolchain, internal admin API, tenancy tiers

Status: Accepted · Date: 2026-10-02 · Related: 0004 (Wasm policy), 0020 (schema)
(Number chosen on branch p6/controlplane; the integrating branch renumbers on collision.)

## Context

`services/control-plane` needs RBAC + ABAC that is fail-closed and auditable, a tenant admin API, and a tenant -> connection routing
layer. Contracts are frozen: the OpenAPI `/v1` file has blueprints, runs, approvals, policies, audit, kill-switches, usage and evals
only (no members, API keys, BYO keys, budgets, SSO, SCIM, settings); the policy DSL's enforcement points are the seven agent
points (no `admin`), and its context roots are fixed (`tool`, `args`, `data`, `tenant`, `actor`, ...); the audit event schema
does allow `enforcement_point: "admin"`.

## Decisions

1. **Authorization = the Risk Kernel's toolchain.** `policies/control-plane/pack.yaml` (DSL v1) is compiled by `@axis/policy`,
   built to Wasm with `opa`, and evaluated in-process with `@open-policy-agent/opa-wasm` (same extraction and evaluation as the
   kernel's `engine.ts`). An admin action is modelled as a `tool_call` (`tool.name` = `members.update_role`, `actor.role`,
   `args.same_tenant`, `args.within_ceiling`, `args.owner_is_actor`, `args.environment`, `data.classification`) because the frozen DSL has no
   admin enforcement point; the audit record uses the frozen `admin` point. DENY rules (priority 1000) fire on UNKNOWN data (the
   compiler's three-valued semantics), so a request that omits an attribute is denied. `make policy-test` covers it (73 golden cases).
2. **Defence in depth for the invariants that must not depend on policy text.** Tenant match, role ceiling and API-key scope are also
   computed in code and refuse before the engine is consulted; the policy receives the computed attributes. Last-owner protection is
   enforced in the admin service AND inside both stores (advisory lock + count in Postgres).
3. **Internal `/admin/v1`.** Because `/v1` has no admin paths and is frozen, the admin API is a separate internal surface documented
   in `docs/spec/control-plane.md` with the same conventions (tenant only from the credential, problem+json, cursor paging). Promoting
   it to the public OpenAPI needs a contract change under ADR 0007 (NEEDS #189). `/v1/policies` is not implemented here.
4. **Pre-tenant lookups** use the RLS lookup policies of ADR 0020, not definer functions.
5. **Tenancy tiers.** `shared_rls | dedicated_db | single_tenant_vpc` is recorded in `tenant_placements` (control database) and
   resolved by `TenantRouter` to a connection pool for WORKLOAD data (runs, memory, audit). Control-plane identity data (members, keys,
   sessions, SCIM, SSO) stays in the control database for every tier because it must be resolvable before the tenant is known.
   Fail-closed: no placement or no configured pool for a dedicated tenant never falls back to the shared pool. Deploying dedicated
   databases/VPCs is Phase 10 (NEEDS #188).
6. **Signup is platform-operated.** Self-service e-mail verification is not built; `POST /platform/v1/tenants` needs a platform credential.
7. **Roles.** owner > admin > {builder, operator} > {auditor, billing} > viewer by rank; a caller may grant or modify only roles at or
   below their own rank. An IdP (SCIM, JIT) can never produce `owner`; SCIM never modifies an existing owner's role.

## Consequences

- New package `@axis/control-plane` (dependencies: audit, contracts, db, policy, opa-wasm, pg, yaml); `opa` is needed at process start
  to build the authz bundle (a prebuilt bundle loader is NEEDS #190).
- The in-process Wasm evaluation cannot be pre-empted; the time budget is enforced after the fact (DENY), as in the kernel.
