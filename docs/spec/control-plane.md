# Control plane (Phase 6 / A)

`services/control-plane` (`@axis/control-plane`). Status: **Prototype**. Built and tested against fakes (IdP, KMS, DNS) and a real
Postgres 16; no real WorkOS, KMS or DNS. Wired end to end with the Risk Kernel, the runtime and billing in `make e2e-phase6`
(ADR 0022, `docs/runbooks/saas-e2e.md`). See `docs/NEEDS.md` #179-#195 and #197-#205, ADRs 0020-0022 and the threat model
`docs/security/control-plane-threat-model.md`.

## 1. Surfaces

| Surface                                   | Auth                                                    | Notes                                                                             |
| ----------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `GET /auth/sso/start?org=&return_to=`     | none                                                    | 302 to the IdP; sets `__Host-axis_login`                                          |
| `GET /auth/sso/callback?code=&state=`     | login cookie                                            | validates state, PKCE, nonce, org; sets session cookies; 302 to a safe return URL |
| `POST /auth/refresh`, `POST /auth/logout` | refresh token (cookie + CSRF header, or body) / session | rotating refresh                                                                  |
| `/admin/v1/*`                             | session token, session cookie (+CSRF), or API key       | tenant admin; tenant from the credential only                                     |
| `/scim/v2/*`                              | per-directory bearer token                              | SCIM 2.0 Users, Groups, ServiceProviderConfig                                     |
| `POST /hooks/idp`                         | directory bearer token + `x-idp-signature`              | IdP directory-sync events                                                         |
| `POST /platform/v1/tenants`               | platform token                                          | tenant signup (platform-operated, NEEDS #185)                                     |
| `POST /dev/session`                       | dev token                                               | DEV ONLY: session for a named member                                              |
| `POST /internal/v1/model-keys/reveal`     | per-tenant runtime token                                | DEV ONLY runtime bridge (section 7)                                               |
| `GET /internal/v1/budget-config`          | per-tenant runtime token                                | DEV ONLY: the tenant's budgets for the TKI ledger (section 5)                     |

Errors on `/admin/v1` are `application/problem+json` `{type, title, status, code, detail}`; codes: `unauthenticated` 401, `forbidden` 403,
`not_found` 404, `conflict` 409, `invalid` 422, `region_mismatch` 421, `unavailable` 503, `internal` 500 (opaque), `too_large` 413.
SCIM errors are RFC 7644 `urn:ietf:params:scim:api:messages:2.0:Error` with `scimType`. A body that contains `tenant_id`/`tenantId` is rejected (422).

## 2. Identity

`IdentityProvider` (WorkOS-shaped): `authorizationUrl`, `exchangeCode -> {id, email, emailVerified, organizationId, connectionType saml|oidc, nonce?}`,
`parseDirectoryEvent` (signature verified), `adminPortalLink`. `FakeIdentityProvider` enforces one-shot codes, redirect-URI match and PKCE S256.

SSO login: `begin` seals {state, nonce, PKCE verifier, org, safe return_to, exp} (AES-256-GCM) into `__Host-axis_login`
(`HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`; Lax because the IdP redirect is a cross-site top-level navigation). `callback` requires the
cookie to unseal (tampering, a foreign key, an expired or replayed attempt are refused), the `state` parameter to equal the sealed state
(login CSRF), the IdP exchange to succeed with our verifier, the asserted organization to equal the requested one, the nonce to match
(an OIDC connection that returns none is refused), and the connection type to match. Then the member is found by `idp:<id>` or by a
**verified** e-mail; otherwise JIT, which requires the connection's JIT flag, a verified e-mail, a domain the tenant verified
(`_axis-challenge.<domain>` TXT `axis-verify=<token>`, hash stored, exclusive across tenants, public mail domains refused) and assigns the connection's
configured non-owner role. `return_to` is a same-site path or an allow-listed origin; `//host`, `/\host`, other schemes and credentials fall back to `/`.
Every outcome is audited in the tenant chain (`auth.sso_login`, `members.jit_provision`).

Sessions: access token `kid.payload.HMAC` (default 15 min, never beyond the session), valid only with a live `sessions` row (the server-side
revocation list) for an ACTIVE member; the role is read from the member on every request. Refresh token `axr.<tenant>.<session>.<secret>` stored
as HMAC(pepper, secret), rotated on use; presenting a rotated token revokes the session. Absolute lifetime default 8 h. Cookies:
`__Host-axis_at`, `__Host-axis_rt` (`HttpOnly; Secure; SameSite=Strict; Path=/`), `__Host-axis_csrf` (readable; double-submit for cookie-authenticated unsafe methods via `x-axis-csrf`).

## 3. SCIM 2.0

Per-directory bearer token (`axs_<16 hex>_<43>`, HMAC stored, rotate/revoke). Users: GET (list, `filter`, `startIndex`, `count`), GET id, POST, PUT, PATCH,
DELETE. Groups likewise. Filter subset: `eq ne co sw pr` over `userName, externalId, emails.value, displayName, active, id`, joined by `and`; anything else is `invalidFilter`.
PATCH: `add|replace|remove`, with or without `path` (Azure-style `path:"active", value:"False"` and Okta-style `{value:{active:false}}`).
Mapping: SCIM user = member (`directory_id`, `external_id`); a directory sees and changes only members it provisioned (an id of another directory or tenant is 404).
Role = highest of the directory's default role and the roles the tenant admin mapped to the user's groups (`directory_role_mappings`); never `owner`; an owner's role is never changed by SCIM.
**Deprovisioning** (`active:false`, PUT inactive, DELETE, or an IdP `user.deleted`/inactive event) sets the member `deprovisioned` and revokes every session and every API key owned by
the member before the call returns. Deprovisioning the last owner is refused (409) but its sessions and keys are still revoked. DELETE is a soft delete (a later GET returns the resource with `active:false`; RFC 7644 says 404: documented deviation).

## 4. Authorization

Roles (rank): owner 100, admin 80, builder 50, operator 50, auditor 40, billing 40, viewer 10. Actions are `<resource>.<verb>` (see `ACTIONS` in `src/authz.ts`).
Policy request (DSL context): `enforcement_point: tool_call`, `tool.name = action`, `tool.side_effects = read|write`, `actor.{id, role, credential: session|api_key}`, `tenant.id`,
`args.{same_tenant, within_ceiling, owner_is_actor, environment}`, `data.classification`. ABAC in the pack: cross-tenant, role ceiling, unknown role, API keys on session-only actions,
`restricted` data only for owner/admin/auditor, builders/operators cannot write `prod` resources, builders/operators can rotate/revoke/write only keys they own.
API-key credentials additionally need a scope `<resource>:read|write` (or `*`, `<resource>:*`); the effective permission is role AND scope. Fail-closed: no policy, evaluation error,
over-budget evaluation, malformed result or anything but an exact `ALLOW` is DENY. Hard invariants (tenant, ceiling, scope) are also checked in code before the engine.

Every `/admin/v1` operation: region pin (mutations) -> authorize -> audit the decision (mutations: ALLOW and DENY; reads: DENY) -> perform -> audit the result (`<action>.result`).
A mutation whose decision cannot be appended to the tenant's chain is not performed (503). Audit events: `enforcement_point: admin`, actor = member, `inputs_hash`/`outputs_hash` over non-secret metadata, `reason` = `key=value`.
Id-based operations resolve the resource inside the caller's tenant; a missing or foreign id is 404 for a caller who may perform the action and 403 for one who may not (no existence oracle).

## 5. `/admin/v1` routes

`GET /tenant` · `GET|POST /members`, `GET|PATCH|DELETE /members/{id}`, `POST /members/{id}/revoke-sessions` · `GET|POST /api-keys`, `POST /api-keys/{id}/rotate`, `DELETE /api-keys/{id}` (revoke) ·
`GET /model-keys`, `PUT|DELETE /model-keys/{provider}/{label}` · `GET|POST /policies`, `POST /policies/{versionId}/activate`, `DELETE /policies/{pack}` ·
`GET|PUT /budgets`, `DELETE /budgets/{id}` · `GET|PATCH /settings` (retention) · `GET|POST /directories`, `POST /directories/{id}/rotate-token`, `PUT /directories/{id}/role-mappings`, `DELETE /directories/{id}` ·
`PUT /sso/connection`, `POST /sso/portal-link` · `GET|POST /domains`, `POST /domains/{domain}/verify` · `GET /audit/events`.

API keys: `axk_<16 hex prefix>_<43 char secret>` (256-bit random), only HMAC-SHA256(pepper, key) stored, shown once; scopes, expiry (default 90 d, max 365), environment, owner, `last_used_at` (write rate bounded),
rotate (new key + old revoked), revoke; verification = format, exact (prefix, HMAC) lookup under the 0009 lookup policy, constant-time compare, revoked/expired/owner-active checks; every failure is the same 401.
Policy packs: versioned, immutable; publish compiles with `opa check --strict` and a Wasm build; activation re-validates the whole prospective active set, is audited, and baseline-deny can never be deactivated;
new tenants get baseline-deny active. **Kernel delivery (DEV, ADR 0022):** with a `bundleSink` configured, signup and every activation/deactivation
compile the tenant's active set to a Wasm bundle and write it to `<dir>/<tenant uuid>.tar.gz`; the kernel dev process (`AXIS_POLICY_BUNDLE_DIR`) serves each
tenant its own bundle and DENIES a tenant with no loadable bundle (NEEDS #197). A publication failure after a committed activation is a 503 (the kernel keeps its previous bundle; re-activating republishes).
Budgets: tenant/agent/run, soft <= hard, fractional values allowed (`cost_usd`); `AdminService.budgetConfig(tenantId)` is served to the runtime at
`GET /internal/v1/budget-config` and applied to the TKI ledger by `runtime/.../tenant_budgets.py` (tenant account limits; run limits merged with the blueprint's, the tighter wins).
The kernel's `budget` gate and agent-scope budgets are not fed from it (NEEDS #198).
Retention: audit >= 365 d and never shortened, transcripts and memory 1-3650 d. Region pinning: `tenants.region` is fixed at signup; a control plane instance refuses writes (421) for tenants of another region (real multi-region is NEEDS #192).

## 6. Tenancy tiers

`tenant_placements`: `shared_rls | dedicated_db | single_tenant_vpc` (+ `pool_key`). `TenantRouter.resolve(tenantId) -> {tier, pool}`; dedicated pools come from configuration, never from a request;
fail-closed (no placement, missing pool, aliasing the shared pool, a placement lookup error). Tested with two real databases (data written through the router lands only in its database; the other tier sees nothing).
Identity data stays in the control database (ADR 0021). Deployment of dedicated infrastructure: Phase 10 (NEEDS #188).

## 7. BYO model keys and the runtime

One AES-256 data key per tenant, wrapped by a `Kms` (`LocalKms` is the fake; tenant bound as context); each secret AES-256-GCM with AAD `axis-byo:<tenant>:<provider>:<label>`. Plaintext is never stored, returned by `/admin/v1`,
audited or put in an error. Runtime path (DEV, non-production): `POST /internal/v1/model-keys/reveal` with `Authorization: Bearer <per-tenant runtime token>` and `{"provider","label"}` -> `{"value"}`;
the tenant is the one the token was issued for. The runtime reads it through `HttpSecretStore` (`runtime/src/axis_runtime/models/secrets_http.py` over `controlplane.ControlPlaneBridge`); production reads through KMS (NEEDS #186).

## 8. Configuration (`wireControlPlane`)

`store` (Memory or `PgControlPlaneStore`, connecting as `axis_app`), `auditSink` (+`auditReader`), `authorizer` (`Authorizer.fromPackFile()` needs `opa`), `idp`, `kms`, `dns`, `region`/`regions`,
`secrets.{pepper, cookieKey, signingKeys[]}` (each >= 32 bytes; rotate signing keys by prepending a new `kid`), `redirectUri`, `allowedReturnOrigins`, optional `platformToken`, `devToken`, `runtimeAuth`, `bundleSink` (DEV: `FileBundleSink(dir)`).
`RoutedAuditLog({router, open})` is an `AuditSink` + reader that sends each tenant's events to the database its placement names (use it as `auditSink`/`auditReader` when dedicated tiers exist).
