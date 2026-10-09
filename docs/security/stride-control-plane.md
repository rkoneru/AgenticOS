# STRIDE: Control plane

Status: Prototype (fakes for IdP, KMS, DNS; real Postgres). Earlier model with 15 numbered threats: [control-plane-threat-model.md](control-plane-threat-model.md).

## Assets

- Tenant isolation, admin privileges and role ceilings.
- Credentials: sessions, API keys, SCIM tokens, BYO model keys, signing keys.
- Policy packs and bundles (what the kernel enforces), budgets, residency settings.
- The audit entries of every admin change.

## Trust boundaries

1. HTTP caller (untrusted) to the control plane: authentication (session cookie, API key, SCIM token, platform credential) then a fail-closed authorizer (`services/control-plane/src/authz.ts`, `services/control-plane/src/http.ts`).
2. IdP (trusted for identity assertions of its organization) to SSO callbacks (`services/control-plane/src/sso.ts`).
3. Control plane to Postgres: FORCED RLS and a tenant router (`services/control-plane/src/pg-store.ts`, `services/control-plane/src/routing.ts`).
4. Control plane to the runtime (BYO key reveal, budgets) and to the kernel (policy bundles) over dev bridges (`services/control-plane/src/runtime-bridge.ts`, `services/control-plane/src/bundles.ts`).

## Data flow

Signup/SSO -> member and session -> API call -> authorizer (OPA pack per action, role rank, key scopes) -> audit append of the decision -> mutation. Policy publish: compile, `opa check`, Wasm build, immutable version, activation re-validates the set, bundle sink writes the tenant bundle for the kernel.

## STRIDE

| Category               | Threat                                                  | Mitigation (code path)                                                                                                                                                     | Test                                                                                          | Residual / NEEDS                                                                                                    |
| ---------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Spoofing               | Session theft or replay                                 | Short access token, server-side session row, rotating refresh with reuse revocation, `__Host-` cookies, CSRF double submit (`services/control-plane/src/sessions.ts`)      | `services/control-plane/test/sessions.test.ts`                                                | No device binding (NEEDS #193)                                                                                      |
| Spoofing               | Login CSRF, code injection, open redirect               | Sealed one-shot login cookie, state, PKCE S256, nonce, exact redirect URI (`services/control-plane/src/sso.ts`)                                                            | `services/control-plane/test/sso.test.ts`                                                     | Spent-state set per process (NEEDS #187)                                                                            |
| Spoofing               | API key guessing                                        | 256-bit keys, HMAC storage with pepper, constant-time compare, one answer for every failure (`services/control-plane/src/apikeys.ts`)                                      | `services/control-plane/test/apikeys.test.ts`, `e2e/redteam_probes.py`                        | No rate limiting or lockout (NEEDS #194)                                                                            |
| Tampering              | Policy tampering or a broken pack activated             | Versions immutable, compile + opa check + Wasm build before publish, set re-validated at activation, baseline irremovable (`services/control-plane/src/policies.ts`)       | `services/control-plane/test/policies.test.ts`                                                | A tenant can publish a permissive pack of its own (by design); bundle delivery is a dev file mechanism (NEEDS #197) |
| Tampering              | A role escalation or a last-owner removal               | Rank ceiling in code and policy, last-owner guard in service and stores (`services/control-plane/src/roles.ts`, `services/control-plane/src/admin.ts`)                     | `services/control-plane/test/admin.test.ts`, `services/control-plane/test/properties.test.ts` | Owners can appoint owners by design                                                                                 |
| Repudiation            | An admin change without a record                        | Decision appended to the tenant chain before the mutation, append failure is 503 and no change (`services/control-plane/src/audit.ts`)                                     | `services/control-plane/test/admin.test.ts`                                                   | Audit and mutation are not one transaction                                                                          |
| Information disclosure | BYO key disclosure                                      | Per-tenant data key under a KMS with tenant-bound context, no read-back API (`services/control-plane/src/modelkeys.ts`, `services/control-plane/src/kms.ts`)               | `services/control-plane/test/modelkeys.test.ts`                                               | KMS is a local fake (NEEDS #183); the runtime reveal is a dev HTTP endpoint (NEEDS #186)                            |
| Information disclosure | Cross-tenant access by id (IDOR), tenant in body/header | Tenant only from the credential, every store call takes it, FORCED RLS, foreign ids are 404 (`services/control-plane/src/tenancy.ts`)                                      | `services/control-plane/test/tenancy.test.ts`, `e2e/redteam_probes.py`                        | none known                                                                                                          |
| Denial of service      | Unauthenticated endpoint abuse                          | Cheap rejections, body size cap (`services/control-plane/src/http.ts`)                                                                                                     | `services/control-plane/test/http.test.ts`                                                    | No rate limiting (NEEDS #194)                                                                                       |
| Elevation of privilege | Authorization bypass by failure                         | Fail-closed `Authorizer`: no policy, error, timeout, malformed or non-ALLOW is DENY (`services/control-plane/src/authz.ts`)                                                | `services/control-plane/test/authz.test.ts`                                                   | Wasm evaluation cannot be pre-empted (NEEDS #21)                                                                    |
| Elevation of privilege | SCIM or JIT mass role grant, domain takeover            | Per-directory token (hash only), group map capped below owner, deprovision revokes sessions and keys, JIT only for verified domains (`services/control-plane/src/scim.ts`) | `services/control-plane/test/scim.test.ts`                                                    | DNS verification is a stub (NEEDS #184)                                                                             |

## Prompt injection

The control plane takes no model input. Its exposure is indirect: a prompt-injected agent calling the public API through a tool would do so with the agent's own credential and scopes, under the same authorizer. The red-team corpus therefore includes admin-shaped goals (`grant-role`, `delete-records`) that must be denied at the kernel, and API probes with a narrow-scope key and a second tenant's key (`e2e/redteam_probes.py`). Policy text submitted by a tenant is data compiled by the policy compiler, never executed as instructions (`packages/policy/src/compile.ts`).

## Tool misuse

Mass assignment is blocked by strict request schemas (unknown fields are 422, a tenant in the body is refused) and by the response validation of the gateway (see [stride-api-gateway.md](stride-api-gateway.md)). Admin operations by API key require scopes AND a role, and session-only actions cannot be done by a key (`services/control-plane/src/apikeys.ts`, tests in `services/control-plane/test/api-authz.test.ts`).
