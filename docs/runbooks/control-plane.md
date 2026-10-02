# Runbook: control plane

Status: Prototype (see `docs/spec/control-plane.md`, `docs/NEEDS.md` #179-#195).

## Run it locally

```bash
pnpm build
# Postgres 16 + pgvector with migrations applied (packages/db `pnpm migrate`), connecting as a login role that is a member of axis_app.
# `opa` must be on PATH (the authz bundle is built at start).
CP_PG_URL=postgres://... CP_PLATFORM_TOKEN=... CP_DEV_TOKEN=... node services/control-plane/dist/main.js   # DEV entry: fake IdP/KMS/DNS
```

`src/main.ts` is a DEV entry point (Postgres store, FAKE IdP/KMS/DNS, loopback only; environment variables are listed in its header and are not smoke-tested: coverage excludes it). The composition root is
`wireControlPlane(config)` (`src/wire.ts`), exercised by `test/world.ts` (memory or Postgres store) and `test/http.test.ts` (`createControlPlaneServer(deps)` + `listenLoopback`). Secrets (`pepper`, `cookieKey`, `signingKeys`) must each be >= 32 random bytes.

## Tests

```bash
cd services/control-plane
pnpm test        # real Postgres 16 via infra/scripts/with-pg.sh (two throwaway databases), real opa for the authz pack and policy validation
pnpm cov         # coverage gates (vitest thresholds)
pnpm mutation    # ~90 safety mutants, one at a time; every one must be killed (about 40 minutes)
make policy-test # includes policies/control-plane/authz.cases.yaml (73 golden cases)
```

## Operations

- **Provision a tenant**: `POST /platform/v1/tenants` with the platform token: `{slug, name, owner_email, region, phi_mode?}`. The owner then signs in through SSO after a tenant admin links an IdP organization
  (`PUT /admin/v1/sso/connection`), or, in dev only, through `POST /dev/session`.
- **Rotate signing keys**: prepend a new `{kid, key}` to `secrets.signingKeys`, deploy, wait one access-token lifetime (15 min), remove the old key. Removing it earlier logs everyone out (refresh still works).
- **Rotate a SCIM token / revoke a directory**: `POST /admin/v1/directories/{id}/rotate-token`, `DELETE /admin/v1/directories/{id}`.
- **Cut off a person now**: `DELETE /admin/v1/members/{id}` (or SCIM deprovision): sessions and API keys are revoked before the call returns. `POST /admin/v1/members/{id}/revoke-sessions` kills sessions only.
- **A tenant admin lost access (last owner deprovisioned)**: there is no break-glass API (NEEDS #185). A platform operator with database owner access inserts an owner member row directly and records it in the audit chain by hand.
- **Policy pack rollback**: activate the previous version (`POST /admin/v1/policies/{versionId}/activate`); versions are immutable. baseline-deny cannot be deactivated.
- **Move a tenant to a dedicated database**: not supported (NEEDS #188). The router and `tenant_placements` exist; provisioning and data migration do not.

## Alerts worth wiring (not wired)

Spikes in 401/403 on `/admin/v1`, `auth.sso_login` DENY events by reason (`nonce_mismatch`, `domain_not_verified`, `member_deprovisioned`), `refresh_token_reuse` session revocations, `*.last_owner_locked_out` events,
503 `unavailable` (audit sink or placement down: mutations stop, by design).
