# Runbook: registry and marketplace

Dev stack only (libraries + loopback servers; `docs/spec/registry.md`, `docs/spec/marketplace.md`).

## Run and test

```bash
pnpm --filter @axis/registry cov         # real Postgres 16 via infra/scripts/with-pg.sh; 95% on signing/provenance/semver/verify
pnpm --filter @axis/marketplace cov      # 95% on state machines, capability diff, install consent, review logic
cd services/registry    && pnpm mutation [substring]   # one safety edit at a time; every mutant must be killed
cd services/marketplace && pnpm mutation [substring]
AXIS_REGISTRY_DATABASE_URL=... AXIS_REGISTRY_TOKENS='{"tok":{"tenantId":"<uuid>","subject":"u1","role":"admin"}}' node services/registry/dist/main.js
AXIS_MARKETPLACE_DATABASE_URL=... AXIS_MARKETPLACE_TOKENS='{"t":{"kind":"reviewer","subject":"rita"}}' node services/marketplace/dist/main.js
```

## Publisher onboarding (dev)

1. Tenant admin: claim a namespace, register an Ed25519 public key (`keyId` = `k1-` + first 32 hex of sha256 of the raw key). Keep the private key offline.
2. Admin: `POST /v1/publisher` (legal name, domain, contact), publish `axis-verify=<challenge>` as TXT (fake prover in dev), `POST /v1/publisher/evidence`.
3. Reviewer: check `/v1/review/publishers/{tenant}/evidence`, decide.
4. Builder: sign + publish versions, `POST /v1/publisher/reviews`, create the listing.

## Incidents

- **Publisher key compromised:** `revoke` the key as `compromised` (all versions it signed stop resolving), rotate to a new key, re-sign and re-publish
  fixed versions under new version numbers, `yank` bad ones. Affected installs keep running; moderators can flag them via takedown.
- **Malicious blueprint found:** moderator `takedown` (version or listing). New installs and updates stop at once, registry versions are yanked, each
  existing install is flagged and audited in its tenant chain; tenants uninstall or accept the risk knowingly. Suspend the publisher if needed.
- **`verification_failed` on resolve:** read the `checks` in the error. `content_hash_mismatch` / `signature_invalid` on stored data = storage tampering or
  corruption: treat as an incident, do not "fix" by republishing the same version (it is immutable). `signing_key_not_trusted` = key rotated/revoked.
- **Metering backlog:** `POST /v1/installs/flush-metering` as the installing tenant's admin (idempotent).
- **Stuck review:** a review is terminal once decided; republish a new version for a new review.
