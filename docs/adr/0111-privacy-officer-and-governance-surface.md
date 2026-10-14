# 0111. The `privacy_officer` role and the data-governance surface

Status: Accepted · Date: 2026-10-14 · Related: 0080-0083, 0112, NEEDS 407-412

## Context

Phase 9 / B built the data-governance engine (DSAR, holds, retention, residency; ADRs 0080-0083) behind a loopback dev server with static
tokens. A personal-data erasure is the one operation in the platform that is deliberately irreversible, and an export hands a person's data to
a third party. Neither fits the existing roles: `owner` and `admin` can already change policies, members and keys, and giving them the power to
erase or export people's data would turn every compromised admin account into a data-destruction or exfiltration path. At the same time the
engine's `RequesterVerifier` was a hook that refused everything (NEEDS 367), so no request could ever be verified and the surface was inert.

## Decision

1. **A `privacy_officer` role** (migration 0016, control-plane RBAC with golden cases). It holds the `api.governance.*` actions and nothing else.
   `owner`, `admin` and `auditor` may READ governance state (the queue, holds, retention reports, residency); only the privacy officer may open
   requests, verify, export, erase, restrict, place or release holds, set retention and run retention. The role is enforced twice, independently:
   by the route's authorisation action (control-plane pack) and by the gateway adapter (`GOVERNANCE_READ_ROLES` / `GOVERNANCE_WRITE_ROLES`).
   The engine itself insists on the privacy-officer role even for reads, so a permitted read is executed under an engine principal built from the
   gateway principal (same tenant, same member id), never under anything the caller supplied.
2. **The gateway hosts the surface** (OpenAPI 1.6.0, ADR 0112) and answers **503 `problem+json` until the kit is wired**: without
   `GW_GOV_MASTER_KEY` every governance route is a 503, no residency write guard is installed, and nothing is half-enforced silently.
   `UnavailableGovernance` throws on every operation; it never returns an empty success.
3. **A real requester verifier with dual control** (`EvidenceVerifier`). Identity of the data subject is proven by two HMAC-signed tokens bound to
   the tenant, the request and a short expiry, signed with a per-tenant key derived from the governance master key:
   a `requester_token` (the tenant's identity-proofing step confirmed the person out of band, names the opaque subject reference) and an
   `admin_attestation` (a tenant admin attests that proofing took place). The attester must differ from the member who opened the request and from
   the member submitting the verification, and must be an ACTIVE `owner` or `admin` of the tenant, looked up in Postgres under forced RLS at the
   time of the check (never read from the token). Any malformed, expired, mis-bound or badly signed token, an unknown attester or a directory
   error refuses; the refusal leaves the request `received` and nothing is exported or erased.
4. **Real ports.** `PgRetentionSettings` (`tenant_settings`, `tenants.phi_mode`; no row means unknown, so nothing is purged),
   `PgRegionResolver` (`tenants.region`, the only region data may be written to today), `PgAttesterDirectory`; the audit sink is the tenant's own
   Postgres chain (`PgAuditLog`); an audit append failure aborts the operation before anything is mutated (fail-closed, as before).
   Migration 0017 grants the governance role `SELECT` on `tenant_settings` (0015 had granted `tenants` but not the settings).
5. **Residency write guard** (`ResidencyPolicy.forService(region)`) is installed from the same kit into the stores the gateway process hosts
   (registry versions, eval-hub documents, billing ledger). A refusal is a 403 `residency_violation` problem; the region names stay in the
   service's own log, not the response. Unknown tenant or empty region is default-deny.
6. **Error mapping.** `not_found` 404; `forbidden`, `restricted`, `residency` 403; `conflict`, `not_verified`, `held` 409; `invalid` 422;
   `unavailable` 503; `residual_data` (erasure could not be proven, nothing shredded) is a 500 so it is never mistaken for done.
   An erasure blocked by a hold is NOT an error: the outcome is `held` (200) and the data is untouched.
7. **Identity proofing is out of band.** The platform does not issue the requester token: the tenant's proofing tooling (an email link, an IdP
   step-up) does, with `EvidenceVerifier.issueRequesterToken`. The e2e stack mints tokens through an ops hook that uses the same master key.

## Consequences

- A compromised admin or owner cannot erase or export personal data; a compromised privacy officer alone cannot verify a request (it needs an
  independent admin's signed attestation and the proofing token) and every step is in the tenant's audit chain without raw identifiers.
- The console is deliberately read-only for governance; writes are CLI/SDK actions of the privacy officer.
- `GW_GOV_MASTER_KEY` is a dev stand-in for a KMS (NEEDS 365). Rotating it invalidates outstanding evidence tokens and the lookup keys of
  sealed identifiers; there is no rotation procedure yet.
- The verifier proves that two people vouched with valid tokens, not that the person is who they claim; that is the proofing step's job.
