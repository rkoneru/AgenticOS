# 0030. Blueprint registry: immutable signed versions, verify-on-resolve, owner-checked RLS

Status: Accepted · Date: 2026-10-02 · Related: 0007 (contracts freeze), 0006 (RLS), phase 7 plan component B, `docs/spec/registry.md`

## Context

Phase 7 needs blueprints to be shared between tenants and sold through a marketplace. A blueprint is code that runs with the tenant's
credentials, so the registry is a supply-chain boundary. The frozen contracts (`/blueprints` in the OpenAPI, ABL v1, audit event) do
not change: `services/registry` is an internal service whose HTTP surface is a non-production dev server.

## Decisions

1. **Names and versions.** A blueprint is `<namespace>/<name>@<version>`. A namespace belongs to exactly one tenant (claimed by a tenant
   admin; reserved words are platform-only). Versions are strict semver without build metadata (equal precedence would make "highest"
   ambiguous). Published versions are immutable: the primary key is the overwrite guard, a trigger forbids UPDATE/DELETE, and there is no
   delete in the port. **Yank** and **deprecate** are append-only events with a mandatory reason; a yank is final (a later deprecation does
   not undo it). Yanked versions are never resolved; they stay readable for pinned installs and forensics.
2. **Content hash.** `sha256(canonicalJson(abl))` using the ABL compiler's own canonical form (`@axis/abl` `contentHash`), so the registry
   hash equals `manifest.blueprint.content_hash`. The registry stores the canonical JSON TEXT (not jsonb, which renormalises) and the
   verifier re-parses it, requires it to be canonical, validates it against the ABL schema and lint rules and recomputes the hash.
3. **Detached Ed25519 signatures (node:crypto).** The signed message is `domain || canonicalJson({v, namespace, name, version, contentHash,
riskLevel, keyId, signedAt})`, rebuilt by the verifier from the stored record, never taken from the client. Base64url decoding is strict
   (re-encoding must reproduce the input), so a flipped non-canonical trailing bit is a failure, not a no-op.
4. **Per-namespace key registry with effective timestamps.** `add`, `rotate` (old key ends at T, new key starts at T) and `revoke` with a
   reason: `retired` (signatures made before the instant stay valid) or `compromised` (NOTHING signed by the key is trusted, because a
   thief can mint any timestamp). Verification requires the key to be trusted at BOTH the registry's publish time (server clock) and the
   signature's claimed time. Key rows only move NULL -> value (trigger).
5. **Provenance.** An in-toto v1 statement (builder id, source ref, ABL sha256, compiler name+version, lint results, optional eval-results
   link) in a DSSE envelope (PAE-signed; payload must be canonical JSON). Verification checks subject name+digest, predicate hash, that the
   lint results can be REPRODUCED by re-running the compiler, an optional minimum compiler version, and a signature by a key trusted at
   publish time. Attestations that are signed but lie are rejected.
6. **Verify-on-resolve, fail closed.** `resolve(ns/name@range)` picks the highest satisfying non-yanked version and verifies it. If that
   version does not verify, resolution FAILS; it never falls back to an older version (a downgrade would let an attacker steer a stale
   release). A `notBelow` lock refuses rollbacks. References must be namespace-qualified; an unqualified reference is refused, not searched
   (dependency confusion). Publishing checks every reference's syntax, resolves and verifies agent dependencies, rejects cycles and
   self-dependency, and requires a public namespace to depend only on public namespaces.
7. **Typosquat guard.** `UNIQUE (namespace, normalized)` over names and `UNIQUE (normalized)` over namespaces, where `normalized` folds
   case, hyphens and look-alikes (`i l 1`, `o 0`, `rn m`, `vv w`, `3 e`, ...). The same publisher republishing the same name is unaffected.
8. **Database (migration 0020, additive; FREEZE.json regenerated per ADR 0007).** Forced RLS on every table. Reads: the owner tenant, plus
   everyone for namespaces listed in `registry_public_namespaces` (anonymous readers set no tenant and see only public rows). Writes: the
   owner only, enforced by `axis.registry_owns(namespace, tenant_id)` (a tenant id on a row is not enough: the namespace must be the tenant's).
   Making a namespace public is marketplace authority: the service method requires the `platform/marketplace` principal, which no HTTP
   credential can produce. At the database it is an INSERT by the owner's tenant context, so a separate DB role for the marketplace is a
   NEEDS item (the app role is shared today).
9. **Audit.** Every mutation writes the decision (ALLOW/DENY) to the TENANT's hash chain before it is performed and the outcome after; a
   decision that cannot be written is not performed. Verification failures on resolve are audited as DENY.

## Consequences

- A malicious or buggy store cannot make the registry serve changed content: the hash, signature and attestation are re-checked on every read.
- Compromise response is clear (revoke as compromised, yank, re-sign with a new key), at the cost that all old versions of a compromised key
  stop resolving until they are re-published under a new key.
- Gaps (NEEDS 1100+): no transparency log/rekor equivalent, no KMS/HSM-held publisher keys (publisher keeps the private key), no key
  transparency, registry clock is trusted for "publish time".
