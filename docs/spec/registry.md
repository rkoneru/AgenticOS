# Blueprint registry (Phase 7 B)

Status: Prototype (library + non-production loopback dev server; Postgres store with forced RLS; no KMS-held keys, no transparency log).
Code: `services/registry` (`@axis/registry`). Decisions: ADR 0030. Threat model: `docs/security/registry-marketplace-threat-model.md`.

## 1. Model

`<namespace>/<name>@<version>`: namespace = one tenant's (claimed by an admin), name = ABL `metadata.name`, version = ABL `metadata.version`
(strict semver, no `+build`). Every published version stores: canonical ABL text, content hash, risk level, detached signature
`{keyId, signedAt, sig}`, a DSSE provenance envelope, publish time (server clock) and publisher. Status events (`yank`, `deprecate`) are append-only.

## 2. Publishing

`publish(principal, namespace, {abl, signature, provenance})` (role builder or above, namespace owned by the caller's tenant):
schema + lint (errors refuse) -> strict semver -> reference checks -> signature + provenance verification (below) -> insert. A version that
exists is a `409` whatever its content. Everything before the insert runs with the decision already written to the tenant's audit chain.

### Signed message and key rules

`axis-registry/blueprint-signature/v1 \n canonicalJson({v:1, namespace, name, version, contentHash, riskLevel, keyId, signedAt})`.
Key states per namespace: `validFrom`, `validUntil` (rotation), `revokedAt` + reason `retired|compromised`. A signature verifies only if
the key is trusted at publish time AND at `signedAt`, `signedAt` is not more than 5 minutes after publish, and the key was never revoked
as compromised. Rotation ends the old key at T and starts the new at T.

### Provenance (in-toto Statement v1 in DSSE)

`predicateType https://axis.dev/blueprint-provenance/v1`: `builder.id`, `source.ref[.digest]`, `abl.sha256`, `compiler {name:@axis/abl, version}`,
`lint {errors, warnings, codes}`, optional `evals.resultsUrl`, `buildFinishedOn`. The verifier recomputes the lint results, checks the
subject (`ns/name@version`, sha256) and requires one signature by a key trusted at publish time.

## 3. Resolution

`resolve(viewer, "ns/name@range")`: ranges are exact, `^`, `~` (partials allowed there), comparators (`>= > <= < =`, ANDed), `||`, `*`;
pre-releases follow the npm rule. Highest non-yanked satisfying version is verified (all checks of section 2, from the stored data); any
failure is `422 verification_failed` with the failed check codes and the result is NOT replaced by an older version. `allowYanked` is for
pinned installs only; `notBelow` refuses rollbacks. Unqualified references are `422`.

Verification check codes: `abl_not_json abl_not_canonical abl_schema content_hash_mismatch name_mismatch version_mismatch
risk_level_mismatch abl_lint_errors signing_key_unknown signed_at_malformed signed_after_publish signing_key_not_trusted
signature_invalid provenance_malformed provenance_payload_invalid provenance_type provenance_subject_mismatch provenance_abl_hash_mismatch
provenance_builder provenance_source provenance_compiler provenance_compiler_too_old provenance_lint_mismatch provenance_signature_invalid rollback`.

## 4. Visibility and authorization

Private namespace: owner only (other tenants get 404, never 403 data). Public namespace (listed by the marketplace): readable by every tenant
and anonymously, writable only by the owner. Roles (control-plane ladder): read = viewer, publish = builder, yank/deprecate/keys/claim = admin.
Platform-only operations (`setNamespacePublic`, `platformYank`) need the `platform/marketplace` principal.

## 4a. Public API (OpenAPI 1.2.0, ADR 0053)

The gateway serves namespaces, keys, publish (a client-signed bundle), versions, yank and `resolve` under `/v1/registry/*`, in process, with the tenant and role from the
credential. A verification failure is 422 with the failed check codes in `errors[].keyword`. Signing is publisher tooling (`axis registry sign`): the provenance contains the
compiler's lint results (NEEDS #273). The e2e tampers a stored version behind the registry's back and requires resolve and the marketplace preview to refuse it.

## 5. Dev HTTP (non-production, loopback, static bearer tokens)

See the header of `services/registry/src/dev-server.ts` for the route list. Tenant and role come from the token; a spoofed `tenant_id` is 403;
sliding-window rate limit per subject (429 + `retry-after`); body cap 4 MB; refuses to start with `NODE_ENV=production`.

## 6. Storage

Migration `0010_registry.sql`: `registry_namespaces`, `registry_public_namespaces`, `registry_keys`, `registry_names`, `registry_versions`,
`registry_version_events`; forced RLS; versions and events immutable; keys only NULL -> value transitions; write checks use
`axis.registry_owns(namespace, tenant_id)`.
