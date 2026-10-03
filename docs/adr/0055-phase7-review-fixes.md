# 0055. Phase 7 review fixes: per-version registry release, gateway limits, and what the review changed

Status: Accepted · Date: 2026-10-03 · Related: 0024, 0030, 0031, 0041, 0042, 0050, 0054

## Context

The independent Phase 7 review found defects that the component tests did not (each has a failing-first test and a mutation check).
Only one needs a schema change.

## Decision

1. **Registry release is per version (migration 0012, additive table + three replaced read policies).** 0010 made every name, version and
   event of a listed namespace readable by every tenant: a publisher's never-submitted blueprints (prompts) and every later, unreviewed
   version were public from the first approval. `registry_public_versions` records the exact versions the marketplace released
   (`RegistryService.setVersionPublic`, platform principal only, called on approval and when a listing is created). Names, versions
   and events are visible to non-owners only for released versions; the namespace record and keys stay public so a reader can verify.
   Public-namespace dependencies must resolve, for an anonymous reader, to the version the publisher resolved. No backfill: dev databases
   lose public readability of earlier versions until re-approved (no production data exists).
2. **Gateway**: default token costs for heavy operations (`DEFAULT_COSTS`); `trustedProxies` (`GW_TRUSTED_PROXIES`) so failed sign-ins are
   throttled per client behind the console's BFF (the BFF relays `X-Forwarded-For` only with `AXIS_TRUST_PROXY=1`); an Idempotency-Key stays
   reserved until a handler that outlived the gateway timeout settles; denied reads are audited with a per-(tenant, member, operation)
   allowance; `opa` runs with PATH only; token tables key their cache on inode+size+mtime.
3. **Marketplace**: the scan reads every model-visible and user-visible text with Unicode/whitespace folding; IPv6 literals and URL
   credentials are findings; installs are re-checked after the write (takedown race); the publisher meter is once per (installer, listing);
   listing text is plain text.
4. **SDK/CLI/console**: dot-segment path parameters are refused; server text is rendered inert in the terminal; a signing key file readable
   by others is refused; the console's secret patterns are one list shared by the unit-tested scanner and the build gate; the ABL
   validate route caps its body.

## Consequences

Install/uninstall cycling no longer re-bills a publisher (a deliberate semantic change; the old test asserted the opposite). Denial audit
rows for a flooding credential are rate-limited, so the chain shows a trickle rather than every attempt.
