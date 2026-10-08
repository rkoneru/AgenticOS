# 0074. Annex IV technical documentation: assembled from records, deterministic, sealed

Status: Accepted · Date: 2026-10-08 · Related: 0070, 0071, 0073

## Context

Article 11 and Annex IV of Regulation (EU) 2024/1689 expect technical documentation that is kept up to date. AXIS already holds most of the facts
(the blueprint, its registry provenance, eval runs and attestations, policy packs, human oversight configuration, the audit chain). The generator
must assemble them without inventing anything and without pretending to be a conformity assessment.

## Decision

- **Pure assembly.** `assemble(sources)` is a function of its inputs: no clock, no random source, arrays sorted with a total order, canonical JSON.
  The same sources give the same bytes. Ten sections map to Annex IV points; a coverage table shows which points are evidenced, partial or gaps.
- **Gaps are first-class.** An unavailable source, a throwing source, a failed registry verification, a blueprint that does not compile, a failed
  audit chain verification, and the items the platform can never produce (hardware, harmonised standards, declaration of conformity) are listed
  as gaps, in the section and in the document. A source's error text is never copied into the document.
- **Sources are ports, asked for the caller.** The gateway builds them from its own ports, so tenant scoping and role checks are the same as for a
  direct call. A registry blueprint is verified again on resolve; a failed verification is reported, never papered over.
- **Seal.** `content_hash` = SHA-256 of the canonical JSON body. The seal (HMAC-SHA256 or Ed25519, both deterministic) covers
  `{content_hash, meta}`, and `meta` carries the hash of the Markdown, so the JSON, the Markdown and the metadata cannot be changed independently.
  Verification recomputes everything on every read. The standalone gateway derives its HMAC key from the seal key it already has, so documents
  keep verifying across restarts; a KMS-held asymmetric key is the intended production form (NEEDS #349).
- **Versions.** The body carries no timestamp, so unchanged sources give an unchanged `content_hash`; then no new version is stored
  (`created: false`). The documentation's own audit events (`compliance.*` and the gateway's records of those calls) are left out of the audit
  statistics, otherwise generating a document would change the next one.
- **Audit statistics** cover the most recent 10 000 events (the window is stated in the document) and report chain verification over the same
  window; a broken chain is a gap with the reason, not an exception.

## Consequences

Regenerating a document is cheap and idempotent. A document is only as true as its sources: runner-side eval grades are trusted, tenant-local
blueprints have no provenance, and the limitations section reads `docs/NEEDS.md` when the deployment can see it. The document says "designed for
and evidence-ready" and carries the disclaimer in its body, which the seal covers.
