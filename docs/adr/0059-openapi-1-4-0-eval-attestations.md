# 0059. OpenAPI 1.4.0: eval attestations of a version (additive)

Status: Accepted · Date: 2026-10-08 · Related: 0056, 0057, 0058

## Context

"Eval history is visible per version" needs the Eval Hub's signed result summaries (attached to registry versions, ADR 0056) to be readable by
clients. Run history per version is already `listEvalRuns?content_hash=`.

## Decision

`GET /v1/registry/blueprints/{namespace}/{name}/versions/{version}/eval-attestations` (`listRegistryEvalAttestations`) returns
`{items: RegistryEvalAttestation[]}` (`run_id, suite_ref, overall, content_hash, attached_at, verified, predicate, envelope`). Every envelope is
re-verified against the trusted hub keys on each read and must be about this name, version and content hash; `predicate` is decoded only when
`verified`. Same visibility as the version (an invisible version is a 404). `info.version` 1.3.0 -> 1.4.0, FREEZE regenerated, SDKs regenerated,
ergonomic layers (`registry.evalAttestations` / `eval_attestations`) and `axis registry attestations` added; the CLI exits 1 when any item is unverified.

## Consequences

Gateway route table is 61 operations. Console shows the attestations in the release-gate panel with a verified badge.
