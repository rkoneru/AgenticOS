# 0052. Docs site: a small deterministic markdown pipeline

Status: Accepted · Date: 2026-10-02

## Context

Docs must publish guides, specs, runbooks, an OpenAPI reference and an ADR index, build with no external network, and be checkable.

## Decision

A ~300-line TypeScript pipeline (`marked` for markdown) instead of a Next static export: no framework runtime, no client JS, byte-identical output (sorted inputs, no timestamps). Raw HTML in markdown is escaped, unsafe link schemes dropped, images replaced by alt text (docs reference none). The OpenAPI reference is generated from `packages/contracts/openapi/axis-v1.yaml` so it cannot drift. A link checker validates every internal href and fragment; the test builds the real `docs/` twice offline and compares bytes. `NEEDS.md` is excluded (working file, not documentation).

## Consequences

No search, versioning or syntax highlighting (NEEDS #1313). Links from docs to files outside `docs/` are not resolvable in the site and would be reported by the build (currently 0).
