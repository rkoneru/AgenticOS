# 0001. Record architecture decisions

Status: Accepted · Date: 2026-09-30

## Context

AXIS is built autonomously and in phases. Decisions must be reviewable later without reconstructing chat history.

## Options

1. Decisions live in commit messages and docs prose.
2. One ADR per significant decision in `docs/adr/`.

## Decision

Option 2. Files are `docs/adr/NNNN-title.md` with Context, Options, Decision, Consequences. An ADR is also
required for reconciliations with the master prompt, contract changes after the Phase 1 freeze, and any
deviation from the fixed stack.

## Consequences

Small overhead per decision. Superseded ADRs stay and are marked `Superseded by NNNN`.

## Recorded alongside

The "existing kernel and docs" assumed by the master prompt were absent; see `docs/INVENTORY.md`.
