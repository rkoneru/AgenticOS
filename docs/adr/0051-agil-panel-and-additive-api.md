# 0051. AGIL explanation panel and the additive API the console assumes

Status: Accepted · Date: 2026-10-02 · Related: invariant 2 (AGIL never governs), 0050

## Context

Phase 7 requires an explanation beside every run, denial and approval. AGIL is a Concept (no service, no `docs/spec/agil.md`). `/v1` is frozen.

## Decision

Define the shape in `lib/api.ts` (`Explanation {summary, steps[], decision_refs[{audit_event_id, seq?}], remediation[]}`) and consume it from three additive GETs. The component renders those fields as text and nothing else: **it never invents or templates explanation content**, so a missing AGIL service shows "no explanation available" instead of plausible fiction. The panel only reads and is never consulted by any decision or action. Other additions (`/auth/me`, marketplace, optional approval and policy fields, `GET /evals/runs`) are listed in `docs/spec/console.md` section 6 and `docs/NEEDS.md` #243. Adding them to the contract needs a follow-up ADR and a spec change by the gateway/AGIL owners.

## Consequences

Until AGIL and the gateway serve these routes the panel is empty by design. The mock serves fixed text that includes hostile markup to prove inertness; it is not an AGIL output.
