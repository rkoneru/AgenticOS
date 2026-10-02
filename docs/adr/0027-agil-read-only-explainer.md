# 0027. AGIL: read-only deterministic explainer (`services/agil`)

Status: Accepted · Date: 2026-10-02 · Related: invariant 2 (AGIL never governs), 0010, 0024, 0025

## Decision

- `@axis/agil` exports `Explainer`, constructed with an `AuditReader` (the frozen, `listEvents`-only view from
  `createAuditReader`). It has no reference to a gate, kernel, approvals service, policy engine or store.
- Explanations are a pure function of audit rows (plus, optionally, run events and tenant-owned rule metadata passed as plain
  values): reasons written by the kernel, gates and approvals service are classified by `classifyReason` into a gate kind (kill-switch
  scope, policy rule ids, default deny, amount/target cap, budget, rate limit, staleness, approval, audit/evaluation failure) with
  parameters from the PHI-safe reason text; hints name the API call that would change the outcome.
- No model call by default. A `Narrator` port exists, off unless `enabled: true` and a narrator is supplied, and receives only
  enumerated fields (gate kind, decision, enforcement point, rule ids, remediation kinds). The deployment adapter (ModelGateway is
  Python) is NEEDS #1011.
- Enforcement: `test/architecture.test.ts` fails if the package imports anything but `@axis/audit` types and `@axis/contracts`, names a
  kernel/gate/approvals/policy/billing/eval/transport module, declares another dependency, or calls an IO or write-like API.
- Tenant safety: rows whose `tenant_id` differs from the requested tenant are dropped even if a reader returns them; rule metadata
  and audit text are sanitised (credential-shaped text masked, length bounded).

## Consequences

Explanations can only be as good as the audit reason text; `matched_rule_ids` are not in the audit row (only in the gate response),
so a REQUIRE_APPROVAL/ALLOW explanation names rules only when the kernel put them in `reason` (it does for winners). Recorded as
NEEDS #1012.
