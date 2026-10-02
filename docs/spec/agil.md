# AGIL (`services/agil`, `@axis/agil`)

Status: Prototype. Invariant 2: AGIL never governs. ADR 0027.

## Interface

`new Explainer({ audit: AuditReader, policies?: PolicyMetadataSource })`; `explainRun(tenantId, {traceId, runEvents?})` and
`explainEvent(tenantId, seq)`. The audit reader is the frozen `listEvents`-only view (`createAuditReader`). AGIL has no handle on a gate,
the kernel, approvals, a policy engine or a writable store, and `test/architecture.test.ts` fails if its imports or dependencies grow.

## Output (stable)

```
{ summary: string,
  steps: [{ n, kind: request|evaluation|outcome|context|run, text, audit_event_id?, seq? }],
  decision_refs: [{ audit_event_id, seq, ts, decision, enforcement_point, action, policy_version, policy_packs[],
                    gate, rule_ids[], gate_id?, kill_switch_scope?, approval_id?, reason }],
  remediation: [{ kind, text, hint? }] }          // + narrative? only when the narrator is enabled
```

`gate`: `kill_switch | policy_rule | default_deny | amount_cap | target_cap | budget | rate_limit | staleness | approval |
audit_unavailable | invalid_request | evaluation_failure | admin | other`, derived from the reason text the kernel, gates and approvals
service write (`classify.ts`). Unrecognised text is `other`.

## Properties

- Deterministic: a pure function of the audit rows (and optional run events / rule metadata). No model call, clock or randomness.
- Tenant-safe: rows of another tenant are dropped even if a reader returns them; a seq of another tenant's chain is simply absent.
- No secrets: reasons are sanitised (credential shapes masked, 300 chars). Rule metadata is the tenant's own pack text.
- Hints name the API call that changes the outcome (`PUT /v1/kill-switches`, `POST /v1/policies`, `POST /v1/policies:test`,
  `POST /v1/approvals/{id}/decision`).
- Optional narrator: `withNarration(explanation, {enabled: true, narrator})`; off by default; receives only `{gate, decision,
enforcement_point, rule_ids}` and remediation kinds (never reason text, ids, actions or values). Adapter: NEEDS #225.

## HTTP

`GET /v1/runs/{runId}/explanation` (`api.explanations.read`), `GET /v1/audit/events/{seq}/explanation` (`api.audit.read`).

## Through the real stack

The Phase 7 e2e asserts, from each client, that every `decision_ref` of a run or denial explanation matches an audit row (id, seq, decision, action, policy version) fetched through the audit API, and that the explanation of a denied tool names it. AGIL is constructed with a frozen `listEvents`-only reader inside the gateway process and is not on the decision path.
