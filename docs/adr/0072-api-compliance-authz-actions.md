# 0072. Authorization actions `api.compliance.read|write|review`

Status: Accepted · Date: 2026-10-08 · Related: 0021, 0024, 0070, 0071

## Context

The `api` namespace of the control-plane pack (ADR 0024) decides one action per operation family. Compliance needs the same, plus a separation of
duties that the evals family approximates with `api.evals.review`.

## Decision

Three actions, decided by `policies/control-plane/pack.yaml` and covered by 21 golden cases:

| role         | read | write | review |
| ------------ | ---- | ----- | ------ |
| owner, admin | yes  | yes   | yes    |
| builder      | yes  | yes   | no     |
| operator     | yes  | no    | no     |
| auditor      | yes  | no    | yes    |
| viewer       | yes  | no    | no     |
| billing      | no   | no    | no     |

API-key scopes follow the existing rule: `compliance:read` for reads, `compliance:write` for write and review. A builder's key therefore cannot
review, and a key limited to `compliance:read` cannot change anything.

Role is necessary, not sufficient. Review also requires independence of the author, every contributor and the submitter of that version; the
service and the database both enforce it (ADR 0070). An owner who wrote an assessment is refused when they try to approve it, and the refusal is
an audited DENY.

## Consequences

`API_ACTIONS` gains three entries, `isRead` classifies only `api.compliance.read` as a read, and the role matrix test in
`services/control-plane/test/api-authz.test.ts` pins the table above.
