# Runbook: Risk Kernel

Status: **Built (single process, in-memory state)**. See `services/risk-kernel`, ADR-0004, ADR-0009.

## What it does

Every external action is evaluated through gRPC `GateService.Evaluate` before it runs. Order: validate → kill-switches →
policy (Wasm) → gates → audit append → respond. Any error, timeout, malformed policy output, failed gate or failed audit
append is `DENY`. Clients treat transport errors, deadlines and `DECISION_UNSPECIFIED` as `DENY`.

## Start (dev)

```bash
pnpm --filter @axis/policy exec tsx src/cli.ts bundle policies/baseline-deny/pack.yaml policies/phi-redaction/pack.yaml -o /tmp/policy.tar.gz
echo '{"dev-token": {"tenantId": "<tenant uuid>", "subject": "runtime", "platformOperator": false}}' > /tmp/tokens.json
AXIS_POLICY_BUNDLE=/tmp/policy.tar.gz AXIS_RK_TOKENS=/tmp/tokens.json AXIS_RK_PORT=50051 pnpm --filter @axis/risk-kernel start
```

State (kill-switches, counters) and audit are **in memory and lost on restart**; do not run more than one instance. Production
needs the Redis stores and the audit service (see `docs/NEEDS.md`).

## Operations

- **Engage a kill-switch:** `SetKillSwitch` (tenant/agent/tool by the tenant's credential; global by a platform operator).
  Takes effect on the next decision. Engaging is never blocked by an audit outage; releasing requires the audit record first.
- **Deploy a new policy:** compile with `axis-policy bundle`, restart/reload the kernel with the new bundle. The response's
  `policy_version` and every audit event record which pack versions decided.
- **Latency:** `pnpm --filter @axis/risk-kernel bench` (in-process numbers; excludes network, DB, Redis).
- **`make policy-test`** must pass before any policy change ships.

## Reading denials

`reason` names the rule ids, gate id, or failure class (`policy evaluation timed out`, `audit unavailable`,
`kill-switch state unavailable`, `gate state unavailable`, `invalid request: ...`). Reasons never contain request values.
Invalid requests (no trustworthy tenant) are **not** written to a tenant's audit chain; they are logged as `gate request rejected`.

## Known limits

- Policy evaluation is synchronous Wasm and cannot be pre-empted; an over-budget evaluation is denied after the fact (default 25 ms).
- Static-token authentication is dev-only; mTLS/short-lived tokens are Phase 6.
- `approval_id` is empty until the approvals service exists (Phase 3); `REQUIRE_APPROVAL` callers must not proceed.
