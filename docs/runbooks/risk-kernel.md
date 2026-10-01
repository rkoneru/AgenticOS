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

- **Global kill-switch:** only platform operators. The operator's principal needs `auditTenantId` (a dedicated platform tenant)
  for the action to be audited on a chain; without it the switch can be engaged (safety first) but **not released**.
- **Engage a kill-switch:** `SetKillSwitch` (tenant/agent/tool by the tenant's credential; global by a platform operator).
  Takes effect on the next decision. Engaging is never blocked by an audit outage; releasing requires the audit record first.
- **Deploy a new policy:** compile with `axis-policy bundle`, restart/reload the kernel with the new bundle. The response's
  `policy_version` and every audit event record which pack versions decided.
- **Latency:** `pnpm --filter @axis/risk-kernel bench` (in-process numbers; excludes network, DB, Redis).
- **`make policy-test`** must pass before any policy change ships.

## Reading denials

`reason` names the rule ids, gate id, or failure class (`policy evaluation timed out`, `audit unavailable`,
`kill-switch state unavailable`, `gate state unavailable`, `invalid request: ...`). Reasons never contain request values.
Rejections are audited when a tenant can be trusted: over gRPC the tenant comes from the credential, so an invalid request,
a context that cannot be hashed (non-finite numbers, cycles, excessive depth/size) or a tenant/credential mismatch is recorded as
`request_rejected` (enforcement point `admin`) in the **authenticated** caller's chain, never in the claimed tenant's. In-process
callers of `RiskKernel.evaluate` with an invalid request get a DENY with an empty `audit_event_id` and a logged warning.

## Known limits

- Rejection audit records are rate-limited to 60 per tenant per minute (`rejectionAuditPerMinute`); the rest are counted and logged
  as `rejection audits dropped`. This only ever bounds the caller's own chain and the shared audit path's load.
- A `REQUIRE_APPROVAL` decision releases any capacity its gates reserved (nothing executes). The approved action is evaluated
  again when resumed (the client re-submits it with the signed decision record in `context.approval`) and reserves then; every
  kill-switch, DENY policy and gate applies again. With no `ApprovalRequester` the decision carries an empty `approval_id`
  (clients DENY); a requester failure is DENY. See `docs/spec/approvals.md`. Approval single-use is per kernel instance and in
  memory (NEEDS #63).
- gRPC messages that fail protobuf decoding (for example pathologically nested `Struct`s) are rejected by the transport with
  INTERNAL before the kernel runs; they are not audited. Clients treat that as DENY.

- Kill-switch and counter state is in-memory and single-instance, so **cross-instance kill-switch propagation (< 1 s) is not built**;
  the Redis stores must implement `CounterStore.reserve` as one atomic script (Lua), not get-then-add.
- Counter keys use the agent name and `run.id` supplied by the (trusted) runtime. There is no tenant-wide budget scope and no
  agent registry binding yet, so a compromised runtime could reset per-agent counters by renaming its agent.

- Policy evaluation is synchronous Wasm and cannot be pre-empted; an over-budget evaluation is denied after the fact (default 25 ms).
- Static-token authentication is dev-only; mTLS/short-lived tokens are Phase 6.
- `approval_id` is empty until the approvals service exists (Phase 3); `REQUIRE_APPROVAL` callers must not proceed.
