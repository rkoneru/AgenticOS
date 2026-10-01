# Runbook: Approvals

Status: **Built (library, single process, in-memory); wired to the kernel and runtime for e2e/dev only**. See `docs/spec/approvals.md`, `services/approvals`.

## Wiring (in-process)

```ts
const svc = new ApprovalService({
  store: new MemoryApprovalStore(),
  audit /* AuditSink: PgAuditLog */,
  signer: new HmacSigner(key32bytes, "hmac-1"),
  dispatcher: new NotificationDispatcher({ notifiers }),
});
svc.startSweeper(5_000); // SLA timers; reads also apply them lazily
const resolver = new ApprovalResolver(svc);
```

Kernel/runtime flow: kernel answers `REQUIRE_APPROVAL` -> caller `svc.create({...approval spec, args_hash...})` -> approver
`claim` / `approve` / `deny` via an authenticated API (not built, NEEDS #50) -> runtime `resolver.resolve()` ->
`isApprovalValidFor()` -> re-gate and run. Wired in the kernel entry point for dev/e2e (below); full flow in
`docs/spec/approvals.md`.

## Dev / e2e: kernel + approvals + bridge (NOT production)

```bash
export AXIS_APPROVALS_HMAC_KEY=$(openssl rand -hex 32)   # signs decision records; the kernel verifies with the same key
export AXIS_APPROVALS_DEV_BRIDGE=1                         # loopback HTTP bridge; the port is in the "listening" line
AXIS_POLICY_BUNDLE=... AXIS_RK_TOKENS=... AXIS_AUDIT_PG_URL=... pnpm --filter @axis/risk-kernel start
# {"event":"listening","port":50051,"approvals_port":43817}
curl -s -XPOST localhost:43817/v1/approvals/list -H "authorization: Bearer $TOKEN" \
  -d '{"principal":{"id":"alice","roles":["finance-approver"]},"status":"pending"}'
curl -s -XPOST localhost:43817/v1/approvals/approve -H "authorization: Bearer $TOKEN" \
  -d '{"request_id":"<id>","principal":{"id":"alice","roles":["finance-approver"]}}'
```

Runtime side: `RunDeps(approvals=HttpApprovalResolver("http://127.0.0.1:<port>", token=...))`. The bridge trusts the
`principal` in the body and listens on loopback only: never expose it. `make e2e-phase3` drives all of this.

## Operations

- **Pending request will not resolve:** the process restarted (in-memory store). Callers must time out and DENY; recreate.
- **`AUDIT_FAILED` on approve/claim/escalate:** the audit log is down; nothing was approved. Fix audit, retry. Denials and
  expiries are still applied while audit is down, logged as `audit append failed on DENY transition`; reconcile those
  requests (empty `audit_event_id` in their decision record) once audit recovers.
- **Notifications missing:** check logs for `notification gave up` (channel, request id, last error; webhook URLs are never
  logged). State is unaffected; approvers can still use the API. Needs per-tenant targets (NEEDS #49).
- **Stuck at an unresponsive level:** nothing to do; the SLA escalates, then expires to DENY.
- **Rotate the signing key:** deploy verifiers with the new key id first; records signed with an old `key_id` fail
  verification (fail-closed) once the old key is removed.
- **Never** run more than one instance (NEEDS #52).
- **Run says `approval_unavailable:*` / `approval_mismatch`:** the runtime could not get a well-formed record for this request
  (bridge down, wrong token/tenant, still pending past `max_wait_seconds`). The action did not run. Check the bridge port and
  token; the request is still decidable.
- **`approval already used` / `approval record not valid for this action` in the kernel's audit reason:** a replayed,
  tampered or mis-bound record was presented; investigate the caller. A kernel restart forgets single-use (NEEDS #63).

## Tests

```bash
pnpm --filter @axis/approvals cov      # 95% gate
```
