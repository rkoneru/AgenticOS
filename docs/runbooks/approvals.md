# Runbook: Approvals

Status: **Built (library, single process, in-memory)**. See `docs/spec/approvals.md`, `services/approvals`.

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
`isApprovalValidFor()` -> re-gate and run. Not wired yet (NEEDS #53).

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

## Tests

```bash
pnpm --filter @axis/approvals cov      # 95% gate
```
