# Approvals service (`@axis/approvals`)

Status: **Built as an in-process library** (in-memory store; no production network surface). Wired to the Risk Kernel and the
runtime end to end for the Phase 3 e2e (`make e2e-phase3`) over a **dev-only** loopback bridge. Evidence: `services/approvals`
tests, property tests, mutation checks (below), `e2e/test_phase3_orchestration.py`. Gaps: `docs/NEEDS.md` #48-#54, #62-#64.

Handles `REQUIRE_APPROVAL` decisions from the Risk Kernel (`GateResponse.approval` = roles, SLA, escalation roles,
`on_timeout: DENY`). It is **on the decision path**; every failure resolves toward DENY.

## Model

`ApprovalRequest` (tenant, run, agent, tool, `args_hash`, `risk_level`, requester, conflicted principals, escalation chain,
current level, deadline, status, claim, decision fields, `version`). Status: `pending | approved | denied | expired`.

Escalation chain from the kernel's `ApprovalSpec`: level 1 = `roles` with `sla_seconds`; level N+1 = `[escalate_to[N-1]]`
with the same SLA. Deadlines chain (`deadline(N+1) = deadline(N) + sla`). Eligible approvers at level N = union of roles of
levels 1..N (escalation widens, never narrows). At most 6 levels.

## Rules (each is a tested, mutation-checked invariant)

1. **Tenant isolation.** The principal's `tenant_id` scopes every operation; every store method takes a tenant. Cross-tenant
   ids behave as `NOT_FOUND`. Audit events land on the owning tenant's chain.
2. **Approver role check.** Principal must hold a role eligible at the current level (`FORBIDDEN_ROLE`).
3. **No self-approval.** Requester id can never claim, approve or deny (`SELF_APPROVAL`).
4. **Separation of duties.** `conflicted` principals (e.g. the agent's owner) are barred (`CONFLICT_OF_INTEREST`); a request
   claimed by one approver cannot be decided by another (`CLAIMED_BY_OTHER`); escalation clears the claim.
5. **Immutable decisions.** A terminal request never changes. Replay of the same verdict by the same decider returns the
   stored result with no new event; anything else is `ALREADY_DECIDED`.
6. **SLA, escalation, fail-closed expiry.** Due timers are applied by `sweep()` / `startSweeper()` AND lazily on every read or
   decision (a missed sweep cannot leave a stale `pending`; an approval at or after a deadline is evaluated at the escalated
   level, and after the last deadline the request is `expired`). `on_timeout` must be `DENY`; expiry is DENY, never approve.
7. **Audited transitions.** Every transition appends a hash-chained event to the `AuditSink` (`enforcement_point: "admin"`,
   `action: approval.requested|claimed|released|escalated|approved|denied|expired`, `request=<id>` and `tool`/`args` hash in
   `reason`, human or `system` actor). Direction matters: ALLOW-direction and widening transitions (create, claim, release,
   escalate, approve) **require** a durable append and fail (`AUDIT_FAILED`, no state change) otherwise; DENY-direction
   transitions (deny, expire) are applied even if the append fails (logged; the record's `audit_event_id` is empty).
8. **Notifications are advisory.** Dispatch is detached from the transition, retried with exponential backoff, logged, and
   can neither block, delay nor approve anything. Payloads carry only the args hash prefix, never arguments or secrets.

## Resolver contract (Risk Kernel / runtime)

```ts
const rec = await resolver.resolve(tenantId, requestId, signal?)   // waits until terminal
// rec.outcome: APPROVED | DENIED | EXPIRED;  rec.decision: ALLOW only for APPROVED
if (!(await isApprovalValidFor(rec, {tenant_id, run_id, tool, args_hash}, signer))) deny();
```

`DecisionRecord` is HMAC-SHA256 signed (key id included) over its canonical JSON and carries the audit event id and hash of
the decision. `isApprovalValidFor` is true only for a verified APPROVED record for exactly that tenant, run, tool and
argument hash (through `kernelApprovalPorts`, also decided within `maxAgeMs`, default 15 minutes, and not in the future) (no replay for different arguments or another tenant). **Any rejection (unknown id, signing/audit failure,
abort) must be treated as DENY.** The resolver re-checks SLA timers itself, so it resolves even if no sweeper runs.
No gRPC: it needs proto changes after the v1 freeze (NEEDS #50); the Phase 3 e2e reaches it through the dev bridge below.

## Round trip with the Risk Kernel and the runtime (Phase 3)

```
runtime executor --Evaluate(tool call)--> kernel: policy REQUIRE_APPROVAL, gates pass
                                          kernel --ApprovalRequester.create--> service (appends approval.requested)
                  <-- REQUIRE_APPROVAL, approval_id ----- kernel appends its own REQUIRE_APPROVAL event (reason has request=<id>)
runtime --resolve(id)--> bridge --> ApprovalResolver.resolve  (long-poll)         approver: claim / approve / deny
                  <-- signed DecisionRecord  (APPROVED | DENIED | EXPIRED)                (appends approval.approved|denied)
runtime --Evaluate(same action + context.approval = record)--> kernel RE-GATES:
        kill-switch, DENY policy, every gate again; ApprovalVerifier (isApprovalValidFor: tenant, run, tool, args hash,
        signature) and single-use; ALLOW (approval_id = request id) -> the executor performs the action, once
```

- **Audit order for a granted approval** (one tenant chain, one trace): `model_call`, `approval.requested`, `tool_call
REQUIRE_APPROVAL`, `approval.approved`, `tool_call ALLOW` (the gated execution), `model_call`. Approval events carry
  `enforcement_point: admin`, `action: approval.*` and `request=<id>` in `reason` (NEEDS #54).
- **Binding.** `args_hash` is computed by the kernel as `sha256(canonicalizePayload(context.args))`; the run id is
  `context.run.id`; the tool is the request `action`. A record for other arguments, another run or tool, another tenant, a
  tampered or forged record, or one already used is a DENY (and a failed verification does not consume it).
- **Never a bypass.** The record is evidence for the kernel's own check, not policy input; kill-switches, DENY policies and caps
  are evaluated before it is looked at (the e2e shows a second approved 6000 payment refused by a 10000 target cap and an
  approved action refused after a tenant kill-switch).
- **Fail-closed everywhere.** No requester injected: empty `approval_id`, which the runtime treats as DENY. Requester error, no
  run id, verifier error, consumed-store error, resolver unreachable/malformed/mismatched, an outcome other than APPROVED, a kernel
  that answers REQUIRE_APPROVAL again (no loop): nothing executes.
- **Ports.** Kernel: `ApprovalRequester`, `ApprovalVerifier`, `ConsumedApprovals` (`services/risk-kernel/src/approvals.ts`).
  Service side: `kernelApprovalPorts(service, signer)`. Runtime: `ApprovalResolver` / `HttpApprovalResolver`
  (`runtime/src/axis_runtime/approvals.py`), `RunDeps.approvals`.
- **Dev bridge** (`dev-bridge.ts`, NEEDS #62): POST JSON on 127.0.0.1: `/v1/approvals/{resolve,get,list,claim,approve,deny}`;
  `Authorization: Bearer <token>` selects the tenant (a body `tenant_id` is ignored; another tenant's request id is "not
  found" for every verb); the approver `principal` comes from the body. Start: kernel `main.ts` with
  `AXIS_APPROVALS_HMAC_KEY=<64 hex>` and `AXIS_APPROVALS_DEV_BRIDGE=1`. Not an approver API.

## Notifier adapters

`Notifier { channel, notify(n) }`; `SlackNotifier`, `TeamsNotifier` (webhook, https + host allowlist, no redirects, secret
URL never logged), `EmailNotifier` (address validation, CR/LF rejected). Transports are injected: `HttpTransport` /
`SmtpTransport`; real `FetchHttpTransport` and `SmtpClient` (implicit TLS, AUTH PLAIN only over TLS) are tested against
loopback servers, fakes elsewhere. Targets resolve per tenant; no target means skip.

## Verification

Coverage gate 95% lines/branches/functions/statements (`pnpm --filter @axis/approvals cov`). Property tests run 40 seeded
random operation sequences (create/approve/deny/claim/advance clock/sweep, with cross-tenant attempts) checking: decided
requests never change, expiry never yields approve, approvals are role-legitimate and non-self, audit chains verify,
tenants never mix. Mutation checks (manual, each killed by a test): self-approval, SoD, role, claim, tenant check, store
tenant scoping, expiry-approves, flip-after-decide, lazy advance, deadline boundary, cumulative eligibility, claim clearing,
`on_timeout`, approval without audit, escalation without audit, awaited notification, args-hash / tenant / signature /
outcome binding, webhook https, SMTP header injection, retry.
