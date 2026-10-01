# Approvals service (`@axis/approvals`)

Status: **Built as an in-process library** (in-memory store; no network surface). Evidence: `services/approvals` tests,
property tests, mutation checks (below). Gaps: `docs/NEEDS.md` #41-#47.

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
argument hash (no replay for different arguments or another tenant). **Any rejection (unknown id, signing/audit failure,
abort) must be treated as DENY.** The resolver re-checks SLA timers itself, so it resolves even if no sweeper runs.
No gRPC: it needs proto changes after the v1 freeze (NEEDS #43).

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
