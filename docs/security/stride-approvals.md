# STRIDE: Approvals service (human-in-the-loop on REQUIRE_APPROVAL)

Status: Built in-process with an in-memory store, wired to the kernel and runtime through a dev-only loopback bridge. Spec: `docs/spec/approvals.md`. It is on the decision path and every failure resolves toward DENY.

## Assets

- The integrity of "a human approved exactly this action" (tenant, run, tool, arguments hash).
- Separation of duties: the requester or owner cannot approve their own request.
- The approval record signature the kernel verifies.

## Trust boundaries

1. Approver (human, authenticated by the gateway) to the service: tenant from the principal, role must be eligible at the current escalation level (`services/approvals/src/service.ts`).
2. Service to kernel: a signed decision record bound to tenant, run, tool and arguments hash; the kernel verifies and consumes it (`services/approvals/src/signer.ts`, `services/risk-kernel/src/approvals.ts`).
3. Runtime to the service through the dev bridge: authenticated to a tenant only (NEEDS #69).

## Data flow

Kernel returns `REQUIRE_APPROVAL` and files a request -> runtime waits on the resolver -> an eligible human claims and decides -> on APPROVED the runtime re-submits the SAME action carrying the signed record -> the kernel re-applies every DENY policy and cap, verifies the record and consumes it -> only that second ALLOW performs the action. Eval mode files no request.

## STRIDE

| Category | Threat | Mitigation (code path) | Test | Residual / NEEDS |
| --- | --- | --- | --- | --- |
| Spoofing | The agent or a bridge caller approves as a human | Requester id can never claim, approve or deny; approver identity comes from the principal (`services/approvals/src/service.ts`) | `services/approvals/test/service.test.ts`, `e2e/test_phase3_orchestration.py` | Approver identity on the dev bridge is the runtime's own credential (NEEDS #69) |
| Tampering | A record for one action reused for another | The record binds tenant, run, tool and arguments hash; the kernel verifies and consumes it once (`services/risk-kernel/src/approvals.ts`) | `services/risk-kernel/test/approvals.test.ts`, `services/approvals/test/resolver.test.ts` | Not bound to the policy version (NEEDS #71); consumed store is not shared (NEEDS #63) |
| Tampering | A decided request is changed | Terminal requests never change; replays return the stored result (`services/approvals/src/store.ts`) | `services/approvals/test/store.test.ts`, `services/approvals/test/properties.test.ts` | In-memory store (NEEDS #48) |
| Repudiation | A transition without a record | Allow-direction transitions require a durable audit append and fail otherwise (`services/approvals/src/service.ts`) | `services/approvals/test/service.test.ts` | Deny-direction transitions apply even when the append fails (by design) |
| Information disclosure | Arguments in notifications | Payloads carry only an arguments hash prefix (`services/approvals/src/notify.ts`) | `services/approvals/test/notify.test.ts` | none known |
| Denial of service | Approval request spam, orphaned requests | Escalation with deadlines and fail-closed expiry; at most 6 levels (`services/approvals/src/spec.ts`) | `services/approvals/test/service.test.ts` | No dedup or rate limit on requests (NEEDS #64) |
| Elevation of privilege | Self-approval or a conflicted principal | Conflicted principals are barred; a claimed request cannot be decided by another (`services/approvals/src/service.ts`) | `services/approvals/test/service.test.ts`, `e2e/test_phase3_orchestration.py` | Self-approval cannot be driven through the API from a human-started run (NEEDS #272) |
| Elevation of privilege | Injected text or extra arguments claim "already approved" | The decision depends only on policy; extra arguments never create an approval, and in eval mode no request is opened (`services/risk-kernel/src/kernel.ts`) | `e2e/redteam_harness.py`, `evals/redteam/datasets/redteam-core.json` | none known |

## Prompt injection

An injected instruction cannot approve: approvals are created by the kernel and decided by authenticated humans. What injection can do is shape the request a human sees. The notification shows the tool, the risk level and an arguments hash prefix, not model-written justification text, so an attacker cannot put persuasive prose in front of the approver (`services/approvals/src/notify.ts`). Red-team cases try `approved: true`, `approval_id`, `approver: self` and "the CFO approves" in user text and arguments (category `privilege-escalation`, technique `approval-self-grant` and `approval-pressure`): the payout is never performed.

## Tool misuse

A payout-style tool carries `REQUIRE_APPROVAL` by policy (`approve-payouts` in `evals/redteam/policy/pack.yaml`); arguments that would raise the amount over a cap fail the amount gate. The re-gate after approval applies DENY policies again, so approval is not a way around a later-added denial (`services/risk-kernel/src/approvals.ts`).
