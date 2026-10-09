# STRIDE: Billing and usage ledger

Status: Prototype (Stripe fake, real Postgres). Earlier model with 15 numbered threats: [billing-threat-model.md](billing-threat-model.md).

## Assets

- What each tenant is charged (integrity), tenant usage data (confidentiality), provider credentials, revenue.
- The sealed period records and the reconciliation result.

## Trust boundaries

1. Runtime usage emitter to ingest: scoped token, tenant from the token (`services/billing/src/emitters.ts`).
2. Billing to Stripe: test keys only, live-mode responses refused (`services/billing/src/stripe.ts`).
3. Stripe webhooks to billing: HMAC with tolerance, raw body (`services/billing/src/webhook.ts`).
4. Ledger to Postgres: insert-only grants, forbid-mutation triggers, sealed-period trigger (`packages/db/migrations/0008_billing.sql`).

## Data flow

Run log -> emitter (only events with a matching ALLOW decision are billable) -> ingest (idempotent per run and seq) -> ledger -> rating -> period close and seal (hash-chained, signed) -> invoice push -> reconcile.

## STRIDE

| Category               | Threat                                              | Mitigation (code path)                                                                                                                                               | Test                                                                         | Residual / NEEDS                                                       |
| ---------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Spoofing               | Usage forgery for another tenant or invented events | Only the `ingest` scope posts; a result bills only if the same run log holds an ALLOW with the same action id (`services/billing/src/emitters.ts`)                   | `services/billing/test/emitters.test.ts`                                     | A token holder can post a coherent log for its own tenant (NEEDS #169) |
| Tampering              | Rewriting history, editing a closed period          | Insert-only grants, forbid-mutation triggers, sealed-period trigger, hash-chained signed seals (`services/billing/src/seal.ts`, `services/billing/src/pg-ledger.ts`) | `services/billing/test/ledger.test.ts`                                       | Seal key is an HMAC secret (NEEDS #165)                                |
| Tampering              | Replay to double bill                               | Unique per tenant and idempotency key with payload hash (`services/billing/src/ledger.ts`)                                                                           | `services/billing/test/ledger-contract.ts`                                   | none known                                                             |
| Tampering              | Rounding drift or overflow                          | Single rounding rule, largest-remainder allocation, bigint with CHECK bounds (`services/billing/src/rating.ts`, `services/billing/src/money.ts`)                     | `services/billing/test/rating.test.ts`, `services/billing/test/core.test.ts` | Quantity ceiling per record (NEEDS #176)                               |
| Repudiation            | A quiet adjustment hides fraud                      | Adjustments need reason and actor, audit event first (fail closed), the original row stays (`services/billing/src/adjustments.ts`)                                   | `services/billing/test/service.test.ts`                                      | Network audit path is a dev port (NEEDS #170)                          |
| Information disclosure | Cross-tenant statement read                         | Forced RLS, token-bound tenant, read-only scope (`services/billing/src/pg-ledger.ts`)                                                                                | `services/billing/test/ledger.test.ts`                                       | none known                                                             |
| Information disclosure | Secrets in logs or errors                           | Errors carry codes only, a rejected key is never echoed (`services/billing/src/errors.ts`)                                                                           | `services/billing/test/stripe.test.ts`                                       | none known                                                             |
| Denial of service      | Billing outage stops agents                         | Metering is off the decision path; the emitter failure is swallowed, the run log is the durable source (`runtime/src/axis_runtime/usage.py`)                         | `runtime/tests/test_usage.py`                                                | Usage emitted once at run end (NEEDS #200)                             |
| Elevation of privilege | A live Stripe key is used from a dev stack          | Constructor refuses anything but test keys (`services/billing/src/stripe.ts`)                                                                                        | `services/billing/test/stripe.test.ts`                                       | A test key can still create real test-mode objects                     |
| Elevation of privilege | Forged webhook                                      | HMAC `t.payload`, constant-time compare, 300 s tolerance, duplicate event ids ignored (`services/billing/src/webhook.ts`)                                            | `services/billing/test/stripe.test.ts`                                       | De-duplication is per process (NEEDS #210)                             |

## Prompt injection

Billing consumes structured run events (counts, ids, meters) and never model text; events carry no content (`services/billing/src/emitters.ts`). An injected agent can cost the tenant money only by performing allowed, metered actions, which tenant budgets and the tool-call budget cap (red-team category `budget-flood` in `evals/redteam/datasets/redteam-core.json`).

## Tool misuse

A flood of allowed calls is bounded by the blueprint's `toolCalls` hard budget and the tenant's budgets; the suite asserts at most 12 performed calls out of 100 requested (cases `rt-bf-003` to `rt-bf-005`). Invoice and usage mutations are API-only with scoped tokens.
