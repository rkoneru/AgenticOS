# Runbook: SaaS end-to-end (`make e2e-phase6`)

What it proves, how to run it, how to read a failure, and what is fake. ADR 0022 explains the wiring.

## Run

```bash
make e2e-phase6        # pnpm build, the e2e on throwaway Postgres 16 (two databases), then the bypass guard
uv run python e2e/mutation_phase6.py [name-substring ...]   # mutation check of the wiring (about 40 s per mutant)
```

Prerequisites: node 22, pnpm, uv, `opa` (>= 0.70) and `psql` on PATH, PostgreSQL 16 (`PG_ADMIN_URL`, or `infra/scripts/with-pg.sh` starts one).
No Chromium, no user namespaces. The test creates two databases (`axis_e2e6_*`: shared/control, `axis_e2e6d_*`: the dedicated tier) and
drops them afterwards.

## Processes

| Process                                                 | Real or fake                                                                                                               |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Risk Kernel (`services/risk-kernel`, gRPC)              | real; `AXIS_POLICY_BUNDLE_DIR` (per-tenant bundles), token file re-read on change, Postgres audit chain                    |
| `e2e/scripts/saas-stack.mjs`: control plane HTTP        | real code on Postgres; FAKE IdP, KMS, DNS; real authorization pack on OPA Wasm; real policy toolchain; platform token      |
| same process: billing ledger, invoices, dev HTTP server | real code on Postgres (forced RLS); payment provider = `FakePaymentProvider` (Stripe test-mode semantics)                  |
| same process: ops port (loopback, bearer)               | the test's hands: fake-IdP user, platform operator, tokens, billing clock, period close, push, reconcile, faults           |
| pytest process: runtime                                 | real: `HttpSecretStore`, TKI + tenant budgets, NEXUS cache, `RunDeps.usage` -> `HttpUsageEmitter`; scripted model provider |

## Scenario (`e2e/test_phase6_saas.py`, stateful, in file order)

1-2 SSO signup (platform signup, operator links the IdP org, the owner signs in through the fake IdP) and its refusals;
3 key, budget over HTTP, read back by the runtime; 4-6 the agent is DENIED under baseline-deny alone, then the tenant publishes, validates
and activates a pack, the bundle reaches the kernel and the tenant's own DENY is enforced, the provider is called with the BYO key;
7 cache hit (gated, zero tokens); 8-9 tenant token and cost hard caps from the control plane stop runs; 10 ledger totals equal totals
recomputed from the model provider's counts, the audit chain and the run logs; 11 replayed/conflicting/forged usage; 12 period close,
seal verification, invoice vs independent recomputation, push and clean reconciliation against the Stripe fake; 13 injected duplicate,
dropped and altered provider records are reported and nothing is repaired; 14-21 RBAC, cross-tenant attacks, API keys, SCIM
deprovisioning, region pinning, live-key refusal, dedicated database routing and the kernel's fail-closed behaviour without a bundle.

## Reading a failure

- Stack does not start: `<tmp>/e2e6*/kernel.err` and `saas.err` (pytest prints the path). Usually a missing `opa`, `psql` or a build that is stale (`pnpm build`).
- Test 6 DENY on `model_call`: the bundle did not reach the kernel. Check `<tmp>/bundles/<tenant>.tar.gz` and the control plane's 503 on activation.
- Test 10 mismatch: compare per-run entries (`ops/billing/entries`) with the run logs; a missing run usually means its emission failed (see the
  `usage emission failed` warning) or was cancelled (it must be shielded, ADR 0022 item 4).
- Test 12 `PERIOD_NOT_CLOSABLE`: the harness clock override (`ops/clock`) was not applied. The scenario assumes it does not straddle a UTC month boundary.
- Anything flaky in `pnpm cov` is NEEDS #196, not this test.

## Fakes and gaps

Listed in `docs/NEEDS.md` #197-#205 and the Phase 6 entry of `CHANGELOG.md`: static dev tokens for the bridges, file-based policy bundles,
an in-memory TKI ledger with no time windows, no real WorkOS/KMS/DNS/Stripe/ClickHouse, usage emitted at run end only, no data moved on a
placement change.
