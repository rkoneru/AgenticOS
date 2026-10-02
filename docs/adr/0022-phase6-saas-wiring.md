# 0022. Phase 6 wiring: control plane, kernel, runtime and billing as one SaaS path

Status: Accepted · Date: 2026-10-02 · Related: 0004 (Wasm policy), 0017 (Phase 5 wiring), 0018/0019 (billing), 0020/0021 (control plane)

## Context

Components A (control plane) and B (billing) were built as libraries with dev surfaces. Phase 6 exit needs them wired into one
path: a tenant signs up via SSO, configures a BYO key, a policy pack and a budget, runs agents, and sees metered usage that is
accurate. Contracts stay frozen (no proto, OpenAPI, audit-event or migration change; the admin API stays the internal `/admin/v1`).
Everything added below is a DEV mechanism unless stated; each is recorded in `docs/NEEDS.md` #197-#205.

## Decisions

1. **The tenant's activated policy reaches the kernel as a compiled bundle in a directory.** `PolicyBundlePublisher` (control plane)
   builds the Wasm bundle from `PolicyPackService.effective(tenant)` (which re-validates the whole active set with the policy
   toolchain: DSL schema, compile, `opa check --strict`, Wasm build) and hands it to a `BundleSink`. The dev sink writes
   `<tenant uuid>.tar.gz` atomically. It runs after signup (the baseline-deny floor exists before any pack) and after every
   activation/deactivation. The kernel dev process, started with `AXIS_POLICY_BUNDLE_DIR` instead of `AXIS_POLICY_BUNDLE`, serves each tenant
   its own bundle through `TenantBundleEngine`: the tenant is the one in the policy input (filled from the authenticated gRPC
   principal), a bundle is reloaded when its file changes, and **no bundle / a corrupt bundle / a non-UUID tenant rejects the
   evaluation, which the kernel turns into an audited DENY** (no fallback to a default or to another tenant's policy). Alternatives
   rejected: the kernel reading the control plane's database (couples the decision path to the identity store and its RLS) and
   one global bundle (no per-tenant policy). Publication failure after a committed activation surfaces as 503 and leaves the
   kernel on the previous bundle (a documented staleness window; a retry republishes).
2. **The runtime gets its BYO key through `HttpSecretStore`**, a `SecretStore` over `ControlPlaneBridge`
   (`runtime/.../controlplane.py`): `POST /internal/v1/model-keys/reveal` with the per-tenant runtime bearer. The control plane derives
   the tenant from the token; the client also refuses to ask for another tenant. `put` is refused (keys are set through the admin
   API). The only new `httpx` allowlist entry is `controlplane.py` (the bypass scanner is unchanged otherwise; the store itself has
   no HTTP). Plaintext crosses loopback (NEEDS #186).
3. **Budgets reach TKI.** `GET /internal/v1/budget-config` (same runtime bearer) returns `AdminService.budgetConfig`. `TenantBudgets`
   (`runtime/.../tenant_budgets.py`) opens the TKI ledger's TENANT account with the tenant limits and merges the run limits with the
   blueprint's ABL limits by taking the TIGHTER cap per resource (a tenant admin can lower, never raise, what a blueprint declares).
   An unknown metric or malformed entry raises instead of being dropped (a cap that cannot be read must stop the run). The ledger is
   in memory and has no time window, so `day`/`month` periods are enforced over the ledger's lifetime (NEEDS #198).
4. **Metering is a `RunDeps.usage` hook.** When set, the run forwards its own log through a `UsageEmitter` (`HttpUsageEmitter`) when
   it ends, off the decision path (failures are logged). The service, not the runtime, decides what is billable (ALLOW join, ok
   results, cache hits bill zero). **The send is shielded from cancellation**: the e2e's accuracy check found that runs stopped by
   a budget trip or a kill were cancelled mid-emission and never billed although the provider had billed the tokens. Idempotency keys
   make re-sending safe, so the shielded send only adds latency (bounded by the emitter timeout).
5. **Control-plane audit hashes are JSON, not integers.** The admin audit used the integer-only canonicalizer, so a fractional budget
   (`cost_usd: 0.001`) was refused as "audit unavailable" (503). `inputs_hash`/`outputs_hash` use `hashJson`, the contract's helper for
   arbitrary payloads. No contract change.
6. **Dedicated databases: the audit sink routes by placement.** `RoutedAuditLog` resolves the tenant's pool with `TenantRouter` per append
   and per read (fail-closed: no placement, no pool or the shared pool for a dedicated tenant is `unavailable`, never a write to the wrong
   database, and the admin layer then does not perform the mutation). Only the admin audit routes today (NEEDS #204).
7. **The e2e harness (`e2e/scripts/saas-stack.mjs`) hosts the control plane and billing in one Node process** with a loopback "ops" port for
   what a human or another system does in production (the fake IdP user authenticating, the platform operator linking an SSO
   organization, registering static tokens, moving the billing clock, closing a period, pushing and reconciling with the payment
   fake, injecting provider faults). Ops calls go through the same classes the HTTP surfaces use. The Risk Kernel runs as its own process
   over gRPC, as in earlier phases. Stripe is represented by `FakePaymentProvider` (strict idempotency, fault injection, lists
   records); the real Stripe adapter is only exercised for its live-key refusal.

## Consequences

- `make e2e-phase6` and a CI job mirror `e2e-phase5`; the bypass guard stays green.
- New dev knobs: kernel `AXIS_POLICY_BUNDLE_DIR` (token file re-read on change), control-plane `bundleSink`, billing `now`.
- Cost: the kernel re-stats a tenant's bundle per evaluation (cheap) and keeps one Wasm instance per tenant in memory.
- The e2e found and fixed two real defects (fractional budget audit, unbilled cancelled runs); both have unit regressions.
