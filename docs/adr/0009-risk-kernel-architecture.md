# 0009. Risk Kernel architecture and cross-language split

Status: Accepted · Date: 2026-09-30

## Context

The control plane is TypeScript; the agent runtime is Python. The gate must be one implementation so its guarantees cannot diverge.

## Decision

- One Risk Kernel, written in TypeScript (`services/risk-kernel`), exposed as gRPC `GateService` (contract frozen in Phase 1).
  The Python runtime is a _client_ (`GateClient`) and contains no policy logic.
- Policy: the DSL compiles to Rego (`packages/policy`). The kernel evaluates compiled **Wasm** bundles in-process (ADR-0004);
  the same Rego is run by `opa test` in `make policy-test`.
- Order inside `Evaluate`: kill-switch check → request validation → policy evaluation (timeout budget) → gates listed by the
  winning rule → audit append → respond. Any exception, timeout, unknown value or audit failure yields DENY.
- The kernel owns the gate semantics (kill_switch, staleness, amount_cap, target_cap, budget, rate_limit) in TypeScript, because
  they need state (counters, clocks, kill flags) that Rego bundles should not hold; Rego decides _which rule/gates apply_, the
  kernel evaluates the gates. Compiler output therefore embeds rule metadata the kernel reads (`data.axis.rules`).
- Stateful gate stores are interfaces (`KillSwitchStore`, `CounterStore`) with in-memory implementations now and Redis
  implementations later (Phase 6 hardening); in-memory is single-process only and is labelled as such.

## Consequences

Runtime tests need either a fake `GateClient` (unit) or a spawned kernel (integration/e2e). The bypass test therefore lives in
both languages: Python proves every action path calls the client; TS proves the kernel denies on every failure mode.
