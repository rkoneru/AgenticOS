# 0004. OPA deployment mode: embedded Wasm by default, sidecar optional

Status: Accepted · Date: 2026-09-30

## Context

The gate must decide in p99 < 10 ms and add < 25 ms to a tool call, fail closed on any error, and support kill-switch propagation < 1 s.

## Options

1. **OPA sidecar** (HTTP/gRPC on localhost): simple, full OPA feature set, hot bundle reload; adds a network hop and a failure mode.
2. **Embedded Wasm** (compiled Rego loaded in-process by the Risk Kernel): no hop, sub-millisecond evaluation; bundle loading handled by us; subset of OPA built-ins.

## Decision

The Risk Kernel evaluates compiled Wasm bundles in-process by default. The same Rego bundle also runs on a sidecar (`policy.mode: sidecar`) for deployments that want OPA's management tooling and for `axis policy test` (which uses `opa test`). Both paths go through one `PolicyEngine` interface. Any engine error, timeout (default 5 ms budget, configurable) or missing bundle returns `DENY`.
Kill-switch state is not stored in Rego data bundles; it is a Redis-backed flag with pub/sub evaluated by the gate _before_ policy evaluation, so propagation does not wait for a bundle rebuild.

## Consequences

The policy compiler must emit Wasm-compatible Rego (no `http.send`, no unsupported built-ins); a compiler test enforces this. The compose stack still runs an OPA container for sidecar mode and policy tests.
