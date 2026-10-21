# ADR 0118: Risk Kernel gRPC health-checking protocol

## Status

Accepted

## Context

NEEDS #507: the Risk Kernel is gRPC-only (`services/risk-kernel/src/grpc.ts`) with no
implementation of the standard gRPC health-checking protocol
(`grpc.health.v1.Health`). Its chart (`infra/helm/charts/risk-kernel`) therefore used a
bare `tcpSocket` liveness/readiness probe: proof the listener accepts a TCP connection,
not that the process answers a real RPC correctly, that its policy bundle loaded, or
that anything past the kernel of the OS network stack is actually working.

## Decision

- Vendor the standard health proto verbatim at `proto/grpc/health/v1/health.proto`. This
  is not an AXIS contract — its shape is fixed upstream (`grpc.health.v1.Health`, the
  `Check`/`Watch` RPCs) — so it is not subject to CLAUDE.md's "proto is frozen v1, ADR to
  change" rule for `proto/axis/**`; this ADR is about adding a vendored _copy_ of a
  third-party standard, not about changing an AXIS contract.
- Implement it by hand in `services/risk-kernel/src/grpc.ts` (`addHealthService`)
  against `@grpc/grpc-js`/`@grpc/proto-loader`, both already dependencies, rather than
  adding the `grpc-health-check` npm package as a new dependency. The implementation is
  ~30 lines; a new pinned dependency (plus the monorepo-wide `pnpm-lock.yaml` churn of
  adding it) was judged not worth it for that size, and hand-rolling against the same
  proto-loader pattern `createGateServer` already uses keeps the two services'
  implementations consistent.
- `isServing` defaults to always-`SERVING`: by the time `main.ts` reaches
  `createGateServer`/`addHealthService`, the policy bundle has already loaded
  synchronously (`WasmPolicyEngine.fromBundle` / `TenantBundleEngine`) — a load failure
  exits the process before any server exists to probe, so there is no "listening but not
  ready" state for this process to report. The parameter exists so a future caller (or a
  test) can wire a real readiness predicate without changing the protocol surface.
- Wire the chart's `livenessProbe`/`readinessProbe` to Kubernetes' native `grpc` probe
  type (`readinessProbe.grpc.port`, stable since 1.27, alpha since 1.24) instead of
  `tcpSocket`. It dials `Check` on the given port with no TLS, matching the kernel's
  `grpc.ServerCredentials.createInsecure()`.

## Consequences

- A pod only becomes/stays Ready once it answers a real `Check` RPC, not merely once its
  listener accepts a connection — closing the gap NEEDS #507 described.
- `helm template` + `kubeconform -strict -kubernetes-version 1.29.0` renders and
  validates the new probe shape cleanly (no new chart inputs needed: the probe just
  points at the existing `service.port`).
- Verified with a real gRPC client (`services/risk-kernel/test/health.test.ts`) dialing a
  real running server over a real socket, not just unit-level mocking: `Check` on the
  overall server and a named service both return `SERVING`, `Watch` streams the current
  status and stays open until cancelled, and a server wired with a custom `isServing`
  predicate correctly answers `NOT_SERVING` for a service name it marks down.
