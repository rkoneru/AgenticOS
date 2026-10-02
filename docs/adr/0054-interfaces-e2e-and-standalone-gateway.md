# 0054. Interfaces e2e on the real stack, the standalone gateway process and the console's two upstreams

Status: Accepted · Date: 2026-10-02 · Related: 0024, 0026, 0042, 0050, 0053 (OpenAPI 1.2.0), 0022

## Context

Phase 7 components (gateway + AGIL, registry + marketplace, SDKs + CLI, console) were built and tested against mocks and in-process fakes.
The exit requires every core workflow through the console, the CLI and both SDKs against the REAL stack. Three structural gaps stood in the way:
the gateway had no process entry (NEEDS #218), the console assumed one upstream and a cookie-reading API, and nothing booted all the services together.

## Decision

1. **Standalone gateway (`apps/api-gateway/src/main.ts`).** A DEV composition configured only from the environment (`configFromEnv`, validated, no
   permissive defaults): Postgres store/audit/ledger/registry/marketplace, the control plane's secrets (so its sessions and API keys verify), the Risk
   Kernel gRPC target, the run service URL and the approvals dev bridge. Per-tenant credentials for the run service, the kernel and the bridge are
   JSON token files re-read on change (`TokenTable`), because tenants are created after the process starts. It REFUSES `NODE_ENV=production`
   and non-loopback hosts: the adapters (static tokens, fake publisher provers, in-memory blueprint store) are dev-only.
2. **Approvals through the kernel's bridge.** The approvals service lives in the kernel process today; the gateway reaches it with an
   `HttpApprovalsClient` (tenant = the bearer's, principal built from the authenticated gateway principal, every non-clean answer an error). The kernel's
   bridge now authenticates late-created tenants from the same reloading token table the gate uses.
3. **Run service launcher.** `runtime/scripts/run_server.py` gained the approvals resolver (REQUIRE_APPROVAL waits for a human, then the kernel re-gates)
   and optional `model_transport` / `tools_factory` hooks. `e2e/scripts/interfaces_run_server.py` supplies the only fakes on the run path: a scripted
   OpenAI-shaped model transport and deterministic tools.
4. **One harness for every client.** `e2e/interfaces_stack.py` boots Postgres (throwaway DB, all migrations), the kernel, `interfaces-stack.mjs`
   (control plane, billing ingest, publisher/staff side of the marketplace, a fake-IdP authorize page, ops), the run service and the gateway process.
   It is a library for pytest and a command (`--out stack.json -- <cmd>`) for the console suite. Ops provision tenants, members, sessions and API
   keys through the same service classes the HTTP surfaces use; they never write tables.
5. **Console upstreams.** `/v1/*` goes to the gateway and `/admin/v1`, `/auth/*` to the control plane (`AXIS_API_URL`, `AXIS_CONTROL_PLANE_URL`, read at run
   time). The gateway authenticates a bearer token, never a cookie: the BFF converts the HttpOnly session cookie into `Authorization: Bearer` for gateway
   calls and drops whatever the browser sent in `Authorization`, `Cookie` and `X-Axis-Api-Key` there. The SSO redirect proxy is a route handler (no build-time
   rewrite). CSP `form-action` gets the IdP origins (`AXIS_IDP_ORIGINS`): Chromium applies it to the sign-in form's redirect chain.
6. **Publisher tooling signs.** Registry provenance carries the ABL compiler's lint results, so signing runs the compiler: `axis registry sign` (offline,
   key in a 0600 PEM) and the e2e's publisher step. The Python SDK and the console transport/verify but never sign (a private key never enters a browser).

## Consequences

- Real defects were found only by this wiring and are fixed: `explainRun` asked the run service for 1000 events (limit 200); the console replay folded
  mock-only event names (`state_transition`) instead of the runtime's (`process_transition`, `tool_call_result`, `process_output`); the sign-in form was
  blocked by `form-action 'self'`; the mutation audit hashed an undefined body.
- The harness is dev-only and fake-backed at the IdP, KMS, DNS, model provider and marketplace provers (NEEDS #272-#283).
- The e2e covers three non-browser clients with one workflow and the console with its own real-stack suite; mutation script `e2e/mutation_phase7.py`.
