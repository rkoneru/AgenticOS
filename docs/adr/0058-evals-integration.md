# 0058. Evals integration: the gate rule, the runner surface, the eval-mode marker

Status: Accepted · Date: 2026-10-08 · Related: 0056, 0057, 0059

## Context

Phase 8 exit needs the hub, a real runner, the kernel, the registry/marketplace and the clients to work as one system. Wiring them found gaps the
components could not see alone.

## Decisions

1. **The gate is asked whenever a hub is wired.** `RegistryService` asks the gate for every release and submit-for-review when constructed with an
   `evalGate`, even if the ABL declares no suites: the hub adds the tenant's `required_for_release` suites that `applies_to` the blueprint and allows
   when nothing is required. A registry with no gate wired still releases a blueprint that declares no suites (nothing could know of a requirement);
   one that declares suites is refused (default `DENY_ALL_EVAL_GATE`). Rule recorded in `docs/spec/eval-hub.md`.
2. **`POST /v1/evals/gate` asks the stored ABL's suites.** The gateway resolves the version (registry or tenant store), adds the suites its ABL declares
   to whatever the caller sent, and answers 422 when the supplied content hash is not the stored one. A caller that forgets `suites` can no longer
   get ALLOWED. A version that is not stored is a hypothetical question answered for the given suites alone.
3. **Runner surface.** The standalone gateway can host the hub's runner API on a second loopback port (`GW_EVAL_RUNNER_TOKENS_FILE`, tokens
   `{tenantId, runnerId}`, HMAC bodies) beside the tenant API, sharing the one hub instance, gate and attestation key.
4. **Manifest source.** `GET /v1/evals/runner/manifest?name&version[&namespace]` returns the compiled manifest only to a runner that holds a
   RUNNING run of exactly that version; the gateway compiles it from the registry (re-verified) or the tenant store. The runner still refuses a hash
   that is not the queued one.
5. **Online feed.** The run service serves `GET /v1/completed-runs` to a separate read-only token only: tenant-scoped, credentials scrubbed, tool results
   as hashes, no input. `eval_runner.py --online` samples from it. Online human-review tasks are queued by the hub (text redacted again) and complete
   as appended records; online data is never read by a gate.
6. **Eval-mode marker.** `EvalModeGate` adds `context.eval_mode: true` to requests it forwards. The kernel strips it before policy evaluation and, for a
   REQUIRE_APPROVAL, returns the decision with the constant approval id `eval-dry-run` and opens no approval request. It can only remove a side
   effect. (An eval payout previously opened a real request in the tenant's queue.)
7. **Canonical numbers.** The runner's canonical JSON prints numbers as JavaScript does; vectors are shared by both test suites.
8. **Judge policy.** `policies/eval-judge` ships the rule; tenants merge it. Without it model grades are `ungraded` (0).

## Consequences

- Production must run ONE registry/marketplace service wired to the hub; the e2e harness's staff side is wired to the same hub data (NEEDS #331).
- Kernel and runner tests cover the marker; `docs/spec/evals-runner.md` section 3 is updated. NEEDS #325-#334 list what remains.
