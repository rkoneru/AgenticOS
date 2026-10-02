# Runbook: API gateway and run service (dev)

## Run the tests

```
pnpm --filter @axis/api-gateway test          # unit + integration (real OPA, real gRPC kernel, real Python run service)
pnpm --filter @axis/api-gateway cov           # thresholds in vitest.config.ts
pnpm --filter @axis/api-gateway mutation      # ~3 min: every guard mutant must be killed
pnpm --filter @axis/agil cov
cd runtime && uv run pytest tests/test_runserver.py tests/test_bypass.py
```

## Run the services

- Gateway: embed `wireGateway(...)` in a stack script (see `e2e/scripts/saas-stack.mjs`); `GatewayOptions.log` receives one `request`
  line per request (`op`, `status`, `tenant`, `request_id`, `trace_id`, `ms`).
- Run service: `RUNSERVER_CONFIG=<json> uv run python runtime/scripts/run_server.py` (config documented in the script header); it prints
  `{"port": N}`. Test double: `runtime/tests/runserver_fake_main.py <token> <tenant>`.

## Triage

| Symptom                                   | Check                                                                                                                                                                  |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 401 with a good key                       | key revoked/expired, owner suspended; both `Authorization` and `X-Axis-Api-Key` sent (400); remote address in the failed-auth bucket (429)                             |
| 403 `forbidden`                           | role matrix (`policies/control-plane/authz.cases.yaml`), API key scope `<resource>:read\|write`; the denied mutation is in the audit chain with the request's trace id |
| 403 `policy_denied`                       | the authorization pack could not be evaluated (engine error, timeout, no pack): fail-closed; check the control plane                                                   |
| 503 on a mutation                         | audit append failed (the operation did NOT run), run service/kernel down, or no per-tenant token configured                                                            |
| 500 + log "violates the OpenAPI contract" | a handler or port returned a shape the contract forbids: fix the producer, not the validator                                                                           |
| run stuck "spawn"/"waiting"               | run service log; TKI budget; model key missing (the run ends `failed`)                                                                                                 |
| `409` on a signal                         | the process has terminated                                                                                                                                             |
| `422 idempotency key reuse`               | the client reused a key for a different request                                                                                                                        |
| 429                                       | per-tenant bucket (`Retry-After`), SSE stream cap, or run service active-run cap                                                                                       |

## Break glass

A tenant kill-switch: `PUT /v1/kill-switches {"scope":"tenant","engaged":true}` (owner/admin/operator). It is applied in the Risk Kernel
first; if the kernel is down the call fails (503) and nothing is recorded: use the kernel's own admin path.
