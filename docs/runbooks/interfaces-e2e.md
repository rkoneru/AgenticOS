# Runbook: the interfaces e2e (`make e2e-phase7`, `make console-e2e`)

What it proves: every core workflow works from the TypeScript SDK, the Python SDK, the `axis` CLI and the console against the real stack
(ADR 0054). Prerequisites are those of `make e2e-core` (Node 22, pnpm, uv, `opa`, PostgreSQL 16 + pgvector via `infra/scripts/with-pg.sh` or `PG_ADMIN_URL`)
plus Playwright's Chromium (`PLAYWRIGHT_BROWSERS_PATH`) for the console.

## Commands

```bash
make e2e-phase7      # pnpm build; 36 pytest tests (12 steps x 3 clients) on the real stack; then the bypass guard
make console-e2e     # build console; bundle secret scan; 60 mock-API flows; then 14 real-stack Playwright tests
make e2e             # both
uv run python e2e/mutation_phase7.py [substring ...]   # by hand: 6 wiring mutants, each must be KILLED
# a stack for poking at: boots everything, writes its description, runs your command, tears down
bash infra/scripts/with-pg.sh uv run python e2e/interfaces_stack.py --out /tmp/stack.json -- sleep 3600
```

## The stack (one OS process each)

| Process                          | Entry                                  | Notes                                                                                |
| -------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------ |
| Risk Kernel (gRPC) + approvals   | `services/risk-kernel/src/main.ts`     | per-tenant bundles from a directory, reloading token file, approvals dev bridge      |
| Control plane, billing, ops, IdP | `e2e/scripts/interfaces-stack.mjs`     | fake IdP page, fake KMS/DNS, marketplace publisher/staff side, token files           |
| Run service                      | `e2e/scripts/interfaces_run_server.py` | scripted model + deterministic tools; kernel gate, BYO key, usage emitter, approvals |
| API gateway                      | `apps/api-gateway/dist/main.js`        | the standalone DEV process; env contract in `docs/spec/api-gateway.md` section 7a    |
| Console (console suite only)     | `next start -p 3100`                   | BFF to gateway and control plane; `AXIS_IDP_ORIGINS` for the sign-in redirect        |

Logs: pytest keeps them in its temp dir (`kernel.err`, `stack.err`, `runserver.err`, `gateway.err`). A stack that does not start fails the run (never skips).

## Troubleshooting

- `PG_ADMIN_URL is required`: run through `make` (it wraps with-pg) or export it.
- Sign-in loops back to `/login` in the console suite: the IdP origin is missing from `AXIS_IDP_ORIGINS` (form-action CSP), or the browser is not on `localhost`
  (`__Host-` Secure cookies are accepted by Chromium only from `https` or `localhost`).
- `registry publish` verification failure: the signature is only trusted from the moment its key became valid; register the key, wait a second, then sign.
- A run that never reaches an approval: the tenant's pack is not active (`axis policies activate`), so the kernel denies the tool (baseline-deny).
- Port 3100 busy: another `next start` (a previous console run) is still alive.
