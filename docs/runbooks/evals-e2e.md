# Runbook: evals end to end (Phase 8)

Dev only (NEEDS #293-#334). See `eval-hub.md` for the hub and `docs/spec/evals-runner.md` for the runner.

## Run the proof

`make e2e-phase8` (Postgres 16, `opa`, node, uv; about 100 s) and `make console-e2e` (adds the evals pages). `make evals` is the fast subset
without the stack. `uv run python e2e/mutation_phase8.py [substring]` runs the 13 wiring mutants (about 20 minutes).

## Stand it up by hand

1. Gateway env: `GW_EVAL_RUNNER_TOKENS_FILE=<file>` (`{"<runner token>": {"tenantId": "...", "runnerId": "runner-a"}}`, re-read on change) and
   `GW_EVAL_RUNNER_PORT`; the readiness line prints `eval_runner_port`.
2. Run service: `read_tokens` (`{token: tenantId}`) for the online feed.
3. Tenant admin registers the runner: `axis evals runners register runner-a`. An unregistered or revoked runner cannot claim or submit and its
   runs stop counting at once.
4. Runner config (`EVAL_RUNNER_CONFIG`): tenant, `hub_url` (the runner port), runner id/token, kernel target/token, control plane URL/runtime token;
   `uv run python runtime/scripts/eval_runner.py` (CI mode) or `--online` with `run_service_url` and `run_read_token`.
5. Tenant policy must allow the judge: merge `policies/eval-judge/pack.yaml` into the active pack, or every model grade is `ungraded`.

## Release workflow

Create dataset and suite, publish the blueprint (signed) with `spec.evals.suites`, `axis evals run <suite> <ns/name@ver> --wait`, human tasks are graded
by someone who neither published nor started (`axis evals review ...`), `axis evals gate <ns/name@ver>` (exit 0 allowed, 4 blocked, reasons printed),
then release. `axis registry attestations <ns/name@ver>` shows the signed history. A newer run waiting for a human holds the gate (`run_in_progress`).

## Triage

- `gate_unavailable`: the registry/marketplace service is not wired to the hub (default deny).
- `missing_run` / `no_run_for_content_hash`: no run of exactly this content; rerun after any prompt change.
- `runner_not_registered`: register, or rerun on a registered runner.
- `regression`: `axis evals compare <run>`; the baseline moves only on a release or an admin `baseline set`.
- Model grades all `ungraded`: the judge rule is missing (`eval_judge` DENY rows in the audit log) or the BYO key is.
- An eval run left approval requests in the queue: the kernel is older than the `eval_mode` marker.
