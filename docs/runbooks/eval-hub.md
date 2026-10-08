# Runbook: Eval Hub

Dev only (NEEDS #293-#305). The dev server (`services/eval-hub/src/main.ts`) refuses `NODE_ENV=production`.

## Register a runner

`axis evals runners register <runner-id>` (admin). Only registered, non-revoked runners count for a gate. Revoke is one-way:
`axis evals runners revoke <id>`; its runs stop counting immediately.

## Release check

`axis evals gate <ns/name@version> [--suite ref[:threshold]]` exits 0 allowed, 4 blocked (reasons printed). Common reasons:
`missing_run` (run `axis evals run <suite> <ref> --wait`), `stale_run` (rerun), `regression` (`axis evals compare <id>`),
`runner_not_registered` (register or rerun on a registered runner), `integrity_failed` (see below), `gate_error` (hub unavailable; the
gate fails closed, check hub logs and the audit log).

## Integrity failure

The hub recomputes scores from the stored grid. `integrity_failed:<check>` means the stored run, dataset or suite no longer matches its
hash. Treat as an incident: do not re-promote; preserve the audit chain, revoke the runner, rerun.

## Human review queue

`axis evals review tasks --state open`, `claim`, `grade --score --comment`, `skip --reason`. Breached SLAs show `(BREACHED)`. A
publisher or run starter cannot review their own work; an admin adjudicates disagreements.

## Baselines

Promoted automatically on release. A bad baseline: `axis evals baseline set <passed-run-id>` (admin; append-only, audited). A baseline
whose run no longer verifies makes the gate block (`baseline_invalid`).

## Online sampling

`axis evals sampling put|list|summary`. Alerts are informational and never gate a release.

## Attestation key rotation

Not built (NEEDS #293): the key is ephemeral in the dev gateway; registry trusts `evalHubKeys` supplied at construction.
