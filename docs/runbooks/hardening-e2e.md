# Runbook: Phase 9 hardening end to end

Dev only (NEEDS #413-#421). Components: `data-governance.md`, `dr.md`, `chaos.md`, `loadtest.md`; specs `docs/spec/{compliance,data-governance}.md`;
red team `docs/security/redteam.md`; targets `docs/nfr.md`; decisions ADR 0113.

## Run the proof

`make e2e-phase9` (Postgres 16, `opa`, node, uv; about 100 s after the build): `compliance-check` and `threatmodel-check` first (they fail on a
citation that does not exist), then `e2e/test_phase9_hardening.py` (23 tests) and the bypass guard. A single scenario:
`bash infra/scripts/with-pg.sh uv run pytest e2e/test_phase9_hardening.py -p no:cacheprovider --no-cov -k test_a2`.
`uv run python e2e/mutation_phase9.py [substring]` runs the 14 wiring mutants (about 15 minutes; it edits the working tree and restores it, and
`git checkout -- .` is the recovery if it is killed hard).

## What each scenario proves (test prefix)

| Scenario | Tests | Proof                                                                                                                                                                                                                                                                       |
| -------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| a DSAR   | a1-a2 | one person in 7 stores (member, signed Slack message, memory, run logs, eval case, approvals, billing refs); export is signed and complete; erase by a privacy officer; verification re-queries every provider; no marker left in the tenant's database; chain verifies, no raw data in it; colleague and the SAME human in another tenant untouched (byte-identical dump) |
| b retention | b1-b3 | dry run changes nothing; tenant legal hold stops the purge; release lets exactly the expired rows go; audit is never purged                                                                                                                                              |
| c PHI    | c1-c6 | canaries (SSN variants incl. fullwidth and zero-width, MRN, email, phone) through a PHI Slack route, memory, an eval dataset and PHI runs (input, tool args, tool errors, answer); controls show the non-PHI path keeps the words; the sweep covers every table, the audit chain and every process log |
| d residency | d1-d4 | a tenant re-homed to eu-west-1 is refused (403 `residency_violation`) by the registry, the Eval Hub and billing; the home tenant is not; the ModelGateway refuses an out-of-region, region-less or empty-allow-list provider before any network call                          |
| e compliance | e1 | Annex IV document from the tenant's real records, sealed, verifies, idempotent, fails verification when a stored byte changes; gaps are reported, not invented                                                                                                          |
| f red team | f1-f2 | `redteam-core@1.0.0` passes -> the registry releases; a widened email allow-list makes the suite fail (exfiltration) -> release refused with `evals_gate_failed`                                                                                                           |
| g chaos  | g0-g3 | kernel killed mid-approval: the action never runs; kernel and gateway lose their database: DENY / 503 and nothing created; a kill switch survives a kernel restart                                                                                                       |
| h DR     | h1    | `infra/dr/results/dr-drill.json` is well-formed, both tamper negatives were detected, RPO/RTO within the targets parsed from `docs/nfr.md`                                                                                                                                |

## Triage

- A scenario fails alone but not in the module: ordering. Each fixture builds its own tenants; the stack is module-scoped.
- `test_c*` leaks a canary: look at `phi_net.py` (run log), `channels/src/redact.ts`, `memory/src/redact.ts`, `eval-hub/src/catalog.ts`; the control
  assertion in the same test says whether the path is the PHI one.
- `test_d*` passes for the wrong reason: check the tenant's `tenants.region` and the stack's `region` (us-east-1); the guard compares them.
- `test_f2` passes (release not blocked): the Hub's gate or the campaign's mutant pack no longer weakens a control; `make redteam-selfcheck`.
- `test_h1` fails on a missing target: `docs/nfr.md` rows N6 and N7 must keep the form `RPO <= 5 min` / `RTO <= 1 h`.
