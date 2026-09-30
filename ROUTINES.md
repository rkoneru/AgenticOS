# ROUTINES

## Phase exit

1. `make lint typecheck test cov` and (once available) `make policy-test evals e2e`.
2. Security scans (CodeQL, gitleaks, Trivy) clean or findings recorded.
3. Independent review subagent audits exit criteria; fix findings.
4. Update the status table in `CLAUDE.md` (evidence decides), `CHANGELOG.md`, `docs/NEEDS.md`.

## Release / security scan

Planned for Phase 10.
