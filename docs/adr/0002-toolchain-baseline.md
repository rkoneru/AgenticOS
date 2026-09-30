# 0002. Toolchain baseline

Status: Accepted · Date: 2026-09-30

## Context

The stack is fixed by the master prompt. Phase 0 needs concrete lint/test/coverage tooling.

## Decision

- TypeScript: pnpm + Turborepo, ESLint 9 flat config + typescript-eslint, Prettier, Vitest with v8 coverage.
  Strict tsconfig (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`).
- Python: uv workspace (Python 3.12), ruff (lint+format, includes bandit `S` rules), mypy strict, pytest + pytest-cov with branch coverage.
- Coverage thresholds live in each package (vitest thresholds, `--cov-fail-under`). Packages default to 85%;
  core packages (ABL, policy compiler, Risk Kernel, TKI, audit, billing ledger, tenancy) raise theirs to 95% when created.
- CI: GitHub Actions; CodeQL (SAST), gitleaks, Trivy fs (dependency scan), CycloneDX SBOM via Anchore.

## Consequences

Control-plane framework (Fastify vs NestJS), OPA mode and sandbox tech are decided in Phase 1 ADRs.
