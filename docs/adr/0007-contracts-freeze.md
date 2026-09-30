# 0007. Contracts freeze mechanism

Status: Accepted · Date: 2026-09-30

## Context

After Phase 1, services are built in parallel against ABL, policy, process/IPC, audit, proto, OpenAPI and the DB schema.

## Decision

`packages/contracts/FREEZE.json` lists every frozen file with its SHA-256. A test (`freeze.test.ts`) fails if any file differs. Changing a frozen contract requires: an ADR, a version bump per the contract's versioning rules (additive = minor, breaking = new `v2` path/apiVersion), and regenerating the manifest with `pnpm --filter @axis/contracts freeze`. Migrations are append-only: existing migration files are frozen; changes are new migration files (which are added to the manifest).

## Consequences

Parallel work can rely on stable contracts. Drift is a red build, not a review comment.
