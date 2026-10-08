# 0073. The control matrix is data, and a checker keeps it honest

Status: Accepted · Date: 2026-10-08 · Related: 0070, 0074

## Context

A control matrix that cites a file that was renamed, a test that was deleted or a make target that never existed is worse than none. The master
prompt requires "designed for / evidence-ready" wording and forbids claiming certification.

## Decision

- **Source of truth:** `docs/compliance/matrix/<framework>.yaml` (SOC 2, GDPR, HIPAA, EU AI Act, ISO/IEC 42001). Each row is
  `{id, requirement (paraphrased), mechanism, code, config, evidence, status, notes}`. Markdown is generated from the YAML and checked for drift;
  nobody edits it by hand.
- **`make compliance-check`** (CLI `axis-compliance-check`, library `checkMatrix`) fails on: a cited code path, config, test, document, file, audit
  query or make target that does not exist (`M010`-`M012`); a test file with no test case (`M013`); a `#needle` that is not in the file;
  `Built` without a test, make target or audit query (`M020`); `Built` or `Prototype` without a code path (`M021`); `Gap` or `Designed` without
  real notes (`M022`); the words certified or compliant, "guarantees compliance" and similar (`M030`); a missing required row (`M005`);
  a stale rendered file (`M040`). Paths may not leave the repository.
- **Required rows** are listed in `src/matrix/required.ts` so that deleting an uncomfortable `Gap` is a finding.
- **Statuses are evidence, not intent.** A document can make a row `Designed`; only something executable makes it `Built`.
- **Mutation check.** `scripts-mutation.mjs` applies one safety-relevant edit at a time (skip the existence check, accept `Built` without
  evidence, nondeterministic output, a source silently omitted, cross-tenant read, reviewer equal to author, weakened constraints) and
  requires the tests to fail.

## Consequences

The checker runs in `pnpm test` of the package against the real repository, so a rename that breaks a citation fails the normal test run as well
as the make target. It proves that cited evidence exists and has the right shape; it does not prove that the control is adequate. The rows say
so in their notes, and the summary table (`docs/compliance/summary.md`) is a count of rows, not a score.
