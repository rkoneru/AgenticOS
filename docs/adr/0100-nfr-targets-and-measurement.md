# 0100. NFR targets, how each is measured, and what "Met" means

Status: Accepted · Date: 2026-10-09 · Related: 0101, 0102, 0103

## Context

AXIS_MASTER_PROMPT.md section 7 lists the non-functional targets. Until Phase 9 only the in-process gate (0.124 ms p99 against an in-memory sink) was measured.
The environment is one small VM; a target that needs a cluster cannot be demonstrated here.

## Decision

- `docs/nfr.md` copies the targets from section 7 EXACTLY and adds clearly-marked PROPOSED targets for things section 7 does not state (run start latency,
  audit append rate, verify time, SSE fan-out, eval throughput, DSAR completion). Each row has a measurement method and a verdict: `Met`, `Not met`
  or `Not measured`, from the numbers of a run in this environment. A scenario with errors, or a component that is not built, is `Not measured`. Extrapolation is not a measurement.
- Load generation is an in-repo Node harness (`perf/`): open-model arrivals, warm-up discarded, HDR-style histograms, latency from the intended start
  (coordinated-omission aware), shed-and-count instead of unbounded queues. It is unit-tested (histogram precision, arrival model, verdict logic).
- k6 scripts with the same scenarios are committed and EXECUTED when the binary is present. k6 is not obtainable from npm (the `k6` package is a typings stub); the
  official GitHub release tarball is installed by `perf/install-k6.sh` after a pinned SHA-256 check (no pipe-to-shell).
- The gate is reported as a rate SWEEP because its capacity (one tenant = one audit chain) is the finding, not a single p99.

## Consequences

Targets that need a region (1k RPS API, 10k concurrent agent processes, multi-AZ availability) stay `Not measured` / `Designed` with the reason, and NEEDS entries 3400-3402.
Defects found while measuring were fixed with failing-first tests (0103) or recorded.
