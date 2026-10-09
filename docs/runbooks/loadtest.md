# Runbook: load test (`make loadtest`)

Phase 9 D. Measures the NFR targets of [docs/nfr.md](../nfr.md) on the REAL stack (Postgres 16, Risk Kernel over gRPC, control plane, billing,
registry/marketplace, AGIL, the Python run service with a scripted model, the standalone API gateway).

## Run it

```bash
make loadtest        # ~4 minutes; needs node, pnpm, uv, opa, PostgreSQL 16 binaries (same as `make e2e-core`)
```

Output: `perf/results/loadtest-short.{json,md}`. The committed copy is ONE representative run on a 4 vCPU / 16 GiB VM where the load generator,
the gateway, the kernel, the run service, the control plane and Postgres all share the machine. Treat absolute numbers as "this machine";
the report header states the machine. **Extrapolation is not a measurement**: nothing here is multiplied up to a "per region" figure.

## What runs

| Tool                                                        | Status                                                                   | What                                                                                                                                                                                                                                                              |
| ----------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `perf/src` (Node, executed by `make loadtest`)              | executed                                                                 | open-model arrivals (seeded Poisson), warm-up discarded, HDR-style histograms (about 0.1% relative error, bounded memory), latency measured from the INTENDED start (coordinated-omission aware), in-flight cap that SHEDS and counts errors, per-request timeout |
| `perf/k6/*.js` (k6 v0.54.0, pinned by `perf/install-k6.sh`) | executed (HTTP scenarios and the gRPC gate) when the binary is installed | the same scenarios with `constant-arrival-rate` executors; thresholds are the proposed targets                                                                                                                                                                    |
| `perf/src/audit-bench.ts`                                   | executed                                                                 | audit append throughput (1 chain; 8 callers on 1 chain; 8 callers on 8 chains) and verify time of a 100k-event chain                                                                                                                                              |

`perf/install-k6.sh` downloads the official release tarball and checks it against a SHA-256 pinned in the script (no `curl | sh`).
If k6 is missing the run says `not-run` in the report; the Node harness numbers are the ones the verdicts use.

## Reading a report

- `p50..max` are milliseconds from the intended start; `svc p99` is from the actual send. A big gap means queueing in the load generator or client.
- `gen lag max` is how late the generator itself ever was. If it is large the generator, not the server, is the bottleneck: lower the rate.
- The gate is a SWEEP (50, 100, 200, 400 per second): past its capacity latency grows with the queue, which is the finding.
- Every verdict is `Met`, `Not met` or `Not measured`. A scenario with errors reports `Not measured`, never `Met`.

## Known limits of this harness

Same-machine measurement; scripted model (no provider latency); one tenant per scenario (so one audit chain); the gateway rate limiter is
raised for the run (`GW_RATE_BURST`); SSE fan-out is capped by `GW_MAX_SSE_STREAMS` (raised to 2000 for the run; default 16 per tenant).

## Tests of the harness itself

`pnpm --filter @axis/perf cov` - histogram math (bucket round trip, 0.1% precision, merge, coordinated-omission correction), the arrival
model (seeded, shed, timeout, virtual clock proving latency is charged from the intended start), the report/verdict logic.
