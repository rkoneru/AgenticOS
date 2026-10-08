/**
 * `make loadtest` driver: runs the scenarios against a booted stack (STACK_JSON, from e2e/interfaces_stack.py) and writes a JSON + Markdown
 * report. Usage: tsx src/cli.ts --stack stack.json --out perf/results [--profile short|smoke]
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { runAuditBench, runVerifyBench } from "./audit-bench.js";
import { runOpenLoad, type LoadResult } from "./openload.js";
import { check, machine, renderMarkdown, type Report, type ScenarioReport } from "./report.js";
import { runK6 } from "./k6.js";
import * as sc from "./scenarios.js";
import { readStack, seedRegistry, setupTenant } from "./stack.js";

interface Profile {
  name: string;
  warmupMs: number;
  durationMs: number;
  /** arrival rate per second per scenario */
  rates: Record<string, number>;
  auditAppends: number;
  verifyEvents: number;
  fanOut: number[];
}

const PROFILES: Record<string, Profile> = {
  // ~2 minutes on a small machine.
  short: {
    name: "short",
    warmupMs: 3000,
    durationMs: 10_000,
    rates: {
      me: 300,
      auditList: 60,
      auditVerify: 5,
      registryResolve: 60,
      runStartAck: 20,
      runComplete: 10,
      gate: 400,
    },
    auditAppends: 5000,
    verifyEvents: 100_000,
    fanOut: [10, 100, 500],
  },
  // a few seconds, used by the test that proves the harness wiring
  smoke: {
    name: "smoke",
    warmupMs: 500,
    durationMs: 2000,
    rates: {
      me: 50,
      auditList: 10,
      auditVerify: 2,
      registryResolve: 10,
      runStartAck: 5,
      runComplete: 3,
      gate: 50,
    },
    auditAppends: 300,
    verifyEvents: 2000,
    fanOut: [5],
  },
};

function arg(name: string, def?: string): string {
  const i = process.argv.indexOf(`--${name}`);
  const v = i >= 0 ? process.argv[i + 1] : def;
  if (v === undefined) throw new Error(`--${name} is required`);
  return v;
}

const profile = PROFILES[arg("profile", "short")];
if (!profile) throw new Error("unknown profile");
const info = readStack(arg("stack"));
const outDir = arg("out");

const slug = `perf${Date.now().toString(36)}`;
const tenant = await setupTenant(info, slug);
const ref = await seedRegistry(info, tenant, `perf-${slug}`);
console.error(`tenant ${tenant.tenantId} ready; registry ref ${ref}`);

const gate = sc.gate(info, tenant);
const defs: { name: string; description: string; fn: sc.Scenario }[] = [
  { name: "me", description: "GET /me (API-key auth)", fn: sc.me(info, tenant) },
  { name: "auditList", description: "GET /audit/events?limit=50", fn: sc.auditList(info, tenant) },
  {
    name: "auditVerify",
    description: "GET /audit/verify (whole chain)",
    fn: sc.auditVerify(info, tenant),
  },
  {
    name: "registryResolve",
    description: "GET /registry/resolve (verified resolve)",
    fn: sc.registryResolve(info, tenant, ref),
  },
  {
    name: "runStartAck",
    description: "POST /runs -> 202 (run start latency)",
    fn: sc.runStartAck(info, tenant),
  },
  {
    name: "runComplete",
    description: "POST /runs and poll until terminated (1 gated model call)",
    fn: sc.runComplete(info, tenant),
  },
  {
    name: "gate",
    description: "gRPC GateService.Evaluate (ALLOW, Wasm policy, audit row in Postgres)",
    fn: gate.scenario,
  },
];

const scenarios: ScenarioReport[] = [];
for (const d of defs) {
  const rate = profile.rates[d.name] as number;
  console.error(`scenario ${d.name} at ${rate}/s ...`);
  const result: LoadResult = await runOpenLoad(d.fn, {
    rate,
    warmupMs: profile.warmupMs,
    durationMs: profile.durationMs,
    arrival: "poisson",
    seed: 42,
    maxInFlight: 2000,
    timeoutMs: 30_000,
  });
  scenarios.push({ name: d.name, description: d.description, result });
}
gate.close();

const extra: Record<string, unknown> = {};
const fan: unknown[] = [];
for (const n of profile.fanOut) {
  console.error(`sse fan-out x${n} ...`);
  fan.push(
    await sc
      .sseFanOut(info, tenant, n)
      .catch((e: unknown) => ({ subscribers: n, error: String(e) })),
  );
}
extra["sseFanOut"] = fan;
console.error("audit append ...");
extra["auditAppendSingleChain"] = await runAuditBench(
  info.db_url,
  info.db_url,
  profile.auditAppends,
  1,
  1,
);
extra["auditAppendConcurrentSameChain"] = await runAuditBench(
  info.db_url,
  info.db_url,
  profile.auditAppends,
  8,
  1,
);
extra["auditAppendManyChains"] = await runAuditBench(
  info.db_url,
  info.db_url,
  profile.auditAppends,
  8,
  8,
);
console.error("audit verify ...");
const verify = await runVerifyBench(info.db_url, profile.verifyEvents);
extra["auditVerify"] = verify;

if (process.argv.includes("--k6")) {
  extra["k6"] = [
    runK6("gateway.js", info, tenant, { REG_REF: ref, RATE: "100", DURATION: "15s" }),
    runK6("gate-grpc.js", info, tenant, { RATE: "200", DURATION: "15s" }),
  ];
}

const byName = (n: string): LoadResult => scenarios.find((s) => s.name === n)?.result as LoadResult;
const p = (n: string, q: "p95" | "p99"): number =>
  Math.round((byName(n).latency[q] / 1000) * 100) / 100;
const clean = (n: string): boolean => byName(n).errors === 0;
const checks = [
  check({
    id: "gate.grpc.p99",
    title: "gate decision over gRPC",
    target: "gate adds < 25 ms p99 to a tool call",
    measured: clean("gate") ? p("gate", "p99") : null,
    unit: "ms",
    bound: "max",
    limit: 25,
    note: `${profile.rates["gate"]}/s, ALLOW with a Postgres audit row per call`,
  }),
  check({
    id: "api.me.p99",
    title: "API p99 (auth only)",
    target: "control-plane API p99 < 200 ms",
    measured: clean("me") ? p("me", "p99") : null,
    unit: "ms",
    bound: "max",
    limit: 200,
    note: `${profile.rates["me"]}/s on one small machine; the 1k RPS part of the target is NOT demonstrated`,
  }),
  check({
    id: "api.auditList.p99",
    title: "audit list p99",
    target: "API p99 < 200 ms",
    measured: clean("auditList") ? p("auditList", "p99") : null,
    unit: "ms",
    bound: "max",
    limit: 200,
  }),
  check({
    id: "api.registryResolve.p99",
    title: "registry resolve p99",
    target: "API p99 < 200 ms",
    measured: clean("registryResolve") ? p("registryResolve", "p99") : null,
    unit: "ms",
    bound: "max",
    limit: 200,
  }),
  check({
    id: "run.start.p99",
    title: "run start acknowledgement p99",
    target: "proposed: < 200 ms",
    measured: clean("runStartAck") ? p("runStartAck", "p99") : null,
    unit: "ms",
    bound: "max",
    limit: 200,
  }),
  check({
    id: "audit.verify.100k",
    title: "verify 100k events (one chain)",
    target: "proposed: < 30 s",
    measured: verify.verifyOk ? verify.verifySecondsPer100k : null,
    unit: "s",
    bound: "max",
    limit: 30,
  }),
];

const report: Report = {
  generatedAt: new Date().toISOString(),
  profile: profile.name,
  machine: machine(),
  scenarios,
  extra,
  checks,
};
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, `loadtest-${profile.name}.json`), JSON.stringify(report, null, 2));
writeFileSync(join(outDir, `loadtest-${profile.name}.md`), renderMarkdown(report));
console.log(renderMarkdown(report));
// exit status: harness errors throw above; a missed target is REPORTED, not a crash. A run with errors in a scenario is flagged.
const bad = scenarios.filter((s) => s.result.errors > 0).map((s) => s.name);
if (bad.length > 0) console.error(`scenarios with errors: ${bad.join(", ")}`);
process.exit(0);
