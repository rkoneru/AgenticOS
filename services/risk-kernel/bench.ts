/* `pnpm --filter @axis/risk-kernel bench`: measures NFR latency (gate < 25 ms p99, policy decision < 10 ms p99) in-process. */
import {
  MemoryAuditSink,
  MemoryCounterStore,
  MemoryKillSwitchStore,
  RiskKernel,
} from "./src/index.js";
import { compileDefault } from "./test/helpers.js";
import { WasmPolicyEngine } from "./src/engine.js";
import { req } from "./test/helpers.js";

const engine = await WasmPolicyEngine.fromBundle(compileDefault().bundle);
const pct = (xs: number[], p: number): number =>
  [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(xs.length * p))] as number;

async function time(n: number, fn: (i: number) => Promise<unknown>): Promise<number[]> {
  for (let i = 0; i < 500; i++) await fn(i); // warm up
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    await fn(i);
    out.push(performance.now() - t);
  }
  return out;
}

const input = {
  enforcement_point: "tool_call",
  tool: { name: "lookup", side_effects: "read" },
  args: {},
  tenant: { id: "t" },
  agent: { name: "a", version: "1" },
  actor: { type: "agent", id: "a" },
};
const policyOnly = await time(20000, () => engine.evaluate(input));

let clock = Date.parse("2026-03-01T00:00:00Z");
const kernel = new RiskKernel({
  engine,
  audit: new MemoryAuditSink(),
  killSwitches: new MemoryKillSwitchStore(),
  counters: new MemoryCounterStore(),
  clock: () => clock,
  policyTimeoutMs: 1000,
});
const full = await time(20000, async () => {
  clock += 120_000;
  return kernel.evaluate(req());
});

const row = (name: string, xs: number[]) =>
  `${name.padEnd(34)} p50=${pct(xs, 0.5).toFixed(3)}ms p99=${pct(xs, 0.99).toFixed(3)}ms max=${Math.max(...xs).toFixed(3)}ms`;
console.log(row("policy decision (Wasm)", policyOnly));
console.log(row("full gate (validate+policy+gates+audit)", full));
console.log(
  `node ${process.version}; in-process, in-memory stores and audit (excludes network/DB/Redis)`,
);
