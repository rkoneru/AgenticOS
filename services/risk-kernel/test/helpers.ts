import { readFileSync } from "node:fs";
import { compilePolicySet, opaBuildWasm } from "@axis/policy";
import { parse } from "yaml";
import {
  MemoryAuditSink,
  MemoryCounterStore,
  MemoryKillSwitchStore,
  RiskKernel,
  WasmPolicyEngine,
  type GateRequest,
  type KernelDeps,
  type PolicyEngine,
} from "../src/index.js";

export const T1 = "11111111-1111-4111-8111-111111111111";
export const T2 = "22222222-2222-4222-8222-222222222222";
export const PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV";
export const policiesDir = new URL("../../../policies/", import.meta.url);

export function compileDefault(): { rego: string; bundle: Buffer; policyVersion: string } {
  const docs = ["baseline-deny/pack.yaml", "phi-redaction/pack.yaml"].map((f) =>
    parse(readFileSync(new URL(f, policiesDir), "utf8")),
  );
  const r = compilePolicySet(docs);
  if (!r.ok) throw new Error(JSON.stringify(r.issues));
  return { rego: r.rego, bundle: opaBuildWasm(r.rego), policyVersion: r.policyVersion };
}

let cached: Promise<WasmPolicyEngine> | undefined;
export const defaultEngine = (): Promise<WasmPolicyEngine> =>
  (cached ??= WasmPolicyEngine.fromBundle(compileDefault().bundle));

export interface Harness {
  kernel: RiskKernel;
  audit: MemoryAuditSink;
  kill: MemoryKillSwitchStore;
  counters: MemoryCounterStore;
  clock: { now: number };
  logs: string[];
}

export async function harness(
  over: Partial<KernelDeps> = {},
  engine?: PolicyEngine,
): Promise<Harness> {
  const audit = new MemoryAuditSink();
  const kill = new MemoryKillSwitchStore();
  const counters = new MemoryCounterStore();
  const clock = { now: Date.parse("2026-03-01T12:00:00.000Z") };
  const logs: string[] = [];
  const kernel = new RiskKernel({
    engine: engine ?? (await defaultEngine()),
    audit,
    killSwitches: kill,
    counters,
    clock: () => clock.now,
    // Generous: functional tests must not depend on machine load. Timeout behaviour has its own explicit tests.
    policyTimeoutMs: 2000,
    logger: {
      warn: (m) => void logs.push(`warn:${m}`),
      error: (m) => void logs.push(`error:${m}`),
    },
    ...over,
  });
  return { kernel, audit, kill, counters, clock, logs };
}

export function req(over: Partial<GateRequest> = {}): GateRequest {
  return {
    tenant_id: T1,
    trace_id: "a".repeat(32),
    actor: { type: "agent", id: "claims-triage", pid: PID },
    blueprint: { name: "claims-triage", version: "1.0.0" },
    enforcement_point: "tool_call",
    action: "lookup",
    context: { tool: { name: "lookup", kind: "function", side_effects: "read" }, args: {} },
    ...over,
  };
}
