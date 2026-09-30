import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { auditEventSchema, policySchema, processModel } from "../src/index.js";

const rel = (p: string) => new URL(`../${p}`, import.meta.url);
const common = readFileSync(
  new URL("../../../proto/axis/runtime/v1/common.proto", import.meta.url),
  "utf8",
);
const openapi = parse(readFileSync(rel("openapi/axis-v1.yaml"), "utf8"));

/** Values of a proto enum, minus UNSPECIFIED and the common prefix, lower/upper-cased by the caller. */
function protoEnum(name: string, prefix: string): string[] {
  const body = new RegExp(`enum ${name} \\{([^}]*)\\}`).exec(common)?.[1] ?? "";
  return [...body.matchAll(/^\s*([A-Z_]+)\s*=\s*\d+;/gm)]
    .map((m) => m[1] as string)
    .filter((v) => !v.endsWith("_UNSPECIFIED"))
    .map((v) => v.slice(prefix.length));
}

const decisions = (auditEventSchema as { properties: { decision: { enum: string[] } } }).properties
  .decision.enum;
const policyDefs = (
  policySchema as { $defs: { enforcementPoint: { enum: string[] }; decision: { enum: string[] } } }
).$defs;

describe("contract drift: one vocabulary across proto, OpenAPI, JSON Schema and the process model", () => {
  it("process states", () => {
    const states = protoEnum("ProcessState", "PROCESS_STATE_").map((s) => s.toLowerCase());
    expect(states).toEqual(processModel.states);
    expect(openapi.components.schemas.ProcessState.enum).toEqual(processModel.states);
  });

  it("signals", () => {
    const signals = protoEnum("Signal", "SIGNAL_");
    expect(signals.sort()).toEqual(Object.keys(processModel.signals).sort());
    expect([...openapi.components.schemas.Signal.enum].sort()).toEqual(
      Object.keys(processModel.signals).sort(),
    );
  });

  it("decisions", () => {
    const d = protoEnum("Decision", "DECISION_");
    expect(d.sort()).toEqual([...decisions].sort());
    expect([...policyDefs.decision.enum].sort()).toEqual([...decisions].sort());
    expect([...openapi.components.schemas.Decision.enum].sort()).toEqual([...decisions].sort());
  });

  it("enforcement points (gate) are a subset of the audit vocabulary", () => {
    const ep = protoEnum("EnforcementPoint", "ENFORCEMENT_POINT_").map((s) => s.toLowerCase());
    expect(ep.sort()).toEqual([...policyDefs.enforcementPoint.enum].sort());
    const audit = (auditEventSchema as { properties: { enforcement_point: { enum: string[] } } })
      .properties.enforcement_point.enum;
    for (const p of ep) expect(audit).toContain(p);
  });

  it("exit reasons in the process model match the DB CHECK constraint", () => {
    const sql = readFileSync(
      new URL("../../db/migrations/0002_core_tables.sql", import.meta.url),
      "utf8",
    );
    const reasons = /exit_reason IN\s*\(([^)]*)\)/.exec(sql)?.[1] ?? "";
    const fromSql = [...reasons.matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
    expect(fromSql).toEqual((processModel as unknown as { exitReasons: string[] }).exitReasons);
  });
});
