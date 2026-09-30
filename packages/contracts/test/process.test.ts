import { describe, expect, it } from "vitest";
import {
  isPid,
  isTerminal,
  newPid,
  nextState,
  processModel,
  validateIpcEnvelope,
} from "../src/index.js";

describe("process model", () => {
  const nonTerminal = processModel.states.filter((s) => !isTerminal(s));

  it("declares the six states from the brief", () => {
    expect(processModel.states).toEqual([
      "spawn",
      "ready",
      "running",
      "waiting",
      "suspended",
      "terminated",
    ]);
  });
  it("terminated is absorbing", () => {
    expect(processModel.transitions.filter((t) => t.from === "terminated")).toEqual([]);
    expect(nextState("terminated", "KILL")).toBeUndefined();
  });
  it("KILL is legal from every non-terminal state", () => {
    for (const s of nonTerminal) expect(nextState(s, "KILL")).toBe("terminated");
  });
  it("PAUSE/RESUME cycle", () => {
    expect(nextState("running", "PAUSE")).toBe("suspended");
    expect(nextState("suspended", "RESUME")).toBe("ready");
    expect(nextState("suspended", "scheduled")).toBeUndefined();
  });
  it("every transition references declared states and signals/events are unique per source state", () => {
    const seen = new Set<string>();
    for (const t of processModel.transitions) {
      expect(processModel.states).toContain(t.from);
      expect(processModel.states).toContain(t.to);
      const k = `${t.from}|${t.on}`;
      expect(seen.has(k), k).toBe(false);
      seen.add(k);
    }
  });
  it("every non-terminal state can reach terminated", () => {
    for (const s of nonTerminal) {
      const reach = new Set([s]);
      for (let i = 0; i < 10; i++) {
        for (const t of processModel.transitions) if (reach.has(t.from)) reach.add(t.to);
      }
      expect(reach.has("terminated"), s).toBe(true);
    }
  });
  it("every signal used in transitions is declared", () => {
    for (const t of processModel.transitions.filter((x) => x.on === x.on.toUpperCase())) {
      expect(Object.keys(processModel.signals)).toContain(t.on);
    }
  });
});

describe("PIDs", () => {
  it("are well-formed, unique and time-sortable", () => {
    const a = newPid(1_700_000_000_000);
    const b = newPid(1_700_000_001_000);
    expect(isPid(a)).toBe(true);
    expect(a).not.toBe(newPid(1_700_000_000_000));
    expect(a < b).toBe(true);
  });
  it("rejects malformed values", () => {
    for (const v of [
      "",
      "axp_",
      "axp_01ARZ3NDEKTSV4RRFFQ69G5FAU",
      "pid_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      5,
      null,
    ]) {
      expect(isPid(v)).toBe(false);
    }
  });
});

describe("IPC envelope", () => {
  const base = {
    schema_version: 1,
    id: "00000000-0000-4000-8000-000000000001",
    tenant_id: "11111111-1111-4111-8111-111111111111",
    trace_id: "a".repeat(32),
    from: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    to: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    kind: "message",
    ts: "2026-01-01T00:00:00.000Z",
    payload: { text: "hi" },
  };
  it("accepts PID and channel destinations", () => {
    expect(validateIpcEnvelope(base)).toBe(true);
    expect(validateIpcEnvelope({ ...base, to: "chan:approvals" })).toBe(true);
  });
  it("requires correlation_id on responses", () => {
    expect(validateIpcEnvelope({ ...base, kind: "response" })).toBe(false);
    expect(validateIpcEnvelope({ ...base, kind: "response", correlation_id: base.id })).toBe(true);
  });
  it("rejects bad destinations and missing tenant", () => {
    expect(validateIpcEnvelope({ ...base, to: "somewhere" })).toBe(false);
    const { tenant_id: _t, ...noTenant } = base;
    void _t;
    expect(validateIpcEnvelope(noTenant)).toBe(false);
  });
});
