import { describe, expect, it } from "vitest";
import {
  applyEvent,
  describeEvent,
  emptyReplay,
  eventTone,
  gauge,
  mergeEvents,
  replayTo,
} from "@/lib/replay";
import type { RunEvent } from "@/lib/api";

const pid = "axp_0000000000000000000000000A";
const e = (sequence: number, type: string, data?: Record<string, unknown>): RunEvent => ({
  sequence,
  type,
  pid,
  at: "2026-01-01T00:00:00Z",
  ...(data ? { data } : {}),
});

const log: RunEvent[] = [
  e(1, "state_transition", { from: "spawn", to: "running" }),
  e(2, "model_call", { model: "m", tokens: 100, cost_usd: 0.01 }),
  e(3, "gate_decision", { decision: "REQUIRE_APPROVAL", reason: "external write" }),
  e(4, "tool_call", { tool: "email.send" }),
  e(5, "gate_decision", { decision: "DENY" }),
  e(6, "model_call", { model: "m", tokens: 50, cost_usd: 0.005 }),
  e(7, "state_transition", { from: "running", to: "terminated" }),
  e(8, "message"),
];

describe("replay", () => {
  it("folds events up to a sequence", () => {
    const s = replayTo(log, 5);
    expect(s).toMatchObject({
      sequence: 5,
      state: "running",
      tokens: 100,
      modelCalls: 1,
      toolCalls: 1,
      denials: 1,
      approvalsRequested: 1,
      lastDecision: "DENY",
    });
    expect(s.costUsd).toBeCloseTo(0.01);
  });
  it("replays the whole log and the empty prefix", () => {
    const all = replayTo(log, 99);
    expect(all.state).toBe("terminated");
    expect(all.tokens).toBe(150);
    expect(replayTo(log, 0)).toEqual(emptyReplay);
  });
  it("ignores hostile numbers and unknown states", () => {
    const s = applyEvent(emptyReplay, e(1, "model_call", { tokens: -5, cost_usd: "9" }));
    expect(s.tokens).toBe(0);
    expect(s.costUsd).toBe(0);
    expect(applyEvent(emptyReplay, e(1, "state_transition", { to: "exploded" })).state).toBe(
      "unknown",
    );
    expect(applyEvent(emptyReplay, e(1, "gate_decision", {})).lastDecision).toBeUndefined();
  });
  it("merges and de-duplicates by sequence", () => {
    const m = mergeEvents([e(2, "a"), e(1, "a")], [e(2, "b"), e(3, "c")]);
    expect(m.map((x) => [x.sequence, x.type])).toEqual([
      [1, "a"],
      [2, "b"],
      [3, "c"],
    ]);
  });
  it("describes and tones events", () => {
    expect(describeEvent(log[0]!)).toBe("spawn -> running");
    expect(describeEvent(e(1, "state_transition"))).toBe("? -> ?");
    expect(describeEvent(log[1]!)).toBe("model m, 100 tokens");
    expect(describeEvent(e(1, "model_call"))).toBe("model ?, 0 tokens");
    expect(describeEvent(log[3]!)).toBe("tool email.send");
    expect(describeEvent(e(1, "tool_call"))).toBe("tool ?");
    expect(describeEvent(log[2]!)).toBe("REQUIRE_APPROVAL: external write");
    expect(describeEvent(e(1, "gate_decision"))).toBe("?");
    expect(describeEvent(log[7]!)).toBe("message");
    expect(eventTone(log[0]!)).toBe("neutral");
    expect(eventTone(log[2]!)).toBe("warn");
    expect(eventTone(log[4]!)).toBe("bad");
    expect(eventTone(e(1, "gate_decision", { decision: "ALLOW" }))).toBe("good");
    expect(eventTone(e(1, "gate_decision", { decision: "?" }))).toBe("neutral");
  });
  it("computes gauges", () => {
    expect(gauge("t", 50, 80, 100)).toMatchObject({ ratio: 0.5, level: "ok" });
    expect(gauge("t", 85, 80, 100).level).toBe("soft");
    expect(gauge("t", 120, 80, 100)).toMatchObject({ level: "hard", ratio: 1 });
    expect(gauge("t", 5).level).toBe("none");
    expect(gauge("t", 5).ratio).toBeUndefined();
    expect(gauge("t", 5, 10).ratio).toBe(0.5);
    expect(gauge("t", 5, undefined, 0).ratio).toBeUndefined();
  });
});

describe("the runtime's own event vocabulary (what the real gateway streams)", () => {
  const ev = (sequence: number, type: string, data: Record<string, unknown> = {}) => ({
    sequence,
    type,
    pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    at: "2026-01-01T00:00:00Z",
    data,
  });
  it("folds process_transition, runtime token/cost fields and tool_call_result", () => {
    const s = replayTo(
      [
        ev(1, "process_transition", { from: "spawn", to: "running" }),
        ev(2, "model_call", { input_tokens: 40, output_tokens: 12, cost_micro_usd: 220 }),
        ev(3, "tool_call_result", { action: "lookup-claim" }),
        ev(4, "gate_decision", { decision: "REQUIRE_APPROVAL", action: "file-payout" }),
        ev(5, "process_transition", { from: "running", to: "terminated" }),
      ],
      5,
    );
    expect(s).toMatchObject({
      state: "terminated",
      tokens: 52,
      toolCalls: 1,
      modelCalls: 1,
      approvalsRequested: 1,
    });
    expect(s.costUsd).toBeCloseTo(0.00022);
  });
  it("describes output and gate decisions with their action", async () => {
    const { describeEvent } = await import("@/lib/replay");
    expect(describeEvent(ev(1, "process_output", { output: "x".repeat(300) }))).toHaveLength(
      8 + 200,
    );
    expect(
      describeEvent(
        ev(2, "gate_decision", { decision: "DENY", action: "lookup-restricted", reason: "r" }),
      ),
    ).toBe("DENY lookup-restricted: r");
    expect(describeEvent(ev(3, "tool_call_result", { action: "lookup-claim" }))).toBe(
      "tool lookup-claim",
    );
  });
});
