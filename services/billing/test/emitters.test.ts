import { describe, expect, it } from "vitest";
import {
  BillingError,
  FakeClickHouseSink,
  FanoutSink,
  MemoryUsageLedger,
  mapRunEvents,
  marketplaceInstall,
  modelClassifier,
  storageSample,
  type RunEventLite,
} from "../src/index.js";
import { Clock, memLedger, signer, usage } from "./helpers.js";

const T = "11111111-1111-4111-8111-111111111111";
const RUN = "run-1";
let seq = 0;
const ev = (
  type: string,
  data: Record<string, unknown>,
  o: { pid?: string | null; ts?: string; run?: string } = {},
): RunEventLite => ({
  run_id: o.run ?? RUN,
  seq: seq++,
  ts: o.ts ?? "2026-09-10T12:00:00Z",
  type,
  pid: o.pid === undefined ? "p1" : o.pid,
  data,
});
const start = () => {
  seq = 0;
  return [
    ev("run_started", { tenant_id: T }, { pid: null }),
    ev("process_spawned", { agent: "support", ppid: null }),
  ];
};
const gate = (id: string, decision: string) =>
  ev("gate_decision", { action_id: id, decision, enforcement_point: "tool_call", action: "x" });
const model = (id: string, o: Record<string, unknown> = {}) =>
  ev("model_call", {
    action_id: id,
    provider: "anthropic",
    model: "claude-opus-4",
    input_tokens: 1000,
    output_tokens: 200,
    cached_tokens: 0,
    ...o,
  });
const tool = (id: string, point: string, ok = true) =>
  ev("tool_call_result", { action_id: id, enforcement_point: point, name: "t", ok });

describe("run event mapping", () => {
  it("bills an allowed model call as fresh input and output tokens with dimensions and a keyed id", () => {
    const events = [...start(), gate("a1", "ALLOW"), model("a1", { cached_tokens: 300 })];
    const r = mapRunEvents(events, {
      tenantId: T,
      classifyModel: modelClassifier([{ prefix: "claude-opus", class: "frontier" }]),
    });
    expect(r.records.map((x) => [x.meter, x.quantity, x.dimensions])).toEqual([
      [
        "tokens_in",
        700n,
        {
          agent: "support",
          model: "claude-opus-4",
          model_class: "frontier",
          provider: "anthropic",
          run: RUN,
        },
      ],
      [
        "tokens_out",
        200n,
        {
          agent: "support",
          model: "claude-opus-4",
          model_class: "frontier",
          provider: "anthropic",
          run: RUN,
        },
      ],
    ]);
    expect(r.records[0]?.idempotencyKey).toBe(`run:${RUN}:${events.length - 1}:tokens_in`);
  });

  it("bills a fully cached model call as zero input tokens", () => {
    const r = mapRunEvents(
      [
        ...start(),
        gate("a1", "ALLOW"),
        model("a1", { input_tokens: 50, cached_tokens: 80, output_tokens: 0 }),
      ],
      { tenantId: T },
    );
    expect(r.records).toEqual([]);
  });

  it("does not bill a model call or tool call without an ALLOW decision (denied, approval, unknown)", () => {
    for (const decision of ["DENY", "REQUIRE_APPROVAL", "something"]) {
      const r = mapRunEvents(
        [...start(), gate("a1", decision), model("a1"), tool("a1", "tool_call")],
        { tenantId: T },
      );
      expect(r.records).toEqual([]);
      expect(r.skipped.map((s) => s.reason)).toEqual([
        "no ALLOW decision for this action",
        "no ALLOW decision for this action",
      ]);
    }
    const r = mapRunEvents(
      [
        ...start(),
        model("ghost"),
        ev("tool_call_result", { enforcement_point: "tool_call", ok: true }),
      ],
      { tenantId: T },
    );
    expect(r.records).toEqual([]);
  });

  it("bills ALLOW_WITH_REDACTION like ALLOW", () => {
    const r = mapRunEvents(
      [...start(), gate("a1", "ALLOW_WITH_REDACTION"), tool("a1", "code_exec")],
      { tenantId: T },
    );
    expect(r.records.map((x) => [x.meter, x.dimensions?.["tool_kind"]])).toEqual([
      ["tool_executions", "code"],
    ]);
  });

  it("maps every enforcement point to a tool kind, skips failed executions and speech sessions", () => {
    const pts = [
      "tool_call",
      "mcp_call",
      "code_exec",
      "browser_exec",
      "memory_write",
      "message_send",
    ];
    const events = [
      ...start(),
      ...pts.flatMap((p, i) => [gate(`g${i}`, "ALLOW"), tool(`g${i}`, p)]),
      gate("f", "ALLOW"),
      tool("f", "tool_call", false),
      gate("s", "ALLOW"),
      tool("s", "model_call"),
    ];
    const r = mapRunEvents(events, { tenantId: T });
    expect(r.records.map((x) => x.dimensions?.["tool_kind"])).toEqual([
      "tool",
      "mcp",
      "code",
      "browser",
      "memory_write",
      "message",
    ]);
    expect(r.skipped.map((s) => s.reason)).toEqual([
      "failed execution is not billed",
      "not a tool execution",
    ]);
  });

  it("bills voice time on call end only", () => {
    const r = mapRunEvents(
      [
        ...start(),
        ev("voice_call", { call_id: "c1", phase: "connected" }),
        ev("voice_turn", { call_id: "c1", turn: 1 }),
        ev("voice_call", { call_id: "c1", phase: "ended", duration_ms: 125_000 }),
        ev("voice_call", { call_id: "c2", phase: "ended", duration_ms: null }),
      ],
      { tenantId: T },
    );
    expect(r.records.map((x) => [x.meter, x.quantity])).toEqual([["voice_minutes", 125_000n]]);
    expect(r.skipped).toHaveLength(1);
  });

  it("bills runtime as the time a process spent RUNNING", () => {
    const tr = (to: string, ts: string) =>
      ev("process_transition", { from: "x", to, trigger: "t" }, { ts });
    const r = mapRunEvents(
      [
        ...start(),
        tr("running", "2026-09-10T12:00:00Z"),
        tr("waiting", "2026-09-10T12:00:10.500Z"),
        tr("running", "2026-09-10T12:01:00Z"),
        tr("terminated", "2026-09-10T12:01:02Z"),
        tr("running", "2026-09-10T12:00:00Z"),
        tr("waiting", "2026-09-10T11:59:00Z"),
      ],
      { tenantId: T },
    );
    expect(r.records.map((x) => x.quantity)).toEqual([10_500n, 2_000n]);
    expect(r.skipped).toHaveLength(1);
    expect(
      mapRunEvents(
        [
          ...start(),
          ev("process_transition", { from: "x", to: "waiting", trigger: "t" }, { pid: null }),
        ],
        { tenantId: T },
      ).records,
    ).toEqual([]);
  });

  it("never bills nexus cache hits, blocked actions or malformed model calls", () => {
    const r = mapRunEvents(
      [
        ...start(),
        ev("nexus_route", { hit_stage: "cache", total_tokens: 9000 }),
        ev("action_blocked", {}),
        gate("a", "ALLOW"),
        model("a", { input_tokens: "x" }),
        ev("process_spawned", { agent: "b" }, { pid: "p2" }),
        ev("signal_delivered", {}),
      ],
      { tenantId: T },
    );
    expect(r.records).toEqual([]);
    expect(r.skipped.map((s) => s.reason)).toEqual(["malformed model_call"]);
  });

  it("rejects a run of another tenant, mixed runs, gaps in order, missing start and bad timestamps", () => {
    seq = 0;
    expect(() =>
      mapRunEvents([ev("run_started", { tenant_id: "22222222-2222-4222-8222-222222222222" })], {
        tenantId: T,
      }),
    ).toThrow(/different tenant/);
    expect(() =>
      mapRunEvents([...start(), ev("model_call", {}, { run: "other" })], { tenantId: T }),
    ).toThrow(BillingError);
    const dup = start();
    expect(() => mapRunEvents([...dup, { ...(dup[1] as RunEventLite) }], { tenantId: T })).toThrow(
      /increasing/,
    );
    seq = 0;
    expect(() => mapRunEvents([ev("model_call", {})], { tenantId: T })).toThrow(/run_started/);
    expect(() =>
      mapRunEvents([...start(), ev("model_call", {}, { ts: "nope" })], { tenantId: T }),
    ).toThrow(/timestamp/);
    expect(mapRunEvents([], { tenantId: T })).toEqual({ records: [], skipped: [] });
  });

  it("re-sending the whole log, or a prefix, is a no-op in the ledger (idempotent keys)", async () => {
    const events = [
      ...start(),
      gate("a1", "ALLOW"),
      model("a1"),
      gate("a2", "ALLOW"),
      tool("a2", "tool_call"),
    ];
    const l = new MemoryUsageLedger({
      signer: signer(),
      now: () => new Date("2026-10-02T00:00:00Z"),
    });
    for (const evs of [events, events, events.slice(0, 5)])
      for (const rec of mapRunEvents(evs, { tenantId: T }).records) await l.append(rec);
    expect(await l.entries(T)).toHaveLength(3);
  });

  it("classifies models with a fallback", () => {
    const c = modelClassifier([{ prefix: "a-", class: "small" }]);
    expect(c("p", "a-1")).toBe("small");
    expect(c("p", "zzz")).toBe("standard");
  });
});

describe("other emitters", () => {
  it("rounds storage samples to milli-GB-hours half up and is idempotent per hour", () => {
    const h = new Date("2026-09-10T12:00:00Z");
    expect(storageSample({ tenantId: T, hourStart: h, bytes: 1_500_000_000n }).quantity).toBe(
      1500n,
    );
    expect(storageSample({ tenantId: T, hourStart: h, bytes: 499_999n }).quantity).toBe(0n);
    expect(storageSample({ tenantId: T, hourStart: h, bytes: 500_000n }).quantity).toBe(1n);
    expect(storageSample({ tenantId: T, hourStart: h, bytes: 1n }).idempotencyKey).toBe(
      `storage:${h.toISOString()}`,
    );
    expect(() => storageSample({ tenantId: T, hourStart: h, bytes: -1n })).toThrow(BillingError);
  });
  it("marketplace installs are keyed by install id", () => {
    const r = marketplaceInstall({ tenantId: T, listingId: "l", installId: "i1", at: new Date() });
    expect([r.meter, r.quantity, r.idempotencyKey]).toEqual([
      "marketplace_installs",
      1n,
      "install:i1",
    ]);
  });
});

describe("analytics fanout", () => {
  it("forwards inserted entries only and survives analytics outages", async () => {
    const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
    const ch = new FakeClickHouseSink();
    const errs: unknown[] = [];
    const sink = new FanoutSink(memLedger(clock), [ch], (e) => errs.push(e));
    const u = usage(T);
    expect((await sink.append(u)).status).toBe("inserted");
    expect((await sink.append({ ...u })).status).toBe("duplicate");
    expect(ch.rows.size).toBe(1);
    ch.failNext = 1;
    expect((await sink.append(usage(T))).status).toBe("inserted");
    expect(errs).toHaveLength(1);
    expect(ch.rows.size).toBe(1);
    const quiet = new FanoutSink(memLedger(clock), [ch]);
    ch.failNext = 1;
    expect((await quiet.append(usage(T))).status).toBe("inserted");
  });
});

describe("emitter edge cases", () => {
  it("bills events without a pid or agent, a missing cached count, and a result without an enforcement point", () => {
    const events = [
      ...start(),
      ev("voice_call", { call_id: "c9", phase: "ended", duration_ms: 1000 }, { pid: null }),
      gate("a1", "ALLOW"),
      ev("model_call", {
        action_id: "a1",
        provider: "p",
        model: "m",
        input_tokens: 10,
        output_tokens: 0,
      }),
      ev("tool_call_result", { action_id: "a1", ok: true }),
      ev("process_spawned", { agent: "x" }, { pid: "p9" }),
      gate("a2", "ALLOW"),
      ev(
        "model_call",
        { action_id: "a2", provider: "p", model: "m", input_tokens: 1, output_tokens: 1 },
        { pid: "p-unknown" },
      ),
    ];
    const r = mapRunEvents(events, { tenantId: T });
    expect(r.records.map((x) => [x.meter, x.quantity, x.dimensions?.["agent"]])).toEqual([
      ["voice_minutes", 1000n, undefined],
      ["tokens_in", 10n, "support"],
      ["tokens_in", 1n, undefined],
      ["tokens_out", 1n, undefined],
    ]);
    expect(r.skipped.map((s) => s.reason)).toEqual(["not a tool execution"]);
  });
});

describe("wire contract with the Python UsageEmitter", () => {
  it("maps the golden projection written by runtime/tests/test_usage.py", async () => {
    const { readFileSync } = await import("node:fs");
    const events = JSON.parse(
      readFileSync(new URL("./fixtures/run-projection.json", import.meta.url), "utf8"),
    ) as RunEventLite[];
    const r = mapRunEvents(events, { tenantId: T });
    expect(r.skipped).toEqual([]);
    expect(
      r.records.map((x) => [
        x.meter,
        x.quantity,
        x.dimensions?.["tool_kind"] ?? x.dimensions?.["provider"],
      ]),
    ).toEqual([
      ["tool_executions", 1n, "memory_write"],
      ["tokens_in", 10n, "anthropic"],
      ["tokens_out", 5n, "anthropic"],
    ]);
    expect(
      r.records.every(
        (x) => x.dimensions?.["agent"] === "a@1" && x.dimensions?.["run"] === "run_1",
      ),
    ).toBe(true);
  });
});
