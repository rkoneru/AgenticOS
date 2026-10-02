import { describe, expect, it } from "vitest";
import {
  Axis,
  AxisAbortError,
  AxisError,
  AxisWaitTimeoutError,
  collect,
  paginate,
  parseBlueprintRef,
  type RunEvent,
} from "../src/index.js";
import { createMockServer, json, problem, type Override } from "./mock-server.js";

const RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f";
const PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const run = (state: string) => ({
  id: RUN,
  blueprint: { name: "a", version: "1" },
  state,
  created_at: "2026-01-01T00:00:00Z",
});
const ev = (sequence: number) => ({
  sequence,
  type: "message",
  pid: PID,
  at: "2026-01-01T00:00:00Z",
});
const sse = (...events: RunEvent[]) =>
  events.map((e) => `id: ${e.sequence}\ndata: ${JSON.stringify(e)}\n\n`).join("");
const sseResponse = (text: string) =>
  new Response(text, { status: 200, headers: { "content-type": "text/event-stream" } });

function client(overrides: Record<string, Override>) {
  const server = createMockServer({ overrides });
  const sleeps: number[] = [];
  const ax = new Axis({
    apiKey: "axk_test_key_123456",
    baseUrl: server.baseUrl,
    fetch: server.fetch,
    sleep: (ms) => (sleeps.push(ms), Promise.resolve()),
  });
  return { ax, server, sleeps };
}

describe("runs.stream", () => {
  it("yields typed events, then ends when the stream closes and the run is terminated", async () => {
    const { ax } = client({
      listRunEvents: () => sseResponse(sse(ev(1), ev(2))),
      getRun: () => json(run("terminated")),
    });
    const got = await collect(ax.runs.stream(RUN));
    expect(got.map((e) => e.sequence)).toEqual([1, 2]);
  });

  it("reconnects with Last-Event-ID / after_sequence, skips duplicates, honours retry:", async () => {
    let conn = 0;
    const { ax, server, sleeps } = client({
      listRunEvents: () => {
        conn++;
        if (conn === 1) return sseResponse(`retry: 250\n${sse(ev(1), ev(2))}`);
        return sseResponse(sse(ev(2), ev(3))); // 2 is a replayed duplicate
      },
      getRun: (_c, n) => json(run(n === 1 ? "running" : "terminated")),
    });
    const got = await collect(ax.runs.stream(RUN));
    expect(got.map((e) => e.sequence)).toEqual([1, 2, 3]);
    const evCalls = server.calls.filter((c) => c.operationId === "listRunEvents");
    expect(evCalls).toHaveLength(2);
    expect(evCalls[0]?.headers.get("last-event-id")).toBe("0");
    expect(evCalls[1]?.headers.get("last-event-id")).toBe("2");
    expect(evCalls[1]?.url.searchParams.get("after_sequence")).toBe("2");
    expect(evCalls[1]?.headers.get("accept")).toBe("text/event-stream");
    expect(sleeps).toEqual([250]);
  });

  it("reconnects after a mid-stream disconnect", async () => {
    let conn = 0;
    const { ax } = client({
      listRunEvents: () => {
        conn++;
        if (conn === 1) {
          let pulls = 0;
          const body = new ReadableStream<Uint8Array>({
            pull(c) {
              if (pulls++ === 0) c.enqueue(new TextEncoder().encode(sse(ev(1))));
              else c.error(new TypeError("terminated"));
            },
          });
          return new Response(body, { status: 200 });
        }
        return sseResponse(sse(ev(2)));
      },
      getRun: () => json(run("terminated")),
    });
    // first connection errors after one event; the generator treats it as a drop and reconnects
    const got = await collect(ax.runs.stream(RUN));
    expect(got.map((e) => e.sequence)).toEqual([1, 2]);
  });

  it("starts after a given sequence", async () => {
    const { ax, server } = client({
      listRunEvents: () => sseResponse(sse(ev(6))),
      getRun: () => json(run("terminated")),
    });
    await collect(ax.runs.stream(RUN, { afterSequence: 5 }));
    expect(server.calls[0]?.url.searchParams.get("after_sequence")).toBe("5");
  });

  it("gives up after maxReconnects empty connections", async () => {
    const { ax } = client({
      listRunEvents: () => sseResponse(": nothing\n\n"),
      getRun: () => json(run("running")),
    });
    await expect(collect(ax.runs.stream(RUN, { maxReconnects: 2 }))).rejects.toThrow(
      /failed 3 times/,
    );
  });

  it("does not reconnect on a 4xx (permission, not found) but does on 5xx", async () => {
    const a = client({ listRunEvents: () => problem(404, "not_found") });
    await expect(collect(a.ax.runs.stream(RUN))).rejects.toMatchObject({ status: 404 });
    expect(a.server.calls).toHaveLength(1);
    let n = 0;
    const b = client({
      listRunEvents: () => (++n === 1 ? problem(503, "internal") : sseResponse(sse(ev(1)))),
      getRun: () => json(run("terminated")),
    });
    expect((await collect(b.ax.runs.stream(RUN))).map((e) => e.sequence)).toEqual([1]);
  });

  it("malformed event JSON is an error, caller abort stops it", async () => {
    const a = client({ listRunEvents: () => sseResponse("data: {not json\n\n") });
    await expect(collect(a.ax.runs.stream(RUN))).rejects.toThrow(/malformed JSON/);
    const ctl = new AbortController();
    ctl.abort();
    const b = client({});
    await expect(collect(b.ax.runs.stream(RUN, { signal: ctl.signal }))).rejects.toBeInstanceOf(
      AxisAbortError,
    );
  });

  it("ignores unrelated SSE event types and bodies without sequence", async () => {
    const { ax } = client({
      listRunEvents: () => sseResponse(`event: ping\ndata: {}\n\ndata: {"x":1}\n\n${sse(ev(1))}`),
      getRun: () => json(run("terminated")),
    });
    expect((await collect(ax.runs.stream(RUN))).map((e) => e.sequence)).toEqual([1]);
  });

  it("an empty body is an API error that is retried then reported", async () => {
    const { ax } = client({ listRunEvents: () => new Response(null, { status: 200 }) });
    await expect(collect(ax.runs.stream(RUN, { maxReconnects: 0 }))).rejects.toBeInstanceOf(
      AxisError,
    );
  });
});

describe("runs.wait / signal / cancel / events", () => {
  it("polls until terminated", async () => {
    let n = 0;
    const { ax, sleeps } = client({ getRun: () => json(run(++n < 3 ? "running" : "terminated")) });
    const r = await ax.runs.wait(RUN, { pollIntervalMs: 10 });
    expect(r.state).toBe("terminated");
    expect(sleeps).toEqual([10, 10]);
  });
  it("times out with AxisWaitTimeoutError", async () => {
    const { ax } = client({ getRun: () => json(run("running")) });
    await expect(ax.runs.wait(RUN, { timeoutMs: 0 })).rejects.toBeInstanceOf(AxisWaitTimeoutError);
  });
  it("cancel sends TERM; force sends KILL; signal passes pid and reason", async () => {
    const { ax, server } = client({});
    await ax.runs.cancel(RUN, { reason: "stop" });
    await ax.runs.cancel(RUN, { force: true });
    await ax.runs.signal(RUN, { signal: "PAUSE", pid: PID, reason: "r" });
    expect(server.calls.map((c) => c.body)).toEqual([
      { signal: "TERM", reason: "stop" },
      { signal: "KILL" },
      { signal: "PAUSE", pid: PID, reason: "r" },
    ]);
    expect(server.violations).toEqual([]);
  });
  it("allEvents follows pages by sequence", async () => {
    const { ax, server } = client({
      listRunEvents: (c) =>
        c.url.searchParams.get("after_sequence") === "0"
          ? json({ items: [ev(1), ev(2)], next_cursor: "c" })
          : json({ items: [ev(3)], next_cursor: null }),
    });
    expect((await collect(ax.runs.allEvents(RUN))).map((e) => e.sequence)).toEqual([1, 2, 3]);
    expect(server.calls).toHaveLength(2);
    const empty = client({ listRunEvents: () => json({ items: [], next_cursor: "c" }) });
    expect(await collect(empty.ax.runs.allEvents(RUN))).toEqual([]);
  });
});

describe("pagination and helpers", () => {
  it("iterates every page via next_cursor and honours maxItems", async () => {
    const pages: Record<string, unknown> = {
      "": { items: [run("running"), run("ready")], next_cursor: "p2" },
      p2: { items: [run("waiting")], next_cursor: null },
    };
    const { ax, server } = client({
      listRuns: (c) => json(pages[c.url.searchParams.get("cursor") ?? ""]),
    });
    expect(await collect(ax.runs.iterate({ limit: 2 }))).toHaveLength(3);
    expect(server.calls.map((c) => c.url.searchParams.get("cursor"))).toEqual([null, "p2"]);
    expect(await collect(ax.runs.iterate({ maxItems: 1 }))).toHaveLength(1);
  });
  it("paginate stops on a repeated cursor with no items", async () => {
    const out = await collect(paginate(() => Promise.resolve({ items: [], next_cursor: "x" })));
    expect(out).toEqual([]);
    let calls = 0;
    await collect(
      paginate(() =>
        Promise.resolve(++calls < 2 ? { items: [1], next_cursor: "a" } : { items: [2] }),
      ),
    );
    expect(calls).toBe(2);
  });
  it("blueprint refs", () => {
    expect(parseBlueprintRef("my-agent@1.2.3")).toEqual({ name: "my-agent", version: "1.2.3" });
    expect(parseBlueprintRef({ name: "a", version: "2" })).toEqual({ name: "a", version: "2" });
    for (const bad of ["noversion", "@1", "a@"])
      expect(() => parseBlueprintRef(bad)).toThrow(/name@version/);
  });
  it("other iterators and shortcuts", async () => {
    const { ax, server } = client({});
    expect(await collect(ax.blueprints.iterate({ maxItems: 1 }))).toHaveLength(1);
    expect(await collect(ax.approvals.iterate({ status: "pending", maxItems: 1 }))).toHaveLength(1);
    expect(await collect(ax.policies.iterate({ maxItems: 1 }))).toHaveLength(1);
    expect(await collect(ax.audit.iterate({ maxItems: 1, from_seq: 1 }))).toHaveLength(1);
    await ax.approvals.reject("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f", "no");
    await ax.killSwitches.release("tenant");
    await ax.audit.verify();
    expect(server.violations).toEqual([]);
    expect(() => ax.killSwitches.engage("agent")).toThrow(/needs a target/);
  });
});
