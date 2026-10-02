import { describe, expect, it } from "vitest";
import { SseParser, consumeRunEvents, isRunEvent } from "@/lib/sse";
import type { RunEvent } from "@/lib/api";

const ev = (n: number): RunEvent => ({
  sequence: n,
  type: "tool_call",
  pid: "axp_0000000000000000000000000A",
  at: "2026-01-01T00:00:00Z",
});
const frame = (e: unknown, name?: string) =>
  `${name ? `event: ${name}\n` : ""}data: ${JSON.stringify(e)}\n\n`;

describe("SseParser", () => {
  it("parses frames split across chunks", () => {
    const p = new SseParser();
    const text = frame({ a: 1 }) + frame({ b: 2 });
    const mid = 7;
    expect(p.push(text.slice(0, mid))).toEqual([]);
    expect(p.push(text.slice(mid)).map((m) => m.data)).toEqual(['{"a":1}', '{"b":2}']);
  });
  it("handles CRLF, comments, multi-line data and named events", () => {
    const p = new SseParser();
    const out = p.push(": hi\r\nevent: x\r\ndata: a\r\ndata: b\r\n\r\ndata:c\r\n\r\n");
    expect(out).toEqual([
      { event: "x", data: "a\nb" },
      { event: "message", data: "c" },
    ]);
  });
  it("waits for a lone CR at the end of a chunk", () => {
    const p = new SseParser();
    expect(p.push("data: z\r")).toEqual([]);
    expect(p.push("\n\r\n")).toEqual([{ event: "message", data: "z" }]);
  });
  it("ignores empty frames and fields without colon", () => {
    const p = new SseParser();
    expect(p.push("\n\ndata\n\n")).toEqual([{ event: "message", data: "" }]);
    expect(p.push("retry: 1000\n\n")).toEqual([]);
  });
});

describe("isRunEvent", () => {
  it("validates shape", () => {
    expect(isRunEvent(ev(1))).toBe(true);
    expect(isRunEvent(null)).toBe(false);
    expect(isRunEvent("x")).toBe(false);
    expect(isRunEvent({ ...ev(1), sequence: 1.5 })).toBe(false);
    expect(isRunEvent({ ...ev(1), type: 3 })).toBe(false);
  });
});

describe("consumeRunEvents", () => {
  it("delivers valid events, drops invalid and malformed frames", async () => {
    const enc = new TextEncoder();
    const chunks = [
      frame(ev(1)),
      frame({ nope: true }),
      "data: {not json\n\n",
      frame(ev(2), "run_event"),
      frame(ev(3), "heartbeat"),
      frame(ev(4)),
    ];
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (const ch of chunks) c.enqueue(enc.encode(ch));
        c.close();
      },
    });
    const got: number[] = [];
    await consumeRunEvents(stream, (e) => got.push(e.sequence));
    expect(got).toEqual([1, 2, 4]);
  });
});
