import { describe, expect, it } from "vitest";
import { readSse, SseParser } from "../src/index.js";

const feed = (chunks: string[]) => {
  const p = new SseParser();
  const out = chunks.flatMap((c) => p.push(c));
  return { p, out };
};

describe("SseParser", () => {
  it("parses a simple event", () => {
    expect(feed(["data: hi\n\n"]).out).toEqual([{ event: "message", data: "hi", id: "" }]);
  });
  it("is independent of chunk boundaries (every split point)", () => {
    const text =
      'id: 7\nevent: run_event\ndata: {"a":1}\ndata: second\n\n: keepalive\n\ndata: x\r\n\r\n';
    const whole = feed([text]).out;
    expect(whole).toHaveLength(2);
    for (let i = 1; i < text.length; i++)
      expect(feed([text.slice(0, i), text.slice(i)]).out).toEqual(whole);
  });
  it("joins multi-line data with newlines and keeps a leading-space rule", () => {
    expect(feed(["data:  a\ndata\ndata: c\n\n"]).out[0]?.data).toBe(" a\n\nc");
  });
  it("ignores comments and unknown fields, and blank-only events", () => {
    expect(feed([": ping\nfoo: bar\n\n\n"]).out).toEqual([]);
  });
  it("handles CR, LF and CRLF line endings, including CR at a chunk end", () => {
    expect(feed(["data: a\r", "\ndata: b\r\r"]).out).toEqual([
      { event: "message", data: "a\nb", id: "" },
    ]);
    expect(feed(["data: a\rdata: b\r\r"]).out[0]?.data).toBe("a\nb");
  });
  it("strips a BOM, once", () => {
    expect(feed(["﻿data: a\n\n"]).out[0]?.data).toBe("a");
    expect(feed(["data: a\n\n﻿data: b\n\n"]).out[1]).toBeUndefined();
  });
  it("tracks last event id across events and ignores ids with NUL", () => {
    const { out, p } = feed(["id: 1\ndata: a\n\ndata: b\n\nid: 2\u00003\ndata: c\n\n"]);
    expect(out.map((e) => e.id)).toEqual(["1", "1", "1"]);
    expect(p.lastEventId).toBe("1");
  });
  it("records retry only when numeric", () => {
    expect(feed(["retry: 2500\n\n"]).p.retry).toBe(2500);
    expect(feed(["retry: soon\n\n"]).p.retry).toBeUndefined();
  });
  it("discards an unterminated trailing event at end of stream", () => {
    const p = new SseParser();
    expect(p.push("data: partial")).toEqual([]);
    p.end();
    expect(p.push("\n\n")).toEqual([]);
  });
  it("field without colon is a field with empty value", () => {
    expect(feed(["data\n\n"]).out[0]?.data).toBe("");
  });
});

describe("readSse", () => {
  it("decodes UTF-8 split across chunks", async () => {
    const bytes = new TextEncoder().encode("data: héllo \u{1F600}\n\n");
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        for (let i = 0; i < bytes.length; i += 3) c.enqueue(bytes.slice(i, i + 3));
        c.close();
      },
    });
    const evs = [];
    for await (const e of readSse(body, new SseParser())) evs.push(e);
    expect(evs[0]?.data).toBe("héllo \u{1F600}");
  });
});
