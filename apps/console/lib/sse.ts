import type { RunEvent } from "./api";

/** Incremental server-sent-events parser (WHATWG framing: `data:` lines, blank-line terminated). */
export class SseParser {
  private buf = "";
  private data: string[] = [];
  private event = "message";

  /** Feed a decoded text chunk; returns completed `{event, data}` messages. */
  push(chunk: string): Array<{ event: string; data: string }> {
    this.buf += chunk;
    const out: Array<{ event: string; data: string }> = [];
    let idx: number;
    while ((idx = this.buf.search(/\r\n|\n|\r/)) >= 0) {
      const m = /^(\r\n|\n|\r)/.exec(this.buf.slice(idx));
      const nl = m![0];
      // A lone "\r" at the very end may be the first half of "\r\n"; wait for more input.
      if (nl === "\r" && idx + 1 === this.buf.length) break;
      const line = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + nl.length);
      if (line === "") {
        if (this.data.length) out.push({ event: this.event, data: this.data.join("\n") });
        this.data = [];
        this.event = "message";
      } else if (line.startsWith(":")) {
        continue;
      } else {
        const c = line.indexOf(":");
        const field = c < 0 ? line : line.slice(0, c);
        let value = c < 0 ? "" : line.slice(c + 1);
        if (value.startsWith(" ")) value = value.slice(1);
        if (field === "data") this.data.push(value);
        else if (field === "event") this.event = value;
      }
    }
    return out;
  }
}

/** True for objects shaped like a RunEvent. Anything else on the wire is dropped, never rendered. */
export function isRunEvent(v: unknown): v is RunEvent {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e["sequence"] === "number" &&
    Number.isInteger(e["sequence"]) &&
    typeof e["type"] === "string" &&
    typeof e["pid"] === "string" &&
    typeof e["at"] === "string"
  );
}

/** Read a byte stream of SSE and call `onEvent` for each valid RunEvent. Resolves when the stream ends. */
export async function consumeRunEvents(
  stream: ReadableStream<Uint8Array>,
  onEvent: (e: RunEvent) => void,
): Promise<void> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const m of parser.push(decoder.decode(value, { stream: true }))) {
        if (m.event !== "message" && m.event !== "run_event") continue;
        try {
          const parsed: unknown = JSON.parse(m.data);
          if (isRunEvent(parsed)) onEvent(parsed);
        } catch {
          /* malformed frame: ignore */
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}
