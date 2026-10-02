/** One dispatched Server-Sent Event (WHATWG HTML, section 9.2). */
export interface SseEvent {
  /** `event:` field; "message" when absent. */
  event: string;
  /** `data:` lines joined with "\n". */
  data: string;
  /** Last event id in effect when this event was dispatched ("" when none). */
  id: string;
}

/**
 * Incremental SSE parser. Feed it decoded text in arbitrary chunks (a chunk may end mid-line, mid-field or
 * between the CR and LF of a CRLF); it returns the events completed by that chunk. `retry` and
 * `lastEventId` persist across events as the specification requires.
 */
export class SseParser {
  lastEventId = "";
  /** Reconnection delay in ms from the last valid `retry:` field. */
  retry: number | undefined;
  #buf = "";
  #started = false;
  #data: string[] = [];
  #event = "";
  #pendingId: string | undefined;

  push(chunk: string): SseEvent[] {
    let text = this.#buf + chunk;
    this.#buf = "";
    if (!this.#started && text.length > 0) {
      this.#started = true;
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    }
    const out: SseEvent[] = [];
    let start = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c !== "\n" && c !== "\r") continue;
      if (c === "\r" && i === text.length - 1) break; // may be the first half of CRLF: wait for more
      const line = text.slice(start, i);
      if (c === "\r" && text[i + 1] === "\n") i++;
      start = i + 1;
      const ev = this.#line(line);
      if (ev) out.push(ev);
    }
    this.#buf = text.slice(start);
    return out;
  }

  /** End of stream: an unterminated final event is discarded, per the specification. */
  end(): void {
    this.#buf = "";
    this.#data = [];
    this.#event = "";
    this.#pendingId = undefined;
  }

  #line(line: string): SseEvent | undefined {
    if (line === "") {
      if (this.#pendingId !== undefined) this.lastEventId = this.#pendingId;
      this.#pendingId = undefined;
      const hadData = this.#data.length > 0;
      const ev: SseEvent = {
        event: this.#event || "message",
        data: this.#data.join("\n"),
        id: this.lastEventId,
      };
      this.#data = [];
      this.#event = "";
      return hadData ? ev : undefined;
    }
    if (line.startsWith(":")) return undefined; // comment / keep-alive
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "data":
        this.#data.push(value);
        break;
      case "event":
        this.#event = value;
        break;
      case "id":
        if (!value.includes("\0")) this.#pendingId = value;
        break;
      case "retry":
        if (/^\d+$/.test(value)) this.retry = Number(value);
        break;
      default:
    }
    return undefined;
  }
}

/** Decode a byte stream into SSE events. */
export async function* readSse(
  body: ReadableStream<Uint8Array>,
  parser: SseParser,
): AsyncGenerator<SseEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const ev of parser.push(decoder.decode(value, { stream: true }))) yield ev;
    }
    for (const ev of parser.push(decoder.decode())) yield ev;
    parser.end();
  } finally {
    reader.releaseLock();
  }
}
