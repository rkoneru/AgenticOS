/**
 * One direction of a proxied connection: fragments are written in the ORDER they were released, whatever toxics were on when each chunk
 * arrived (TCP's byte order, and therefore HTTP/2 framing, must survive the fault injection).
 */
export interface LaneClock {
  /** Monotonic milliseconds. */
  now(): number;
  /** Run ``fn`` after ``ms`` milliseconds; returns a cancel function. */
  after(ms: number, fn: () => void): () => void;
}

export const realClock: LaneClock = {
  now: () => performance.now(),
  after: (ms, fn) => {
    const t = setTimeout(fn, ms);
    return () => clearTimeout(t);
  },
};

export class OrderedLane {
  private tail = 0;
  private queue: { at: number; write: () => void }[] = [];
  private cancel: (() => void) | undefined;

  constructor(private readonly clock: LaneClock = realClock) {}

  /**
   * Release ``fragments`` of one chunk, the first ``base`` ms from now (never before the previous fragment), ``gapMs`` apart.
   * A fragment that is due while an earlier one is still queued waits behind it: a timer that fires late (a busy event loop) must not
   * let a later chunk overtake it. Only an empty queue writes synchronously.
   */
  release(base: number, gapMs: number, fragments: Buffer[], write: (b: Buffer) => void): void {
    let due = Math.max(this.clock.now() + base, this.tail);
    for (const f of fragments) {
      const at = due;
      this.tail = at;
      due = at + gapMs;
      if (this.queue.length === 0 && at - this.clock.now() <= 0) write(f);
      else this.queue.push({ at, write: () => write(f) });
    }
    this.arm();
  }

  private arm(): void {
    if (this.cancel !== undefined || this.queue.length === 0) return;
    const head = this.queue[0] as { at: number };
    this.cancel = this.clock.after(Math.max(0, head.at - this.clock.now()), () => {
      this.cancel = undefined;
      while (this.queue.length > 0 && (this.queue[0] as { at: number }).at - this.clock.now() <= 0)
        (this.queue.shift() as { write: () => void }).write();
      this.arm();
    });
  }

  /** Drop everything not yet written (the connection is gone or the proxy stops). */
  stop(): void {
    this.cancel?.();
    this.cancel = undefined;
    this.queue = [];
  }
}
