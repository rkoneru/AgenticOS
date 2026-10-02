import type { RunEvent } from "./api";

export type FollowStatus = "connecting" | "live" | "reconnecting" | "ended" | "error";

export interface FollowDeps {
  /** Events after `after` (JSON backfill). */
  listEvents(after: number): Promise<RunEvent[]>;
  /** Open the SSE stream after `after` and call `onEvent` for each event; resolves when the stream closes. */
  stream(after: number, onEvent: (e: RunEvent) => void, signal: AbortSignal): Promise<void>;
  /** True once the run is terminated (the log is complete). */
  isTerminal(): Promise<boolean>;
  onEvent(e: RunEvent): void;
  onStatus(s: FollowStatus, error?: Error): void;
  sleep(ms: number, signal: AbortSignal): Promise<void>;
  signal: AbortSignal;
  /** Consecutive connections without progress tolerated before giving up. Default 6. */
  maxFailures?: number;
}

const PAGE = 200;

/**
 * Follow a run's events: backfill over JSON, then the SSE stream; when the stream drops (proxy idle timeout, restart, network) and the run
 * is not terminal, reconnect with backoff from the last sequence seen (`after_sequence`), without duplicating or skipping an event.
 * A connection that made progress resets the failure count. Aborting `signal` stops everything silently.
 */
export async function followRun(d: FollowDeps, startAfter = 0): Promise<void> {
  let last = startAfter;
  let failures = 0;
  const max = d.maxFailures ?? 6;
  const emit = (e: RunEvent): boolean => {
    if (e.sequence <= last) return false;
    last = e.sequence;
    d.onEvent(e);
    return true;
  };
  for (;;) {
    if (d.signal.aborted) return;
    let progressed = false;
    try {
      for (;;) {
        const page = await d.listEvents(last);
        if (d.signal.aborted) return;
        for (const e of page) progressed = emit(e) || progressed;
        if (page.length < PAGE) break;
      }
      if (await d.isTerminal()) {
        d.onStatus("ended");
        return;
      }
      d.onStatus("live");
      await d.stream(last, (e) => void (emit(e) && (progressed = true)), d.signal);
      if (d.signal.aborted) return;
      if (await d.isTerminal()) {
        d.onStatus("ended");
        return;
      }
      failures = progressed ? 0 : failures + 1;
    } catch (e) {
      if (d.signal.aborted) return;
      failures = progressed ? 1 : failures + 1;
      if (failures >= max) {
        d.onStatus("error", e instanceof Error ? e : new Error(String(e)));
        return;
      }
    }
    if (failures >= max) {
      d.onStatus("error", new Error("the event stream keeps closing without new events"));
      return;
    }
    d.onStatus("reconnecting");
    await d.sleep(Math.min(1000 * 2 ** Math.max(0, failures - 1), 10_000), d.signal);
  }
}
