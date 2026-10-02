import { describe, expect, it } from "vitest";
import type { RunEvent } from "@/lib/api";
import { followRun, type FollowDeps, type FollowStatus } from "@/lib/follow";

const ev = (n: number): RunEvent => ({
  sequence: n,
  type: "x",
  pid: "p",
  at: "2026-01-01T00:00:00Z",
});

function harness(over: Partial<FollowDeps> & { log?: RunEvent[]; terminalAfter?: number } = {}) {
  const got: number[] = [];
  const statuses: FollowStatus[] = [];
  const sleeps: number[] = [];
  const ac = new AbortController();
  const afters: number[] = [];
  const d: FollowDeps = {
    signal: ac.signal,
    listEvents: async (after) => (over.log ?? []).filter((e) => e.sequence > after),
    stream: async () => undefined,
    isTerminal: async () => false,
    onEvent: (e) => got.push(e.sequence),
    onStatus: (s) => statuses.push(s),
    sleep: async (ms) => void sleeps.push(ms),
    ...over,
  };
  const wrapped: FollowDeps = {
    ...d,
    stream: async (after, onEvent, signal) => {
      afters.push(after);
      return d.stream(after, onEvent, signal);
    },
  };
  return { d: wrapped, got, statuses, sleeps, afters, ac };
}

describe("followRun", () => {
  it("backfills, streams, and ends when the run is terminal", async () => {
    let terminal = false;
    const h = harness({
      log: [ev(1), ev(2)],
      stream: async (_a, on) => {
        on(ev(3));
        on(ev(4));
        terminal = true;
      },
      isTerminal: async () => terminal,
    });
    await followRun(h.d);
    expect(h.got).toEqual([1, 2, 3, 4]);
    expect(h.statuses.at(-1)).toBe("ended");
  });

  it("reconnects after a dropped stream from the last sequence, without duplicates or gaps", async () => {
    let conn = 0;
    let terminal = false;
    const h = harness({
      stream: async (after, on) => {
        conn++;
        if (conn === 1) {
          on(ev(1));
          on(ev(2));
          throw new Error("network reset");
        }
        if (conn === 2) {
          on(ev(2)); // replayed by the server after the reconnect: must be dropped
          on(ev(3));
          return; // closed without terminal
        }
        on(ev(4));
        terminal = true;
        expect(after).toBe(3);
      },
      isTerminal: async () => terminal,
    });
    await followRun(h.d);
    expect(h.got).toEqual([1, 2, 3, 4]);
    expect(h.afters).toEqual([0, 2, 3]);
    expect(h.statuses).toContain("reconnecting");
    expect(h.statuses.at(-1)).toBe("ended");
  });

  it("backs off exponentially while nothing arrives and gives up with an error", async () => {
    const h = harness({
      stream: async () => {
        throw new Error("down");
      },
      maxFailures: 4,
    });
    await followRun(h.d);
    expect(h.sleeps).toEqual([1000, 2000, 4000]);
    expect(h.statuses.at(-1)).toBe("error");
  });

  it("a connection that made progress resets the failure count", async () => {
    let n = 0;
    const h = harness({
      stream: async (_a, on) => {
        n++;
        on(ev(n));
        throw new Error("flaky");
      },
      isTerminal: async () => n >= 10,
      maxFailures: 3,
    });
    await followRun(h.d);
    expect(h.statuses.at(-1)).toBe("ended");
    expect(Math.max(...h.sleeps)).toBe(1000);
  });

  it("stops silently when aborted", async () => {
    const h = harness({
      stream: async () => {
        h.ac.abort();
      },
    });
    await followRun(h.d);
    expect(h.statuses).not.toContain("error");
  });

  it("pages the JSON backfill", async () => {
    const log = Array.from({ length: 450 }, (_, i) => ev(i + 1));
    const h = harness({
      log,
      isTerminal: async () => true,
      listEvents: async (a) => log.filter((e) => e.sequence > a).slice(0, 200),
    });
    await followRun(h.d);
    expect(h.got).toHaveLength(450);
  });
});
