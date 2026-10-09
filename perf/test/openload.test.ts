import { describe, expect, it } from "vitest";
import { rng, runOpenLoad, schedule } from "../src/openload.js";

/** A virtual clock: sleeping advances time instantly, so timing tests are exact and take no wall time. */
function virtual(): {
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  advance: (ms: number) => void;
} {
  let t = 0;
  return {
    now: () => t,
    sleep: async (ms) => {
      await new Promise((r) => setImmediate(r)); // let already-resolved requests complete at the CURRENT virtual time
      t += ms;
    },
    advance: (ms) => {
      t += ms;
    },
  };
}

describe("schedule", () => {
  it("constant arrivals are evenly spaced and independent of anything else", () => {
    const s = schedule(100, 1000);
    expect(s).toHaveLength(100);
    expect(s[1]! - s[0]!).toBeCloseTo(10);
  });
  it("poisson arrivals are reproducible per seed and average the requested rate", () => {
    const a = schedule(200, 10_000, "poisson", 7);
    const b = schedule(200, 10_000, "poisson", 7);
    const c = schedule(200, 10_000, "poisson", 8);
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
    expect(a.length / 10).toBeGreaterThan(180);
    expect(a.length / 10).toBeLessThan(220);
    expect([...a].sort((x, y) => x - y)).toEqual(a);
  });
  it("rejects a non-positive rate", () => {
    expect(() => schedule(0, 100)).toThrow(RangeError);
  });
  it("rng is deterministic and in [0,1)", () => {
    const r = rng(3);
    const xs = Array.from({ length: 1000 }, r);
    expect(xs.every((x) => x >= 0 && x < 1)).toBe(true);
    expect(Array.from({ length: 5 }, rng(3))).toEqual(xs.slice(0, 5));
  });
});

describe("runOpenLoad", () => {
  it("excludes the warmup from the results and counts ok/error outcomes", async () => {
    const v = virtual();
    const seen: number[] = [];
    const r = await runOpenLoad(
      (i) => {
        seen.push(i);
        return Promise.resolve(i % 4 === 0 ? { ok: false, label: "http_503" } : { ok: true });
      },
      { rate: 100, warmupMs: 500, durationMs: 1000, now: v.now, sleep: v.sleep },
    );
    expect(seen).toHaveLength(150); // warmup requests ARE sent
    expect(r.scheduled).toBe(100);
    expect(r.completed).toBe(100);
    expect(r.ok + r.errors).toBe(100);
    expect(r.errorsByLabel["http_503"]).toBe(r.errors);
    expect(r.achievedRate).toBe(100);
  });

  it("charges queueing to the request: latency is measured from the INTENDED start (no coordinated omission)", async () => {
    // The generator's thread is stuck for 200 ms once (a GC pause, a blocked loop): the arrivals due meanwhile are sent late
    // but measured from when they were due.
    const v = virtual();
    let stalled = false;
    const r = await runOpenLoad(() => Promise.resolve({ ok: true }), {
      rate: 100,
      warmupMs: 0,
      durationMs: 1000,
      now: v.now,
      sleep: (ms) => {
        const extra = !stalled && v.now() > 300 ? 200 : 0;
        stalled ||= extra > 0;
        return v.sleep(ms + extra);
      },
    });
    expect(r.latency.max).toBeGreaterThanOrEqual(150_000); // us: a late arrival is charged ~190 ms
    expect(r.service.max).toBeLessThan(10_000); // the server itself was instant
    expect(r.maxGeneratorLagMs).toBeGreaterThanOrEqual(150);
  });

  it("sheds arrivals above the in-flight cap and COUNTS them as errors", async () => {
    const v = virtual();
    const never = (): Promise<{ ok: boolean }> => new Promise(() => undefined);
    const r = await runOpenLoad(never, {
      rate: 100,
      warmupMs: 0,
      durationMs: 500,
      maxInFlight: 10,
      timeoutMs: 100,
      now: v.now,
      sleep: v.sleep,
    });
    expect(r.shed).toBe(40);
    expect(r.errorsByLabel["shed"]).toBe(40);
    expect(r.sent).toBe(10);
  });

  it("times out hung requests and records a thrown error by name", async () => {
    const real = await runOpenLoad(
      (i) => (i === 0 ? new Promise(() => undefined) : Promise.reject(new TypeError("boom"))),
      { rate: 20, warmupMs: 0, durationMs: 100, timeoutMs: 60 },
    );
    expect(real.errorsByLabel["timeout"]).toBeGreaterThanOrEqual(1);
    expect(real.errorsByLabel["TypeError"]).toBeGreaterThanOrEqual(1);
    expect(real.ok).toBe(0);
  });

  it("runs against real timers at the requested rate (smoke)", async () => {
    const r = await runOpenLoad(() => Promise.resolve({ ok: true }), {
      rate: 200,
      warmupMs: 50,
      durationMs: 400,
      arrival: "poisson",
      seed: 5,
    });
    expect(r.errors).toBe(0);
    expect(r.achievedRate).toBeGreaterThan(120);
    expect(r.achievedRate).toBeLessThan(300);
  });
});
