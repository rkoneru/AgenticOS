import { describe, expect, it } from "vitest";
import { OrderedLane, type LaneClock } from "../src/lane.js";

/** A clock the test drives by hand: timers never fire by themselves, and "now" can move past a pending timer (an event loop that lags). */
class ManualClock implements LaneClock {
  t = 0;
  private pending: { at: number; fn: () => void; live: boolean }[] = [];
  now(): number {
    return this.t;
  }
  after(ms: number, fn: () => void): () => void {
    const e = { at: this.t + ms, fn, live: true };
    this.pending.push(e);
    return () => {
      e.live = false;
    };
  }
  /** Fire every live timer that is due, earliest first (what the event loop does when it catches up). */
  run(): void {
    for (;;) {
      const due = this.pending
        .filter((e) => e.live && e.at <= this.t)
        .sort((a, b) => a.at - b.at)[0];
      if (!due) return;
      due.live = false;
      due.fn();
    }
  }
}

const frag = (s: string): Buffer[] => [...s].map((c) => Buffer.from(c));

describe("OrderedLane", () => {
  it("writes an undelayed chunk immediately", () => {
    const clock = new ManualClock();
    const out: string[] = [];
    new OrderedLane(clock).release(0, 0, [Buffer.from("A")], (b) => out.push(b.toString()));
    expect(out).toEqual(["A"]);
  });

  it("spaces fragments by the gap and keeps their order", () => {
    const clock = new ManualClock();
    const out: string[] = [];
    new OrderedLane(clock).release(5, 10, frag("xyz"), (b) => out.push(b.toString()));
    expect(out).toEqual([]);
    clock.t = 5;
    clock.run();
    expect(out).toEqual(["x"]);
    clock.t = 25;
    clock.run();
    expect(out).toEqual(["x", "y", "z"]);
  });

  it("a later chunk never overtakes a fragment that is already due but not yet written (a lagging event loop)", () => {
    const clock = new ManualClock();
    const out: string[] = [];
    const write = (b: Buffer): void => void out.push(b.toString());
    const lane = new OrderedLane(clock);
    lane.release(10, 10, frag("AAA"), write); // due at 10, 20, 30
    clock.t = 100; // the loop was busy: all three are overdue, none has run
    lane.release(0, 0, frag("B"), write); // an undelayed chunk arrives NOW
    clock.run();
    expect(out.join("")).toBe("AAAB");
  });
});
