import { describe, expect, it } from "vitest";
import { Histogram } from "../src/hdr.js";

function exactPercentile(xs: number[], p: number): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.max(0, Math.ceil((p / 100) * s.length) - 1)] as number;
}

describe("Histogram", () => {
  it("maps values to buckets and back without gaps or overlaps", () => {
    let prevHigh = -1;
    for (let i = 0; i < 2048 + 1024 * 12; i++) {
      const { low, high } = Histogram.bounds(i);
      expect(low).toBe(prevHigh + 1);
      expect(Histogram.indexOf(low)).toBe(i);
      expect(Histogram.indexOf(high)).toBe(i);
      prevHigh = high;
    }
  });

  it("keeps every percentile within 0.1% of the exact value (relative precision)", () => {
    let s = 12345;
    const next = (): number => (s = (s * 1664525 + 1013904223) >>> 0) / 4294967296;
    const xs = Array.from({ length: 50_000 }, () => Math.floor(Math.exp(next() * 16))); // 1 us .. ~9 s, heavy tail
    const h = new Histogram();
    xs.forEach((x) => h.record(x));
    for (const p of [1, 25, 50, 90, 95, 99, 99.9, 100]) {
      const exact = exactPercentile(xs, p);
      const got = h.percentile(p);
      expect(got).toBeGreaterThanOrEqual(exact);
      expect(got - exact).toBeLessThanOrEqual(Math.max(1, exact * 0.001));
    }
    expect(h.count).toBe(xs.length);
    expect(h.min).toBe(Math.min(...xs));
    expect(h.max).toBe(Math.max(...xs));
    expect(h.mean).toBeCloseTo(xs.reduce((a, b) => a + b, 0) / xs.length, 6);
  });

  it("is exact below 2048 and monotonic in p", () => {
    const h = new Histogram();
    for (let v = 0; v < 2000; v++) h.record(v);
    expect(h.percentile(50)).toBe(999);
    expect(h.percentile(100)).toBe(1999);
    let prev = 0;
    for (let p = 1; p <= 100; p += 3) {
      const v = h.percentile(p);
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
  });

  it("never reports above the maximum recorded value", () => {
    const h = new Histogram();
    h.record(1_000_003);
    expect(h.percentile(100)).toBe(1_000_003);
    expect(h.percentile(50)).toBe(1_000_003);
  });

  it("is empty-safe, clamps negatives, and rejects bad input", () => {
    const h = new Histogram();
    expect(h.percentile(99)).toBe(0);
    expect(h.min).toBe(0);
    expect(h.mean).toBe(0);
    h.record(-5);
    expect(h.max).toBe(0);
    expect(() => h.record(Number.NaN)).toThrow(RangeError);
    expect(() => h.record(Infinity)).toThrow(RangeError);
    expect(() => h.record(1, 0)).toThrow(RangeError);
    expect(() => h.percentile(0)).toThrow(RangeError);
    expect(() => h.percentile(101)).toThrow(RangeError);
  });

  it("memory is bounded by the value range, not the sample count", () => {
    const h = new Histogram();
    for (let i = 0; i < 300_000; i++) h.record(1 + (i % 5_000_000));
    expect(h.buckets).toBeLessThan(2048 + 1024 * 24);
    expect(h.count).toBe(300_000);
  });

  it("merges two histograms", () => {
    const a = new Histogram();
    const b = new Histogram();
    for (let i = 1; i <= 100; i++) a.record(i);
    for (let i = 101; i <= 200; i++) b.record(i);
    a.merge(b);
    expect(a.count).toBe(200);
    expect(a.percentile(50)).toBe(100);
    expect(a.max).toBe(200);
    expect(a.min).toBe(1);
  });

  it("recordCorrected fills in the samples a stalled closed loop would have omitted", () => {
    const plain = new Histogram();
    plain.record(10_000);
    const corrected = new Histogram();
    corrected.recordCorrected(10_000, 1_000);
    expect(plain.count).toBe(1);
    expect(corrected.count).toBe(10); // 10000, 9000, ..., 1000
    expect(corrected.percentile(50)).toBeLessThan(10_000);
    const noop = new Histogram();
    noop.recordCorrected(500, 1_000);
    noop.recordCorrected(500, 0);
    expect(noop.count).toBe(2);
  });

  it("summary has every field", () => {
    const h = new Histogram();
    for (let i = 1; i <= 1000; i++) h.record(i * 10);
    const s = h.summary();
    expect(s.count).toBe(1000);
    expect(s.p50).toBeLessThanOrEqual(s.p95);
    expect(s.p95).toBeLessThanOrEqual(s.p99);
    expect(s.p99).toBeLessThanOrEqual(s.p999);
    expect(s.p999).toBeLessThanOrEqual(s.max);
  });
});
