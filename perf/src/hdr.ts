/**
 * An HDR-style histogram: log-linear buckets, constant RELATIVE precision (about 0.1%: 1024 sub-buckets per power of two), integer values
 * (microseconds by convention). Memory is bounded by the value range (a few tens of thousands of counters for 1 us .. 1 h), never by the
 * number of samples, so a long run cannot grow it. Percentiles are returned as the HIGHEST value equivalent to the bucket, like the
 * reference HdrHistogram, so a reported pXX is never optimistic by more than the bucket width.
 */
const SUB_BITS = 11; // 2048 sub-buckets in the first (linear) range
const SUB_COUNT = 1 << SUB_BITS;
const HALF = SUB_COUNT >> 1; // 1024

export class Histogram {
  private counts: number[] = [];
  private total = 0;
  private minV = Number.POSITIVE_INFINITY;
  private maxV = 0;
  private sum = 0;

  /** Index of the bucket that holds ``v`` (an integer >= 0). */
  static indexOf(v: number): number {
    if (v < SUB_COUNT) return v;
    const shift = Math.floor(Math.log2(v)) - (SUB_BITS - 1);
    const sub = Math.floor(v / 2 ** shift); // in [HALF, SUB_COUNT)
    return SUB_COUNT + (shift - 1) * HALF + (sub - HALF);
  }

  /** Lowest and highest integer value that fall in bucket ``idx``. */
  static bounds(idx: number): { low: number; high: number } {
    if (idx < SUB_COUNT) return { low: idx, high: idx };
    const k = idx - SUB_COUNT;
    const shift = Math.floor(k / HALF) + 1;
    const sub = (k % HALF) + HALF;
    const low = sub * 2 ** shift;
    return { low, high: low + 2 ** shift - 1 };
  }

  get count(): number {
    return this.total;
  }
  get min(): number {
    return this.total === 0 ? 0 : this.minV;
  }
  get max(): number {
    return this.maxV;
  }
  get mean(): number {
    return this.total === 0 ? 0 : this.sum / this.total;
  }

  /** Record ``n`` observations of ``value`` (rounded to an integer, negatives clamp to 0, non-finite values are rejected). */
  record(value: number, n = 1): void {
    if (!Number.isFinite(value))
      throw new RangeError(`histogram value must be finite, got ${value}`);
    if (!Number.isInteger(n) || n < 1) throw new RangeError("count must be a positive integer");
    const v = Math.max(0, Math.round(value));
    const idx = Histogram.indexOf(v);
    this.counts[idx] = (this.counts[idx] ?? 0) + n;
    this.total += n;
    this.sum += v * n;
    if (v < this.minV) this.minV = v;
    if (v > this.maxV) this.maxV = v;
  }

  /**
   * Record ``value`` and, when it exceeds ``expectedInterval``, the samples a closed-loop generator would have OMITTED while it was stuck
   * (HdrHistogram's ``recordValueWithExpectedInterval``): value - interval, value - 2*interval, ... Used only for closed-loop sources;
   * the open-model generator measures from the intended start instead and never needs it.
   */
  recordCorrected(value: number, expectedInterval: number): void {
    this.record(value);
    if (expectedInterval <= 0) return;
    for (
      let missing = value - expectedInterval;
      missing >= expectedInterval;
      missing -= expectedInterval
    ) {
      this.record(missing);
    }
  }

  /** The value at percentile ``p`` (0..100]: the smallest recorded-bucket value with at least p% of samples at or below it. */
  percentile(p: number): number {
    if (this.total === 0) return 0;
    if (!(p > 0 && p <= 100)) throw new RangeError("percentile must be in (0, 100]");
    const target = Math.max(1, Math.ceil((p / 100) * this.total - 1e-9));
    let seen = 0;
    for (let i = 0; i < this.counts.length; i++) {
      const c = this.counts[i];
      if (c === undefined) continue;
      seen += c;
      if (seen >= target) return Math.min(Histogram.bounds(i).high, this.maxV);
    }
    return this.maxV;
  }

  merge(other: Histogram): void {
    other.counts.forEach((c, i) => {
      if (c !== undefined) this.counts[i] = (this.counts[i] ?? 0) + c;
    });
    this.total += other.total;
    this.sum += other.sum;
    this.minV = Math.min(this.minV, other.minV);
    this.maxV = Math.max(this.maxV, other.maxV);
  }

  /** Number of allocated counters (memory is bounded by the value range, asserted by a test). */
  get buckets(): number {
    return this.counts.length;
  }

  summary(): Summary {
    return {
      count: this.total,
      min: this.min,
      mean: round(this.mean),
      p50: this.percentile(50),
      p90: this.percentile(90),
      p95: this.percentile(95),
      p99: this.percentile(99),
      p999: this.percentile(99.9),
      max: this.max,
    };
  }
}

export interface Summary {
  count: number;
  min: number;
  mean: number;
  p50: number;
  p90: number;
  p95: number;
  p99: number;
  p999: number;
  max: number;
}

const round = (x: number): number => Math.round(x * 100) / 100;
