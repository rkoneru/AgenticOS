import { Histogram, type Summary } from "./hdr.js";

/**
 * Open-model load generator. Arrivals follow a SCHEDULE (constant rate or seeded Poisson) that does not depend on how fast the system
 * under test answers, so a slow server cannot slow the generator down (the "coordinated omission" trap of closed-loop tools).
 *
 * Latency is measured from the INTENDED start of each request, not from when the generator got round to sending it: if the event loop
 * is late, or a connection pool is exhausted, the queueing delay is charged to the request. The time from the actual send is recorded too
 * (``service``) so a reader can see how much of the latency was queueing in the generator/client rather than in the server.
 * An in-flight cap sheds load instead of letting memory grow without bound; shed arrivals are COUNTED as errors, never hidden.
 */
export interface Outcome {
  ok: boolean;
  /** error class or status label, e.g. "http_503", "timeout", "denied" */
  label?: string;
}

export interface LoadOptions {
  /** arrivals per second */
  rate: number;
  warmupMs: number;
  durationMs: number;
  /** "constant" (default) or "poisson" (exponential inter-arrival times from a seeded RNG) */
  arrival?: "constant" | "poisson";
  seed?: number;
  /** requests allowed in flight at once; beyond it an arrival is shed (default 10_000) */
  maxInFlight?: number;
  /** a request still running this long after its intended start is abandoned and counted as "timeout" (default 30 s) */
  timeoutMs?: number;
  /** injectable clock/timer for tests */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export interface LoadResult {
  rate: number;
  arrival: string;
  warmupMs: number;
  durationMs: number;
  /** arrivals scheduled / sent / completed in the measured window */
  scheduled: number;
  sent: number;
  completed: number;
  ok: number;
  errors: number;
  shed: number;
  errorsByLabel: Record<string, number>;
  achievedRate: number;
  /** microseconds, intended start -> completion */
  latency: Summary;
  /** microseconds, actual send -> completion */
  service: Summary;
  /** worst lateness of the generator itself in ms (how far behind schedule an arrival was sent) */
  maxGeneratorLagMs: number;
  /** requests still unfinished when the window closed (counted as timeout errors) */
  unfinished: number;
}

/** mulberry32: a tiny seeded PRNG so a Poisson schedule is reproducible. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Intended arrival offsets (ms from t0) for ``rate`` per second over ``totalMs``. */
export function schedule(
  rate: number,
  totalMs: number,
  arrival: "constant" | "poisson" = "constant",
  seed = 1,
): number[] {
  if (!(rate > 0)) throw new RangeError("rate must be > 0");
  const out: number[] = [];
  if (arrival === "constant") {
    const gap = 1000 / rate;
    for (let t = 0; t < totalMs; t += gap) out.push(t);
    return out;
  }
  const r = rng(seed);
  let t = 0;
  for (;;) {
    t += (-Math.log(1 - r()) * 1000) / rate;
    if (t >= totalMs) return out;
    out.push(t);
  }
}

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function runOpenLoad(
  fn: (index: number) => Promise<Outcome>,
  o: LoadOptions,
): Promise<LoadResult> {
  const now = o.now ?? ((): number => performance.now());
  const sleep = o.sleep ?? realSleep;
  const maxInFlight = o.maxInFlight ?? 10_000;
  const timeoutMs = o.timeoutMs ?? 30_000;
  const arrivals = schedule(
    o.rate,
    o.warmupMs + o.durationMs,
    o.arrival ?? "constant",
    o.seed ?? 1,
  );
  const latency = new Histogram();
  const service = new Histogram();
  const errorsByLabel: Record<string, number> = {};
  let sent = 0;
  let completed = 0;
  let ok = 0;
  let errors = 0;
  let shed = 0;
  let scheduled = 0;
  let inflight = 0;
  let maxLag = 0;
  const pending = new Set<Promise<void>>();
  const t0 = now();

  const fail = (label: string): void => {
    errors++;
    errorsByLabel[label] = (errorsByLabel[label] ?? 0) + 1;
  };

  const fire = (i: number, intended: number, measured: boolean): void => {
    const start = now();
    if (measured) maxLag = Math.max(maxLag, start - intended);
    inflight++;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const guarded = new Promise<Outcome>((resolve) => {
      const remaining = Math.max(1, timeoutMs - (start - intended));
      timer = setTimeout(() => resolve({ ok: false, label: "timeout" }), remaining);
      fn(i).then(resolve, (e: unknown) =>
        resolve({ ok: false, label: e instanceof Error ? e.name || "error" : "error" }),
      );
    });
    const p = guarded.then((out) => {
      clearTimeout(timer);
      inflight--;
      if (!measured) return;
      const end = now();
      completed++;
      latency.record((end - intended) * 1000);
      service.record((end - start) * 1000);
      if (out.ok) ok++;
      else fail(out.label ?? "error");
    });
    pending.add(p);
    void p.finally(() => pending.delete(p));
  };

  for (let k = 0; k < arrivals.length; k++) {
    const offset = arrivals[k] as number;
    const intended = t0 + offset;
    const wait = intended - now();
    if (wait > 1) await sleep(wait);
    const measured = offset >= o.warmupMs;
    if (measured) scheduled++;
    if (inflight >= maxInFlight) {
      if (measured) {
        shed++;
        fail("shed");
      }
      continue;
    }
    if (measured) sent++;
    fire(k, intended, measured);
  }

  // Drain: let in-flight requests finish, up to the per-request timeout, then count what is left.
  const deadline = now() + timeoutMs;
  while (pending.size > 0 && now() < deadline) await Promise.race([...pending, sleep(50)]);
  const unfinished = inflight;
  for (let i = 0; i < unfinished; i++) fail("unfinished");

  return {
    rate: o.rate,
    arrival: o.arrival ?? "constant",
    warmupMs: o.warmupMs,
    durationMs: o.durationMs,
    scheduled,
    sent,
    completed,
    ok,
    errors,
    shed,
    errorsByLabel,
    achievedRate: round((completed / o.durationMs) * 1000),
    latency: latency.summary(),
    service: service.summary(),
    maxGeneratorLagMs: round(maxLag),
    unfinished,
  };
}

const round = (x: number): number => Math.round(x * 100) / 100;
