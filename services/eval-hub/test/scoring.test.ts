import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { aggregate, compareRuns, mismatches, pairedSignFlip, round9 } from "../src/index.js";

const G = [
  { id: "a", weight: 1 },
  { id: "b", weight: 3 },
];

describe("aggregate", () => {
  it("weights graders, then averages cases and graders", () => {
    const r = aggregate(G, [
      { case_id: "c1", scores: { a: 1, b: 0 } },
      { case_id: "c2", scores: { a: 0, b: 1 } },
    ]);
    expect(r.per_case).toEqual({ c1: 0.25, c2: 0.75 });
    expect(r.per_grader).toEqual({ a: 0.5, b: 0.5 });
    expect(r.overall).toBe(0.5);
  });

  it("refuses a missing score or an empty input", () => {
    expect(() => aggregate(G, [{ case_id: "c1", scores: { a: 1 } }])).toThrow(/no score for b/);
    expect(() => aggregate(G, [])).toThrow();
    expect(() => aggregate([], [{ case_id: "c", scores: {} }])).toThrow();
    expect(() => aggregate(G, [{ case_id: "c1", scores: { a: Number.NaN, b: 1 } }])).toThrow();
  });

  it("does not depend on the order of cases or graders (property)", () => {
    const arb = fc.array(
      fc.tuple(
        fc.double({ min: 0, max: 1, noNaN: true }),
        fc.double({ min: 0, max: 1, noNaN: true }),
      ),
      {
        minLength: 1,
        maxLength: 30,
      },
    );
    fc.assert(
      fc.property(arb, fc.integer({ min: 0, max: 1000 }), (rows, seed) => {
        const cases = rows.map(([a, b], i) => ({
          case_id: `c${String(i).padStart(3, "0")}`,
          scores: { a, b },
        }));
        const base = aggregate(G, cases);
        const shuffled = [...cases].sort(
          (x, y) =>
            ((x.case_id.length * 31 + seed) % 7) - ((y.case_id.length * 17 + seed) % 5) ||
            (x.case_id < y.case_id ? 1 : -1),
        );
        const other = aggregate([...G].reverse(), shuffled);
        expect(other).toEqual(base);
        expect(base.overall).toBeGreaterThanOrEqual(0);
        expect(base.overall).toBeLessThanOrEqual(1);
      }),
      { numRuns: 100 },
    );
  });
});

describe("mismatches", () => {
  const computed = aggregate(G, [{ case_id: "c1", scores: { a: 1, b: 0.5 } }]);
  it("accepts a consistent claim (within the rounding epsilon)", () => {
    expect(
      mismatches({ overall: computed.overall + 1e-7, per_grader: computed.per_grader }, computed),
    ).toEqual([]);
    expect(mismatches({ overall: computed.overall }, computed)).toEqual([]);
  });
  it("names every disagreement", () => {
    expect(mismatches({ overall: 0.99 }, computed)).toEqual(["overall"]);
    expect(mismatches({ overall: "x" }, computed)).toEqual(["overall"]);
    expect(
      mismatches({ overall: computed.overall, per_grader: { a: 0, b: 0.5 } }, computed),
    ).toEqual(["per_grader.a"]);
    expect(
      mismatches({ overall: computed.overall, per_grader: { a: 1, b: 0.5, zzz: 1 } }, computed),
    ).toEqual(["per_grader.zzz"]);
    expect(mismatches({ overall: computed.overall, per_grader: { a: 1 } }, computed)).toEqual([
      "per_grader.b",
    ]);
    expect(mismatches({ overall: computed.overall, per_grader: [1] }, computed)).toEqual([
      "per_grader",
    ]);
    expect(mismatches({ overall: computed.overall, per_grader: null }, computed)).toEqual([
      "per_grader",
    ]);
  });
});

describe("pairedSignFlip", () => {
  it("is degenerate when nothing differs", () => {
    const r = pairedSignFlip([0, 0, 0], 0.05, "x");
    expect(r).toMatchObject({ method: "degenerate", p_value: 1, significant: false, n: 3 });
    expect(pairedSignFlip([], 0.05, "x").n).toBe(0);
  });

  it("computes the exact two-sided p-value by enumeration", () => {
    // 5 equal positive differences: only the all-plus and all-minus patterns reach |S| = 5d: p = 2/32.
    const r = pairedSignFlip([0.1, 0.1, 0.1, 0.1, 0.1], 0.05, "x");
    expect(r.method).toBe("exact");
    expect(r.p_value).toBe(0.0625);
    expect(r.significant).toBe(false);
    // 6 of them: p = 2/64 = 0.03125 -> significant at 0.05
    const r6 = pairedSignFlip(new Array<number>(6).fill(0.1), 0.05, "x");
    expect(r6.p_value).toBe(0.03125);
    expect(r6.significant).toBe(true);
    expect(r6.mean_diff).toBe(0.1);
  });

  it("is symmetric in the sign of the differences", () => {
    const d = [0.3, -0.1, 0.2, 0.05, -0.4, 0.15];
    expect(pairedSignFlip(d, 0.05, "s").p_value).toBe(
      pairedSignFlip(
        d.map((x) => -x),
        0.05,
        "s",
      ).p_value,
    );
  });

  it("uses a seeded Monte Carlo test above 16 non-zero pairs, reproducibly", () => {
    const d = Array.from({ length: 40 }, (_, i) => (i % 5 === 0 ? -0.05 : 0.1));
    const a = pairedSignFlip(d, 0.05, "seed-1");
    const b = pairedSignFlip(d, 0.05, "seed-1");
    expect(a).toEqual(b);
    expect(a.method).toBe("monte_carlo");
    expect(a.significant).toBe(true);
    const flat = pairedSignFlip(
      Array.from({ length: 40 }, (_, i) => (i % 2 ? 0.1 : -0.1)),
      0.05,
      "seed-1",
    );
    expect(flat.p_value).toBeGreaterThan(0.5);
  });
});

describe("compareRuns", () => {
  const mk = (
    id: string,
    perCase: Record<string, number>,
    over: Partial<{ suite_hash: string; dataset_hash: string }> = {},
  ) => {
    const vals = Object.values(perCase);
    return {
      id,
      record_hash: id.repeat(8),
      suite_hash: over.suite_hash ?? "s",
      dataset_hash: over.dataset_hash ?? "d",
      scores: {
        overall: round9(vals.reduce((a, b) => a + b, 0) / vals.length),
        per_grader: { g: 0.5 },
        per_case: perCase,
      },
    };
  };
  const o = { tolerance: 0.05, alpha: 0.05, requiresSignificance: false };
  const base = mk("b", { c1: 0.9, c2: 0.9, c3: 0.9, c4: 0.9 });

  it("a drop of exactly the tolerance is not a regression; more is", () => {
    const edge = compareRuns(mk("e", { c1: 0.85, c2: 0.85, c3: 0.85, c4: 0.85 }), base, o);
    expect(edge).toMatchObject({
      comparable: true,
      regression: false,
      blocking: false,
      delta: -0.05,
    });
    const worse = compareRuns(mk("w", { c1: 0.8, c2: 0.85, c3: 0.85, c4: 0.85 }), base, o);
    expect(worse).toMatchObject({ regression: true, blocking: true });
    expect(worse.delta).toBeCloseTo(-0.0625, 9);
  });

  it("an improvement is never a regression", () => {
    const better = compareRuns(mk("i", { c1: 1, c2: 1, c3: 1, c4: 1 }), base, o);
    expect(better).toMatchObject({ regression: false, blocking: false });
  });

  it("can require significance before a regression blocks", () => {
    const worse = mk("w", { c1: 0.5, c2: 0.9, c3: 0.9, c4: 0.9 });
    const lenient = compareRuns(worse, base, { ...o, requiresSignificance: true });
    expect(lenient.regression).toBe(true);
    expect(lenient.significance?.significant).toBe(false);
    expect(lenient.blocking).toBe(false);
  });

  it("is not comparable across suite or dataset versions, or different cases", () => {
    const same = { c1: 0.9, c2: 0.9, c3: 0.9, c4: 0.9 }; // identical cases: only the hashes differ
    expect(compareRuns(mk("x", same, { suite_hash: "other" }), base, o).comparable).toBe(false);
    expect(compareRuns(mk("x", same, { dataset_hash: "other" }), base, o).comparable).toBe(false);
    expect(compareRuns(mk("x", same), base, o).comparable).toBe(true);
    expect(compareRuns(mk("x", { c1: 1, c2: 1, c3: 1, c9: 1 }), base, o).comparable).toBe(false);
    expect(compareRuns(mk("x", {}), mk("y", {}), o).comparable).toBe(false);
  });

  it("reports per-grader deltas for graders both runs have", () => {
    const c = mk("c", { c1: 0.9, c2: 0.9, c3: 0.9, c4: 0.9 });
    (c.scores as { per_grader: Record<string, number> }).per_grader = { g: 0.7, extra: 1 };
    expect(compareRuns(c, base, o).per_grader_delta).toEqual({ g: 0.2 });
  });
});
