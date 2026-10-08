import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  aggregateGrid,
  compareRuns,
  mismatches,
  pairedSignFlip,
  r6,
  round9,
} from "../src/index.js";

interface Vector {
  name: string;
  suite: {
    pass_threshold: number;
    min_case_score: number | null;
    graders: { id: string; weight: number; min_mean?: number }[];
  };
  cases: Record<string, Record<string, { status: string; score: number }>>;
  errored: string[];
  expected: Record<string, unknown>;
}
const vectors = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/eval-aggregation-vectors.json", import.meta.url)),
    "utf8",
  ),
) as {
  version: number;
  vectors: Vector[];
};

describe("aggregation: the runner's shared vectors (hand-derived in docs/spec/evals-runner.md section 6)", () => {
  it("pins version 1 with 13 vectors", () => {
    expect(vectors.version).toBe(1);
    expect(vectors.vectors).toHaveLength(13);
  });
  for (const v of vectors.vectors)
    it(v.name, () => {
      const got = aggregateGrid(v.suite.graders, v.cases, {
        pass_threshold: v.suite.pass_threshold,
        min_case_score: v.suite.min_case_score,
        errored: v.errored,
      });
      expect(got).toEqual(v.expected);
      // the hub accepts the runner's own report of every vector, and refuses any perturbation of it
      expect(mismatches(v.expected, got)).toEqual([]);
    });
});

describe("aggregation rules", () => {
  const G = [
    { id: "a", weight: 1 },
    { id: "b", weight: 3 },
  ];
  const cell = (score: number) => ({ status: "scored", score });

  it("r6 rounds half-up to 6 decimals and clamps", () => {
    expect(r6(0.1234565)).toBe(0.123457);
    expect(r6(2 / 3)).toBe(0.666667);
    expect(r6(-1)).toBe(0);
    expect(r6(7)).toBe(1);
  });

  it("refuses a result set that does not match its suite", () => {
    expect(() => aggregateGrid([], {}, { pass_threshold: 0 })).toThrow(/at least one grader/);
    expect(() => aggregateGrid([G[0] as never, G[0] as never], {}, { pass_threshold: 0 })).toThrow(
      /duplicate grader/,
    );
    expect(() => aggregateGrid(G, { "bad id": { a: cell(1) } }, { pass_threshold: 0 })).toThrow(
      /invalid case id/,
    );
    expect(() => aggregateGrid(G, { c1: { zzz: cell(1) } }, { pass_threshold: 0 })).toThrow(
      /does not declare/,
    );
    expect(() =>
      aggregateGrid(G, { c1: { a: cell(1) } }, { pass_threshold: 0, errored: ["ghost"] }),
    ).toThrow(/errored case/);
  });

  it("does not depend on the order the runner listed the cases (property)", () => {
    const arb = fc.array(
      fc.tuple(
        fc.double({ min: 0, max: 1, noNaN: true }),
        fc.double({ min: 0, max: 1, noNaN: true }),
      ),
      { minLength: 1, maxLength: 30 },
    );
    fc.assert(
      fc.property(arb, fc.integer({ min: 0, max: 1000 }), (rows, seed) => {
        const entries = rows.map(
          ([a, b], i) => [`c${String(i).padStart(3, "0")}`, { a: cell(a), b: cell(b) }] as const,
        );
        const base = aggregateGrid(G, Object.fromEntries(entries), { pass_threshold: 0.5 });
        const shuffled = [...entries].sort(
          (x, y) =>
            ((x[0].length * 31 + seed) % 7) - ((y[0].length * 17 + seed) % 5) ||
            (x[0] < y[0] ? 1 : -1),
        );
        expect(aggregateGrid(G, Object.fromEntries(shuffled), { pass_threshold: 0.5 })).toEqual(
          base,
        );
        expect(base.overall).toBeGreaterThanOrEqual(0);
        expect(base.overall).toBeLessThanOrEqual(1);
      }),
      { numRuns: 100 },
    );
  });
});

describe("mismatches", () => {
  const computed = aggregateGrid(
    G2(),
    { c1: { a: { status: "scored", score: 1 }, b: { status: "scored", score: 0.5 } } },
    { pass_threshold: 0.5 },
  );
  function G2() {
    return [
      { id: "a", weight: 1 },
      { id: "b", weight: 3 },
    ];
  }
  it("accepts a consistent claim (within the rounding epsilon)", () => {
    expect(
      mismatches({ ...computed, overall: (computed.overall as number) + 1e-7 }, computed),
    ).toEqual([]);
  });
  it("names every disagreement", () => {
    expect(mismatches({ ...computed, overall: 0.99 }, computed)).toEqual(["overall"]);
    expect(mismatches({ ...computed, overall: "x" }, computed)).toEqual(["overall"]);
    expect(mismatches({ ...computed, passed: !computed.passed }, computed)).toEqual(["passed"]);
    expect(mismatches({ ...computed, failures: ["x"] }, computed)).toEqual(["failures"]);
    expect(mismatches({ ...computed, ungraded: 3 }, computed)).toEqual(["ungraded"]);
    expect(mismatches({ ...computed, status: "pending_human" }, computed)).toEqual(["status"]);
    expect(mismatches({ ...computed, per_grader: { a: 0, b: 0.5 } }, computed)).toEqual([
      "per_grader.a",
    ]);
    expect(
      mismatches({ ...computed, per_grader: { ...computed.per_grader, zzz: 1 } }, computed),
    ).toEqual(["per_grader.zzz"]);
    expect(mismatches({ ...computed, per_case: {} }, computed)).toEqual(["per_case.c1"]);
    expect(mismatches({ ...computed, per_grader: [1] }, computed)).toEqual(["per_grader"]);
    expect(mismatches({ ...computed, per_case: null }, computed)).toEqual(["per_case"]);
    expect(mismatches(null, computed)).toEqual(["scores"]);
    expect(mismatches([], computed)).toEqual(["scores"]);
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
