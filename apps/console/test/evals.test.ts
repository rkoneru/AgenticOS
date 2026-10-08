import { describe, expect, it } from "vitest";
import { scoreBars, sparkPoints } from "@/lib/eval-charts";
import { parseBlueprintRef } from "@/lib/eval-ref";
import { can } from "@/lib/roles";

describe("parseBlueprintRef", () => {
  it("accepts [namespace/]name@version and nothing else", () => {
    expect(parseBlueprintRef("answer-agent@1.0.0")).toEqual({
      name: "answer-agent",
      version: "1.0.0",
    });
    expect(parseBlueprintRef(" pub/answer-agent@1.2.3-rc.1 ")).toEqual({
      namespace: "pub",
      name: "answer-agent",
      version: "1.2.3-rc.1",
    });
    for (const bad of ["", "a", "a@", "@1", "A@1", "a/b/c@1", "a b@1", "a@1/../x", "<img>@1"])
      expect(parseBlueprintRef(bad), bad).toBeUndefined();
  });
});

describe("score charts", () => {
  it("bars live on a FIXED 0..1 axis (a high score is not stretched, a bad one is not hidden) and clamp junk", () => {
    const { bars, height } = scoreBars(
      [
        { label: "a", value: 0.5 },
        { label: "b", value: 2 },
        { label: "c", value: Number.NaN, other: -1 },
      ],
      { plotWidth: 100, rowHeight: 20, gap: 4, top: 2 },
    );
    expect(bars.map((b) => b.width)).toEqual([50, 100, 0]);
    expect(bars[2]?.otherWidth).toBe(0);
    expect(bars.map((b) => b.y)).toEqual([2, 26, 50]);
    expect(height).toBe(74);
    expect(bars[0]?.height).toBe(9); // two series share the row: the bars halve
  });
  it("a history is oldest first, bounded, and a single sample sits in the middle", () => {
    const one = sparkPoints([0.5], { width: 100, height: 50, pad: 10 });
    expect(one).toEqual([{ x: 50, y: 25, v: 0.5 }]);
    const many = sparkPoints([0, 1, 5], { width: 100, height: 50, pad: 10 });
    expect(many.map((p) => p.x)).toEqual([10, 50, 90]);
    expect(many.map((p) => p.y)).toEqual([40, 10, 10]);
  });
});

describe("eval capabilities (UI only; the server decides)", () => {
  it("builders write, operators review but do not write, viewers do neither", () => {
    expect(can("builder", "evals.write")).toBe(true);
    expect(can("operator", "evals.write")).toBe(false);
    expect(can("operator", "evals.review")).toBe(true);
    expect(can("viewer", "evals.review")).toBe(false);
    expect(can("auditor", "evals.write")).toBe(false);
  });
});
