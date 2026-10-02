import { describe, expect, it } from "vitest";
import { barLayout, niceMax, scaleLinear, ticks, totalsByMeter } from "@/lib/charts";
import { parseCases, runCases, SAMPLE_CASES } from "@/lib/policy-tests";
import { formatNumber, formatTime, formatUsd, shortId } from "@/lib/format";

describe("charts", () => {
  it("picks nice maxima and ticks", () => {
    expect(niceMax(0)).toBe(1);
    expect(niceMax(NaN)).toBe(1);
    expect(niceMax(0.7)).toBe(1);
    expect(niceMax(1.4)).toBe(2);
    expect(niceMax(3)).toBe(5);
    expect(niceMax(7)).toBe(10);
    expect(niceMax(1234)).toBe(2000);
    expect(ticks(10, 2)).toEqual([0, 5, 10]);
  });
  it("scales linearly and handles a degenerate domain", () => {
    const s = scaleLinear([0, 10], [0, 100]);
    expect(s(5)).toBe(50);
    expect(scaleLinear([3, 3], [7, 9])(3)).toBe(7);
  });
  it("lays out bars within the box", () => {
    const { bars, max } = barLayout(
      [
        { label: "a", value: 5 },
        { label: "b", value: 10 },
        { label: "c", value: 0 },
      ],
      { width: 300, height: 120, padLeft: 30, padBottom: 20 },
    );
    expect(max).toBe(10);
    expect(bars).toHaveLength(3);
    expect(bars[1]!.height).toBeGreaterThan(bars[0]!.height);
    expect(bars[2]!.height).toBe(0);
    for (const b of bars) {
      expect(b.x).toBeGreaterThanOrEqual(30);
      expect(b.x + b.width).toBeLessThanOrEqual(300);
      expect(b.y + b.height).toBeLessThanOrEqual(100);
    }
    expect(barLayout([], { width: 100, height: 100, padLeft: 10, padBottom: 10 }).bars).toEqual([]);
  });
  it("totals per meter", () => {
    expect(
      totalsByMeter([
        { meter: "tokens", quantity: 3, unit: "tok" },
        { meter: "a", quantity: 1, unit: "u" },
        { meter: "tokens", quantity: 4, unit: "tok" },
      ]),
    ).toEqual([
      { meter: "a", unit: "u", total: 1 },
      { meter: "tokens", unit: "tok", total: 7 },
    ]);
  });
});

describe("policy cases", () => {
  it("parses the sample", () => {
    const r = parseCases(SAMPLE_CASES);
    expect("cases" in r && r.cases).toHaveLength(2);
  });
  it("rejects malformed input", () => {
    expect(parseCases("{")).toMatchObject({ error: expect.stringContaining("not valid JSON") });
    expect(parseCases("{}")).toMatchObject({ error: "Cases must be a JSON array" });
    expect(parseCases(JSON.stringify(new Array(101).fill(0)))).toMatchObject({
      error: "At most 100 cases",
    });
    expect(parseCases("[null]")).toMatchObject({ error: expect.stringContaining("Case 1") });
    expect(
      parseCases(
        '[{"name":"a","request":{"enforcement_point":"x","context":{}},"expect":"MAYBE"}]',
      ),
    ).toMatchObject({ error: expect.stringContaining("expect must be") });
    expect(
      parseCases(
        '[{"name":"a","request":{"enforcement_point":"x","context":null},"expect":"ALLOW"}]',
      ),
    ).toMatchObject({ error: expect.stringContaining("Case 1") });
  });
  it("keeps the optional action", () => {
    const r = parseCases(
      '[{"name":"a","request":{"enforcement_point":"x","action":"y","context":{}},"expect":"ALLOW"}]',
    );
    expect("cases" in r && r.cases[0]!.request.action).toBe("y");
  });
  it("runs cases, failing closed on errors", async () => {
    const parsed = parseCases(SAMPLE_CASES);
    if (!("cases" in parsed)) throw new Error("x");
    const res = await runCases(parsed.cases, async (req) => {
      if (req.action === "email.send") throw new Error("boom");
      return { decision: "ALLOW", policy_version: "1", reason: "r", matched_rule_ids: ["R1"] };
    });
    expect(res[0]).toMatchObject({ pass: true, actual: "ALLOW", rules: ["R1"] });
    expect(res[1]).toMatchObject({ pass: false, error: "boom" });
    const res2 = await runCases(parsed.cases.slice(0, 1), async () => {
      throw "str";
    });
    expect(res2[0]!.error).toBe("evaluation failed");
    const res3 = await runCases(parsed.cases.slice(0, 1), async () => ({
      decision: "DENY",
      policy_version: "1",
    }));
    expect(res3[0]).toMatchObject({ pass: false, actual: "DENY", rules: [] });
  });
});

describe("format", () => {
  it("formats", () => {
    expect(shortId("abcdefghijkl")).toBe("abcdefgh");
    expect(shortId("abc")).toBe("abc");
    expect(formatTime("2026-01-02T03:04:05.678Z")).toBe("2026-01-02 03:04:05Z");
    expect(formatTime(null)).toBe("-");
    expect(formatTime("nope")).toBe("-");
    expect(formatNumber(1500000)).toBe("1.50M");
    expect(formatNumber(25000)).toBe("25.0k");
    expect(formatNumber(12)).toBe("12");
    expect(formatNumber(1.234)).toBe("1.23");
    expect(formatNumber(Infinity)).toBe("-");
    expect(formatUsd(0.0123)).toBe("$0.0123");
    expect(formatUsd(12.5)).toBe("$12.50");
  });
});
