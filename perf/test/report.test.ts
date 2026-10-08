import { describe, expect, it } from "vitest";
import { check, judge, machine, renderMarkdown, type Report } from "../src/report.js";
import { Histogram } from "../src/hdr.js";

describe("verdicts come from evidence only", () => {
  it("max / min bounds", () => {
    expect(judge(5, "max", 10)).toBe("Met");
    expect(judge(10, "max", 10)).toBe("Met");
    expect(judge(11, "max", 10)).toBe("Not met");
    expect(judge(1000, "min", 1000)).toBe("Met");
    expect(judge(999, "min", 1000)).toBe("Not met");
  });
  it("no measurement is never Met", () => {
    expect(judge(null, "max", 10)).toBe("Not measured");
    expect(judge(Number.NaN, "min", 0)).toBe("Not measured");
  });
});

describe("renderMarkdown", () => {
  it("states the machine, the scenarios, the errors and the checks", () => {
    const h = new Histogram();
    [1000, 2000, 3000].forEach((x) => h.record(x));
    const s = h.summary();
    const rep: Report = {
      generatedAt: "2026-01-01T00:00:00Z",
      profile: "short",
      machine: machine(),
      scenarios: [
        {
          name: "me",
          description: "GET /me",
          result: {
            rate: 10,
            arrival: "constant",
            warmupMs: 0,
            durationMs: 1000,
            scheduled: 3,
            sent: 3,
            completed: 3,
            ok: 2,
            errors: 1,
            shed: 0,
            errorsByLabel: { http_500: 1 },
            achievedRate: 3,
            latency: s,
            service: s,
            maxGeneratorLagMs: 0.5,
            unfinished: 0,
          },
        },
      ],
      extra: { audit: { appendsPerSec: 1 } },
      checks: [
        check({
          id: "x",
          title: "x",
          target: "p99 < 5 ms",
          measured: 3,
          unit: "ms",
          bound: "max",
          limit: 5,
        }),
      ],
    };
    const md = renderMarkdown(rep);
    expect(md).toContain("Machine:");
    expect(md).toContain("| me | 10 |");
    expect(md).toContain("http_500");
    expect(md).toContain("**Met**");
    expect(md).toContain("appendsPerSec");
    const empty = renderMarkdown({ ...rep, scenarios: [], extra: {}, checks: [] });
    expect(empty).not.toContain("## Errors");
  });
});
