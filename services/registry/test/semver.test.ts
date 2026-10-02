import fc from "fast-check";
import semver from "semver";
import { describe, expect, it } from "vitest";
import {
  compareVersionStrings,
  formatVersion,
  maxSatisfying,
  parseRange,
  parseVersion,
  satisfies,
  tryParseVersion,
} from "../src/index.js";

const VALID = [
  "0.0.0",
  "1.2.3",
  "10.20.30",
  "1.0.0-alpha",
  "1.0.0-alpha.1",
  "1.0.0-0.3.7",
  "1.0.0-x.7.z.92",
  "1.0.0-alpha+001",
  "1.0.0+20130313144700",
  "1.0.0-beta+exp.sha.5114f85",
  "1.0.0-rc.1",
];
const INVALID = [
  "",
  "1",
  "1.2",
  "1.2.3.4",
  "01.2.3",
  "1.02.3",
  "1.2.03",
  "1.2.3-",
  "1.2.3-01",
  "1.2.3-+",
  "1.2.3+",
  "v1.2.3",
  "1.2.3 ",
  " 1.2.3",
  "1.2.x",
  "-1.2.3",
  "1.2.3-alpha..1",
  "99999999999999999999.0.0",
  "1.2.3-a_b",
];

describe("strict semver parsing", () => {
  it.each(VALID)("accepts %s", (v) => expect(tryParseVersion(v)).toBeDefined());
  it.each(INVALID)("rejects %j", (v) => expect(tryParseVersion(v)).toBeUndefined());
  it("parseVersion throws invalid, and rejects overlong input", () => {
    expect(() => parseVersion("nope")).toThrow(/semantic version/);
    expect(tryParseVersion("1.0.0-" + "a".repeat(200))).toBeUndefined();
    expect(tryParseVersion(undefined as unknown as string)).toBeUndefined();
  });
  it("formatVersion round-trips", () => {
    for (const v of VALID) expect(formatVersion(parseVersion(v))).toBe(v);
  });
  it("agrees with the reference parser on a fixed corpus", () => {
    // The reference trims whitespace and accepts a leading "v"; strict parsing deliberately does not.
    for (const v of [...VALID, ...INVALID].filter((x) => x.trim() === x && !x.startsWith("v")))
      expect(tryParseVersion(v) !== undefined).toBe(semver.valid(v) !== null);
  });
});

const arbVersion = fc
  .record({
    major: fc.integer({ min: 0, max: 4 }),
    minor: fc.integer({ min: 0, max: 4 }),
    patch: fc.integer({ min: 0, max: 4 }),
    pre: fc.option(
      fc.array(
        fc.oneof(
          fc.integer({ min: 0, max: 5 }).map(String),
          fc.constantFrom("alpha", "beta", "rc", "a", "b-1"),
        ),
        { minLength: 1, maxLength: 3 },
      ),
      { nil: undefined },
    ),
  })
  .map((r) => `${r.major}.${r.minor}.${r.patch}${r.pre ? "-" + r.pre.join(".") : ""}`);

describe("ordering matches the reference implementation", () => {
  it("compare", () => {
    fc.assert(
      fc.property(arbVersion, arbVersion, (a, b) => {
        expect(compareVersionStrings(a, b)).toBe(semver.compare(a, b));
      }),
      { numRuns: 500 },
    );
  });
  it("build metadata does not change precedence", () => {
    expect(compareVersionStrings("1.0.0+a", "1.0.0+b")).toBe(0);
  });
  it("is a total order (antisymmetric, transitive)", () => {
    fc.assert(
      fc.property(arbVersion, arbVersion, arbVersion, (a, b, c) => {
        expect(compareVersionStrings(a, b)).toBe(0 - compareVersionStrings(b, a));
        if (compareVersionStrings(a, b) <= 0 && compareVersionStrings(b, c) <= 0)
          expect(compareVersionStrings(a, c)).toBeLessThanOrEqual(0);
      }),
      { numRuns: 300 },
    );
  });
});

const arbRange = fc.oneof(
  arbVersion.map((v) => v),
  arbVersion.map((v) => `^${v}`),
  arbVersion.map((v) => `~${v}`),
  fc.tuple(fc.constantFrom(">=", ">", "<=", "<", "="), arbVersion).map(([o, v]) => `${o}${v}`),
  fc.tuple(arbVersion, arbVersion).map(([a, b]) => `>=${a} <${b}`),
  fc.tuple(arbVersion, arbVersion).map(([a, b]) => `^${a} || ~${b}`),
  fc.constant("*"),
);

describe("range resolution matches the reference implementation", () => {
  it("satisfies", () => {
    fc.assert(
      fc.property(arbRange, arbVersion, (r, v) => {
        expect(satisfies(parseVersion(v), parseRange(r))).toBe(semver.satisfies(v, r));
      }),
      { numRuns: 1500 },
    );
  });
  it("maxSatisfying", () => {
    fc.assert(
      fc.property(arbRange, fc.array(arbVersion, { maxLength: 12 }), (r, vs) => {
        expect(maxSatisfying(vs, parseRange(r)) ?? null).toBe(semver.maxSatisfying(vs, r));
      }),
      { numRuns: 800 },
    );
  });
  it("partial versions after ^ and ~", () => {
    const cases: [string, string[]][] = [
      ["^1.2", ["1.2.0", "1.9.9", "2.0.0", "1.1.9"]],
      ["^0.2", ["0.2.0", "0.2.9", "0.3.0"]],
      ["^0.0", ["0.0.0", "0.0.9", "0.1.0"]],
      ["^0", ["0.0.1", "0.9.0", "1.0.0"]],
      ["~1", ["1.0.0", "1.9.0", "2.0.0"]],
      ["~1.2", ["1.2.0", "1.2.9", "1.3.0"]],
      ["^0.0.3", ["0.0.3", "0.0.4"]],
      ["^1.2.3-beta.2", ["1.2.3-beta.2", "1.2.3-beta.3", "1.2.3", "1.3.0-beta.1", "2.0.0"]],
    ];
    for (const [r, vs] of cases)
      for (const v of vs)
        expect(satisfies(parseVersion(v), parseRange(r)), `${r} ${v}`).toBe(semver.satisfies(v, r));
  });
  it("pre-releases are excluded unless named by the range", () => {
    expect(satisfies(parseVersion("1.5.0-beta.1"), parseRange("^1.0.0"))).toBe(false);
    expect(satisfies(parseVersion("1.5.0-beta.2"), parseRange(">=1.5.0-beta.1 <2.0.0"))).toBe(true);
  });
});

describe("range syntax errors", () => {
  it.each([
    "",
    "   ",
    "^",
    "~x",
    "1.2",
    ">=1.2",
    "^1.2.3.4",
    "||",
    "1.0.0 ||",
    "^1.0-beta",
    "latest",
    "^01.2.3",
    "a".repeat(300),
    "^99999999999999999999.0.0",
  ])("rejects %j", (r) => {
    expect(() => parseRange(r)).toThrow();
  });
  it("limits alternatives and comparators", () => {
    expect(() => parseRange(Array.from({ length: 20 }, (_, i) => `${i}.0.0`).join("||"))).toThrow(
      /alternatives/,
    );
    expect(() => parseRange(Array.from({ length: 20 }, () => ">=1.0.0").join(" "))).toThrow(
      /comparators/,
    );
    expect(() => parseRange(undefined as unknown as string)).toThrow();
  });
  it("maxSatisfying ignores unparseable versions", () => {
    expect(maxSatisfying(["junk", "1.0.0", "1.1.0"], parseRange("^1.0.0"))).toBe("1.1.0");
    expect(maxSatisfying([], parseRange("*"))).toBeUndefined();
  });
});
