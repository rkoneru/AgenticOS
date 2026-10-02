import { invalid } from "./errors.js";

/**
 * Strict semver 2.0.0 (https://semver.org) and the range syntax blueprints use: exact, `^`, `~`, comparators (`>= > <= < =`, ANDed
 * by spaces), `||`, `*`. Partial versions are accepted only after `^` and `~` (`^1.2`, `~1`).
 * Pre-releases follow the npm rule: a pre-release version satisfies a comparator set only when a comparator of that set names a
 * pre-release of the same major.minor.patch. The registry rejects build metadata on publish (two versions that differ only in
 * `+build` have equal precedence, which would make "highest version" ambiguous), but parsing accepts it.
 */
export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: readonly (string | number)[];
  build: readonly string[];
}

const NUM = "(0|[1-9]\\d*)";
const PRE_ID = "(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)";
const VERSION_RE = new RegExp(
  `^${NUM}\\.${NUM}\\.${NUM}(?:-(${PRE_ID}(?:\\.${PRE_ID})*))?(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$`,
);
const MAX_LEN = 128;

export function tryParseVersion(s: string): SemVer | undefined {
  if (typeof s !== "string" || s.length === 0 || s.length > MAX_LEN) return undefined;
  const m = VERSION_RE.exec(s);
  if (!m) return undefined;
  const nums = [m[1], m[2], m[3]].map(Number);
  if (!nums.every((n) => Number.isSafeInteger(n))) return undefined;
  const pre = (m[4] ?? "")
    .split(".")
    .filter((x) => x !== "")
    .map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  if (pre.some((x) => typeof x === "number" && !Number.isSafeInteger(x))) return undefined;
  return {
    major: nums[0] as number,
    minor: nums[1] as number,
    patch: nums[2] as number,
    prerelease: pre,
    build: (m[5] ?? "").split(".").filter((x) => x !== ""),
  };
}

export function parseVersion(s: string): SemVer {
  const v = tryParseVersion(s);
  if (!v) throw invalid(`not a strict semantic version: ${JSON.stringify(String(s).slice(0, 64))}`);
  return v;
}

export function formatVersion(v: SemVer): string {
  return (
    `${v.major}.${v.minor}.${v.patch}` +
    (v.prerelease.length ? `-${v.prerelease.join(".")}` : "") +
    (v.build.length ? `+${v.build.join(".")}` : "")
  );
}

const cmpNum = (a: number, b: number): number => (a < b ? -1 : a > b ? 1 : 0);

/** Semver precedence (build metadata ignored). Returns -1, 0 or 1. */
export function compareVersions(a: SemVer, b: SemVer): number {
  const core = cmpNum(a.major, b.major) || cmpNum(a.minor, b.minor) || cmpNum(a.patch, b.patch);
  if (core !== 0) return core;
  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1; // a release outranks its pre-releases
  if (b.prerelease.length === 0) return -1;
  const n = Math.min(a.prerelease.length, b.prerelease.length);
  for (let i = 0; i < n; i++) {
    const x = a.prerelease[i] as string | number;
    const y = b.prerelease[i] as string | number;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return cmpNum(x, y);
    if (typeof x === "number") return -1; // numeric identifiers sort below alphanumeric ones
    if (typeof y === "number") return 1;
    return x < y ? -1 : 1;
  }
  return cmpNum(a.prerelease.length, b.prerelease.length);
}

export const compareVersionStrings = (a: string, b: string): number =>
  compareVersions(parseVersion(a), parseVersion(b));

type Op = ">=" | ">" | "<=" | "<" | "=";
interface Comparator {
  op: Op;
  v: SemVer;
}
/** OR of AND-sets. */
export type Range = readonly (readonly Comparator[])[];

const v3 = (
  major: number,
  minor: number,
  patch: number,
  pre: (string | number)[] = [],
): SemVer => ({
  major,
  minor,
  patch,
  prerelease: pre,
  build: [],
});

const PARTIAL_RE = /^(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?(?:-([0-9A-Za-z.-]+))?$/;

interface Partial3 {
  major: number;
  minor: number | undefined;
  patch: number | undefined;
  pre: SemVer["prerelease"];
}

function parsePartial(s: string): Partial3 {
  const m = PARTIAL_RE.exec(s);
  if (!m) throw invalid(`bad version in range: ${JSON.stringify(s.slice(0, 64))}`);
  const minor = m[2] === undefined ? undefined : Number(m[2]);
  const patch = m[3] === undefined ? undefined : Number(m[3]);
  let pre: SemVer["prerelease"] = [];
  if (m[4] !== undefined) {
    if (patch === undefined) throw invalid("a pre-release needs a full version");
    pre = parseVersion(`0.0.0-${m[4]}`).prerelease;
  }
  const nums = [Number(m[1]), minor, patch].filter((x): x is number => x !== undefined);
  if (!nums.every(Number.isSafeInteger)) throw invalid("version number out of range");
  return { major: Number(m[1]), minor, patch, pre };
}

function caret(p: Partial3): Comparator[] {
  const { major, minor, patch, pre } = p;
  const lo = v3(major, minor ?? 0, patch ?? 0, [...pre]);
  let hi: SemVer;
  if (major > 0 || minor === undefined) hi = v3(major + 1, 0, 0);
  else if (minor > 0 || patch === undefined) hi = v3(0, minor + 1, 0);
  else hi = v3(0, 0, patch + 1);
  return [
    { op: ">=", v: lo },
    { op: "<", v: hi },
  ];
}

function tilde(p: Partial3): Comparator[] {
  const { major, minor, patch, pre } = p;
  const lo = v3(major, minor ?? 0, patch ?? 0, [...pre]);
  const hi = minor === undefined ? v3(major + 1, 0, 0) : v3(major, minor + 1, 0);
  return [
    { op: ">=", v: lo },
    { op: "<", v: hi },
  ];
}

const MAX_RANGE_LEN = 256;
const MAX_SETS = 16;
const MAX_COMPARATORS = 16;

export function parseRange(input: string): Range {
  if (typeof input !== "string" || input.trim() === "") throw invalid("empty version range");
  if (input.length > MAX_RANGE_LEN) throw invalid("version range too long");
  const sets = input.split("||").map((s) => s.trim());
  if (sets.length > MAX_SETS) throw invalid("too many alternatives in range");
  return sets.map((set): Comparator[] => {
    if (set === "") throw invalid("empty alternative in range");
    const toks = set.split(/\s+/);
    if (toks.length > MAX_COMPARATORS) throw invalid("too many comparators in range");
    const out: Comparator[] = [];
    for (const t of toks) {
      if (t === "*") {
        out.push({ op: ">=", v: v3(0, 0, 0) });
      } else if (t.startsWith("^")) {
        out.push(...caret(parsePartial(t.slice(1))));
      } else if (t.startsWith("~")) {
        out.push(...tilde(parsePartial(t.slice(1))));
      } else {
        const m = /^(>=|<=|>|<|=)?(.+)$/.exec(t);
        const op = ((m as RegExpExecArray)[1] ?? "=") as Op;
        out.push({ op, v: parseVersion((m as RegExpExecArray)[2] as string) });
      }
    }
    return out;
  });
}

const holds = (v: SemVer, c: Comparator): boolean => {
  const r = compareVersions(v, c.v);
  switch (c.op) {
    case ">=":
      return r >= 0;
    case ">":
      return r > 0;
    case "<=":
      return r <= 0;
    case "<":
      return r < 0;
    case "=":
      return r === 0;
  }
};

const sameTuple = (a: SemVer, b: SemVer): boolean =>
  a.major === b.major && a.minor === b.minor && a.patch === b.patch;

export function satisfies(v: SemVer, range: Range): boolean {
  return range.some((set) => {
    if (!set.every((c) => holds(v, c))) return false;
    if (v.prerelease.length === 0) return true;
    return set.some((c) => c.v.prerelease.length > 0 && sameTuple(c.v, v));
  });
}

/** Highest version (by precedence) that satisfies `range`; versions that do not parse are ignored. */
export function maxSatisfying(versions: readonly string[], range: Range): string | undefined {
  let best: { s: string; v: SemVer } | undefined;
  for (const s of versions) {
    const v = tryParseVersion(s);
    if (!v || !satisfies(v, range)) continue;
    if (!best || compareVersions(v, best.v) > 0) best = { s, v };
  }
  return best?.s;
}
