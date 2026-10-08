import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface WireExample {
  name: string;
  as: "admin" | "builder" | "reviewer" | "runner" | "none";
  method: string;
  path: string;
  request?: unknown;
  status: number;
  capture?: Record<string, string>;
  response: unknown;
}
export interface Wire {
  version: number;
  base_path: string;
  examples: WireExample[];
}

export const loadWire = (): Wire =>
  JSON.parse(
    readFileSync(fileURLToPath(new URL("../contract/wire-v1.json", import.meta.url)), "utf8"),
  ) as Wire;

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A string that is exactly `{{x}}` becomes the (typed) captured value; `{{x}}` inside a longer string becomes its text. */
export function subst<T>(v: T, vars: Record<string, unknown>): T {
  const walk = (n: unknown): unknown => {
    if (typeof n === "string") {
      const m = /^\{\{(\w+)\}\}$/.exec(n);
      if (m) return m[1] !== undefined && m[1] in vars ? vars[m[1]] : `UNBOUND:${m[1]}`;
      return n.replace(/\{\{(\w+)\}\}/g, (_m, k: string) =>
        k in vars ? String(vars[k]) : `UNBOUND:${k}`,
      );
    }
    if (Array.isArray(n)) return n.map(walk);
    if (typeof n === "object" && n !== null)
      return Object.fromEntries(Object.entries(n).map(([k, x]) => [k, walk(x)]));
    return n;
  };
  return walk(v) as T;
}

/** Returns the list of mismatches ("path: why"); empty = the actual value conforms to the expected shape. */
export function conform(expected: unknown, actual: unknown, path = "$"): string[] {
  if (typeof expected === "string" && /^<\w+>$/.test(expected)) {
    const ok: Record<string, (a: unknown) => boolean> = {
      "<uuid>": (a) => typeof a === "string" && UUID.test(a),
      "<iso>": (a) => typeof a === "string" && ISO.test(a),
      "<hash>": (a) => typeof a === "string" && /^[0-9a-f]{64}$/.test(a),
      "<string>": (a) => typeof a === "string",
      "<number>": (a) => typeof a === "number",
      "<integer>": (a) => Number.isInteger(a),
      "<boolean>": (a) => typeof a === "boolean",
      "<null>": (a) => a === null,
      "<any>": () => true,
    };
    const f = ok[expected];
    if (!f) return [`${path}: unknown placeholder ${expected}`];
    return f(actual)
      ? []
      : [`${path}: expected ${expected}, got ${JSON.stringify(actual)?.slice(0, 80)}`];
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return [`${path}: expected an array`];
    if (expected[0] === "<each>")
      return actual.flatMap((a, i) => conform(expected[1], a, `${path}[${i}]`));
    if (expected.length !== actual.length)
      return [`${path}: expected ${expected.length} elements, got ${actual.length}`];
    return expected.flatMap((e, i) => conform(e, actual[i], `${path}[${i}]`));
  }
  if (typeof expected === "object" && expected !== null) {
    if (typeof actual !== "object" || actual === null || Array.isArray(actual))
      return [`${path}: expected an object`];
    return Object.entries(expected).flatMap(([k, v]) =>
      k in (actual as object)
        ? conform(v, (actual as Record<string, unknown>)[k], `${path}.${k}`)
        : [`${path}.${k}: missing`],
    );
  }
  return Object.is(expected, actual) ||
    (typeof expected === "number" &&
      typeof actual === "number" &&
      Math.abs(expected - actual) < 1e-9)
    ? []
    : [
        `${path}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)?.slice(0, 80)}`,
      ];
}

export function pick(obj: unknown, dotted: string): unknown {
  return dotted
    .split(".")
    .reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], obj);
}
