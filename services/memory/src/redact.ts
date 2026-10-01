import { MemoryError, type Json } from "./types.js";

/** Same marker as the runtime (`axis_runtime.redaction.REDACTED`). */
export const REDACTED = "[REDACTED]";

/**
 * Field-path redaction with the SAME semantics as `runtime/src/axis_runtime/redaction.py` (parity is tested against the shared
 * vectors in `test/redaction-vectors.json`, which the Python tests also load): dot-separated paths, `*` matches every list
 * element / object value, a path that does not exist is a no-op, a malformed path throws (callers turn that into a rejection:
 * never persist unredacted data).
 */
export function parsePath(path: string): string[] {
  const parts = path.split(".");
  if (path === "" || parts.some((p) => p === ""))
    throw new MemoryError("INVALID", "malformed redaction path");
  return parts;
}

function apply(node: Json, parts: string[]): Json {
  const head = parts[0] as string;
  const rest = parts.slice(1);
  if (Array.isArray(node)) {
    const idxs =
      head === "*"
        ? node.map((_, i) => i)
        : /^\d+$/.test(head) && Number(head) < node.length
          ? [Number(head)]
          : [];
    for (const i of idxs) node[i] = rest.length === 0 ? REDACTED : apply(node[i] as Json, rest);
  } else if (typeof node === "object" && node !== null) {
    const keys = head === "*" ? Object.keys(node) : Object.hasOwn(node, head) ? [head] : [];
    for (const k of keys) node[k] = rest.length === 0 ? REDACTED : apply(node[k] as Json, rest);
  }
  return node;
}

export function redactPaths<T extends Json>(doc: T, paths: readonly string[]): T {
  const parsed = paths.map(parsePath); // validate every path before touching anything
  let out = structuredClone(doc) as Json;
  for (const parts of parsed) out = apply(out, parts);
  return out as T;
}

// Conservative free-text patterns. HEURISTIC, not a PHI detector: path redaction is the contract, this is a net under it
// (docs/NEEDS.md). Each pattern replaces the whole match.
const PATTERNS: RegExp[] = [
  /\b\d{3}-\d{2}-\d{4}\b/g, // US SSN
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g, // email
  /(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)/g, // US phone
  /\bMRN\s*[:#]?\s*\d{5,}\b/gi, // labelled medical record number
];

export function scrubText(text: string): string {
  let out = text;
  for (const re of PATTERNS) out = out.replace(re, REDACTED);
  return out;
}

function scrubJson(v: Json): Json {
  if (typeof v === "string") return scrubText(v);
  if (Array.isArray(v)) return v.map(scrubJson);
  if (typeof v === "object" && v !== null) {
    const o: { [k: string]: Json } = {};
    for (const [k, x] of Object.entries(v)) o[k] = scrubJson(x);
    return o;
  }
  return v;
}

/** Paths always redacted in PHI mode: the structured PHI/PII subtrees the policy packs name (`phi.*`, `pii.*`). */
export const DEFAULT_PHI_PATHS = ["metadata.phi", "metadata.pii"] as const;

/** Mirror of `split_scope(...)[0]` in the runtime: `args.x` and unprefixed paths apply here, `result.*` paths do not. */
export function argsPaths(paths: readonly string[]): string[] {
  const out: string[] = [];
  for (const p of paths) {
    if (p === "args") out.push("*");
    else if (p === "result" || p.startsWith("result.")) continue;
    else out.push(p.startsWith("args.") ? p.slice(5) : p);
  }
  return out;
}

export interface Redactable {
  content: string;
  metadata: { [k: string]: Json };
}

/**
 * PHI mode: applied BEFORE anything is embedded, hashed or persisted. Order: caller/policy paths + default PHI subtrees, then the
 * free-text scrub over every remaining string.
 */
export function redactForPhi(doc: Redactable, extraPaths: readonly string[] = []): Redactable {
  const stripped = argsPaths(extraPaths);
  const done = redactPaths(doc as unknown as Json, [
    ...DEFAULT_PHI_PATHS,
    ...stripped,
  ]) as unknown as Redactable;
  return scrubJson(done as unknown as Json) as unknown as Redactable;
}
