import { redactPatterns } from "@axis/channels";

/** A tenant-supplied hook (names, addresses: whatever the tenant's DLP catches) applied after the built-in net. */
export type RedactionHook = (text: string) => string;

export const MAX_DEPTH = 12;

/**
 * Redacts every string (and object key) inside a JSON value with the repository's PHI net (`redactPatterns`: emails, SSN- and
 * card-shaped numbers, phone numbers, mentions) plus the tenant hook. A failing hook withholds the value entirely: raw text never
 * passes through. Returns a new value; the input is not mutated. A net, not proof (docs/security/eval-hub-threat-model.md).
 */
export function redactJson(value: unknown, hook?: RedactionHook, depth = 0): unknown {
  if (depth > MAX_DEPTH) return "[redacted:depth]";
  if (typeof value === "string") {
    try {
      const t = redactPatterns(value);
      return hook ? redactPatterns(hook(t)) : t;
    } catch {
      return "[redacted:error]";
    }
  }
  if (Array.isArray(value)) return value.map((v) => redactJson(v, hook, depth + 1));
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>))
      out[redactJson(k, hook, depth + 1) as string] = redactJson(v, hook, depth + 1);
    return out;
  }
  return value;
}
