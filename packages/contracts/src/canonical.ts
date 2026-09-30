import { createHash } from "node:crypto";

/**
 * Canonical JSON for hashing: object keys sorted by UTF-16 code unit, no whitespace,
 * integers only (floats are rejected so hashes are portable across languages),
 * `undefined` rejected. Compatible with RFC 8785 for the value space we allow.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new TypeError(`canonicalize: only safe integers allowed, got ${value}`);
      }
      return String(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`canonicalize: unsupported type ${typeof value}`);
  }
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Hash of an arbitrary JSON payload (used for inputs_hash / outputs_hash). */
export function hashPayload(value: unknown): string {
  return sha256Hex(canonicalize(value));
}
