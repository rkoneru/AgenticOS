import { createHash } from "node:crypto";

/**
 * Canonical JSON for hashing ABL documents: object keys sorted by UTF-16 code unit, no whitespace.
 *
 * `@axis/contracts` `canonicalize` rejects non-integer numbers (so audit hashes stay portable), but ABL legitimately
 * contains floats (`temperature: 0.1`, `costUsd: 2.5`, `threshold: 0.92`). Numbers are therefore written with
 * ECMAScript `JSON.stringify` formatting, which is the shortest round-trip form and fully deterministic. The same
 * number always yields the same text, which is all a content hash needs. Non-finite numbers and non-JSON types throw.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError(`canonicalJson: non-finite number ${value}`);
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`canonicalJson: unsupported type ${typeof value}`);
  }
}

/** sha256 (hex) of the canonical JSON of `value`. */
export function contentHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}
