import { createHash } from "node:crypto";

/**
 * Canonical JSON: sorted keys, no whitespace, numbers in ECMAScript shortest form. `undefined`, functions, non-finite numbers and
 * non-plain values are errors, never silently dropped (a document hash must cover everything that is shown).
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("canonicalJson: non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
      const o = value as Record<string, unknown>;
      return `{${Object.keys(o)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
        .join(",")}}`;
    }
    default:
      throw new TypeError(`canonicalJson: unsupported value (${typeof value})`);
  }
}

export const sha256Hex = (text: string | Uint8Array): string =>
  createHash("sha256").update(text).digest("hex");

export const hashOf = (value: unknown): string => sha256Hex(canonicalJson(value));
