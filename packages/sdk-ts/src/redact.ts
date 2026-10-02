const INSPECT = Symbol.for("nodejs.util.inspect.custom");

export const REDACTED = "[REDACTED]";

/**
 * Holds a credential so that it cannot leak through `String()`, `JSON.stringify`, `console.log`,
 * `util.inspect` or a structured clone. The value is only reachable through `reveal()`.
 */
export class Secret {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  reveal(): string {
    return this.#value;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  [INSPECT](): string {
    return `Secret(${REDACTED})`;
  }
}

const PATTERNS: readonly RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /(x-axis-api-key["']?\s*[:=]\s*["']?)[^\s"',}]+/gi,
];

/** Remove known secret values and credential-shaped substrings from free text (messages, URLs, logs). */
export function redactText(text: string, secrets: readonly string[] = []): string {
  let out = text;
  for (const s of secrets) if (s.length >= 4) out = out.split(s).join(REDACTED);
  out = out.replace(PATTERNS[0] as RegExp, `Bearer ${REDACTED}`);
  out = out.replace(PATTERNS[1] as RegExp, `$1${REDACTED}`);
  return out;
}
