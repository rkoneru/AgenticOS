/** The four decision outcomes of the policy gate. The gate is fail-closed: anything else is DENY. */
export const DECISIONS = ["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"] as const;
export type Decision = (typeof DECISIONS)[number];

/** Default outcome on error, timeout, or missing policy. */
export const FAIL_CLOSED_DECISION: Decision = "DENY";

export function isDecision(value: unknown): value is Decision {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

/** Coerce any untrusted value to a Decision; unknown values fail closed to DENY. */
export function coerceDecision(value: unknown): Decision {
  return isDecision(value) ? value : FAIL_CLOSED_DECISION;
}
