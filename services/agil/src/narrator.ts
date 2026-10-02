import type { Explanation } from "./types.js";

/**
 * OPTIONAL narrator (OFF by default). A narrator turns an explanation into smoother prose through the ModelGateway. It receives
 * ONLY the enumerated, PHI-safe projection below: gate kinds, decisions, enforcement points, counts and rule ids; never an audit
 * reason string, an actor id, a value or a free-text field. Its output is shown next to (never instead of) the deterministic
 * explanation and never feeds back into any decision.
 */
export interface NarratorInput {
  decisions: { gate: string; decision: string; enforcement_point: string; rule_ids: string[] }[];
  remediation_kinds: string[];
}

export type Narrator = (input: NarratorInput) => Promise<string>;

export function narratorInput(e: Explanation): NarratorInput {
  return {
    decisions: e.decision_refs.slice(0, 20).map((r) => ({
      gate: r.gate,
      decision: r.decision,
      enforcement_point: r.enforcement_point,
      rule_ids: r.rule_ids.slice(0, 5),
    })),
    remediation_kinds: e.remediation.map((r) => r.kind),
  };
}

export interface NarrationOptions {
  /** Must be explicitly true; defaults to off. */
  enabled?: boolean;
  narrator?: Narrator;
}

/** The deterministic explanation, plus a `narrative` only when the flag is on and the narrator answers. Failures are silent. */
export async function withNarration(
  e: Explanation,
  o: NarrationOptions = {},
): Promise<Explanation & { narrative?: string }> {
  if (o.enabled !== true || !o.narrator) return e;
  try {
    const text = await o.narrator(narratorInput(e));
    return typeof text === "string" && text.length > 0
      ? { ...e, narrative: text.slice(0, 2000) }
      : e;
  } catch {
    return e;
  }
}
