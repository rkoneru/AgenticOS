import type { Decision, GateDecision } from "./api";

export interface PolicyCase {
  name: string;
  request: { enforcement_point: string; action?: string; context: Record<string, unknown> };
  expect: Decision;
}

export interface CaseResult {
  name: string;
  expected: Decision;
  actual?: Decision;
  reason?: string | undefined;
  rules?: string[];
  pass: boolean;
  error?: string;
}

const DECISIONS: ReadonlySet<string> = new Set([
  "ALLOW",
  "DENY",
  "REQUIRE_APPROVAL",
  "ALLOW_WITH_REDACTION",
]);

export function parseCases(text: string): { cases: PolicyCase[] } | { error: string } {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch (e) {
    return { error: `Cases are not valid JSON: ${(e as Error).message}` };
  }
  if (!Array.isArray(v)) return { error: "Cases must be a JSON array" };
  if (v.length > 100) return { error: "At most 100 cases" };
  const cases: PolicyCase[] = [];
  for (const [i, c] of v.entries()) {
    const o = c as Record<string, unknown> | null;
    const req = o?.["request"] as Record<string, unknown> | undefined;
    if (
      !o ||
      typeof o["name"] !== "string" ||
      !req ||
      typeof req["enforcement_point"] !== "string" ||
      typeof req["context"] !== "object" ||
      req["context"] === null
    ) {
      return { error: `Case ${i + 1}: needs name, request.enforcement_point and request.context` };
    }
    if (typeof o["expect"] !== "string" || !DECISIONS.has(o["expect"])) {
      return { error: `Case ${i + 1}: expect must be one of ${[...DECISIONS].join(", ")}` };
    }
    cases.push({
      name: o["name"],
      expect: o["expect"] as Decision,
      request: {
        enforcement_point: req["enforcement_point"] as string,
        ...(typeof req["action"] === "string" ? { action: req["action"] } : {}),
        context: req["context"] as Record<string, unknown>,
      },
    });
  }
  return { cases };
}

export async function runCases(
  cases: readonly PolicyCase[],
  run: (req: PolicyCase["request"]) => Promise<GateDecision>,
): Promise<CaseResult[]> {
  const out: CaseResult[] = [];
  for (const c of cases) {
    try {
      const d = await run(c.request);
      out.push({
        name: c.name,
        expected: c.expect,
        actual: d.decision,
        reason: d.reason,
        rules: d.matched_rule_ids ?? [],
        pass: d.decision === c.expect,
      });
    } catch (e) {
      // Fail closed: an evaluation error is never a pass.
      out.push({
        name: c.name,
        expected: c.expect,
        pass: false,
        error: e instanceof Error ? e.message : "evaluation failed",
      });
    }
  }
  return out;
}

export const SAMPLE_CASES = `[
  {
    "name": "read is allowed",
    "request": { "enforcement_point": "tool_call", "action": "kb.search", "context": { "tool": { "name": "kb.search", "side_effects": "read" } } },
    "expect": "ALLOW"
  },
  {
    "name": "external write needs approval",
    "request": { "enforcement_point": "tool_call", "action": "email.send", "context": { "tool": { "name": "email.send", "side_effects": "external" } } },
    "expect": "REQUIRE_APPROVAL"
  }
]`;
