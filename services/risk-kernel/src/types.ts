export const DECISIONS = ["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"] as const;
export type DecisionName = (typeof DECISIONS)[number];

export const ENFORCEMENT_POINTS = [
  "tool_call",
  "mcp_call",
  "model_call",
  "memory_write",
  "message_send",
  "code_exec",
  "browser_exec",
] as const;
export type EnforcementPoint = (typeof ENFORCEMENT_POINTS)[number];

export interface GateRequest {
  tenant_id: string;
  trace_id: string;
  actor: { type: "human" | "agent" | "system"; id: string; pid?: string };
  blueprint: { name: string; version: string };
  enforcement_point: EnforcementPoint;
  action: string;
  /** tool.{name,kind,side_effects}, args.*, data.phi, run.id ... (docs/plans/phase-2.md). Untrusted. */
  context: Record<string, unknown>;
}

export interface ApprovalSpec {
  roles: string[];
  sla_seconds: number;
  escalate_to: string[];
  on_timeout: "DENY";
}

export interface GateResponse {
  decision: DecisionName;
  policy_version: string;
  reason: string;
  matched_rule_ids: string[];
  redact_fields: string[];
  approval: ApprovalSpec | null;
  /** Assigned by the approvals service (Phase 3); empty until then. */
  approval_id: string;
  /** Empty only when the request was too malformed to audit (no trustworthy tenant). */
  audit_event_id: string;
}

export interface PolicyGate {
  id: string;
  type: string;
  scope?: string;
  params: Record<string, unknown>;
}

/** Validated result of the compiled policy (see @axis/policy resolution). */
export interface PolicyResult {
  decision: DecisionName;
  reason: string;
  matched: string[];
  winners: string[];
  gates: PolicyGate[];
  redact: string[];
  approval: ApprovalSpec | null;
  policy_version: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TRACE_RE = /^[0-9a-f]{32}$/;
const PID_RE = /^axp_[0-9A-HJKMNP-TV-Z]{26}$/;

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const nonEmpty = (v: unknown, max = 256): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= max;

const MAX_DEPTH = 32;
const MAX_NODES = 10_000;

/**
 * The context is untrusted and is hashed, forwarded to the policy engine and audited. Reject anything that cannot be
 * canonically hashed or could exhaust the kernel: non-finite numbers, undefined/functions/bigint/symbols, cycles,
 * excessive depth or size. Iterative, so a hostile 5000-level structure cannot overflow the stack.
 */
export function contextProblem(root: unknown): string | undefined {
  const stack: { v: unknown; d: number }[] = [{ v: root, d: 0 }];
  const seen = new Set<object>();
  let nodes = 0;
  while (stack.length > 0) {
    const { v, d } = stack.pop() as { v: unknown; d: number };
    if (++nodes > MAX_NODES) return "context too large";
    if (d > MAX_DEPTH) return "context too deeply nested";
    if (v === null || typeof v === "string" || typeof v === "boolean") continue;
    if (typeof v === "number") {
      if (!Number.isFinite(v)) return "context contains a non-finite number";
      continue;
    }
    if (typeof v !== "object") return `context contains an unsupported ${typeof v}`;
    if (seen.has(v)) return "context contains a cycle or shared reference";
    seen.add(v);
    for (const child of Array.isArray(v) ? v : Object.values(v)) stack.push({ v: child, d: d + 1 });
  }
  return undefined;
}

export type Validated<T> = { ok: true; value: T } | { ok: false; reason: string };

/** Strict request validation. Anything unexpected is rejected (the kernel then answers DENY). */
export function validateRequest(raw: unknown): Validated<GateRequest> {
  if (!isObj(raw)) return { ok: false, reason: "request is not an object" };
  const { tenant_id, trace_id, actor, blueprint, enforcement_point, action, context } = raw;
  if (typeof tenant_id !== "string" || !UUID_RE.test(tenant_id))
    return { ok: false, reason: "invalid tenant_id" };
  if (typeof trace_id !== "string" || !TRACE_RE.test(trace_id))
    return { ok: false, reason: "invalid trace_id" };
  if (
    !isObj(actor) ||
    !["human", "agent", "system"].includes(actor["type"] as string) ||
    !nonEmpty(actor["id"])
  ) {
    return { ok: false, reason: "invalid actor" };
  }
  const pid = actor["pid"];
  if (actor["type"] === "agent" && (typeof pid !== "string" || !PID_RE.test(pid))) {
    return { ok: false, reason: "agent actor requires a valid pid" };
  }
  if (pid !== undefined && (typeof pid !== "string" || !PID_RE.test(pid)))
    return { ok: false, reason: "invalid actor pid" };
  if (!isObj(blueprint) || !nonEmpty(blueprint["name"]) || !nonEmpty(blueprint["version"])) {
    return { ok: false, reason: "invalid blueprint" };
  }
  if (!(ENFORCEMENT_POINTS as readonly unknown[]).includes(enforcement_point)) {
    return { ok: false, reason: "invalid enforcement_point" };
  }
  if (!nonEmpty(action)) return { ok: false, reason: "invalid action" };
  if (!isObj(context)) return { ok: false, reason: "invalid context" };
  const bad = contextProblem(context);
  if (bad) return { ok: false, reason: bad };
  return {
    ok: true,
    value: {
      tenant_id,
      trace_id,
      actor: {
        type: actor["type"] as GateRequest["actor"]["type"],
        id: actor["id"] as string,
        ...(typeof pid === "string" ? { pid } : {}),
      },
      blueprint: { name: blueprint["name"], version: blueprint["version"] },
      enforcement_point: enforcement_point as EnforcementPoint,
      action,
      context,
    },
  };
}

function strings(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

/** Validates the raw object returned by a policy engine. Unknown shapes are rejected, never coerced to ALLOW. */
export function validatePolicyResult(raw: unknown): Validated<PolicyResult> {
  if (!isObj(raw)) return { ok: false, reason: "policy result is not an object" };
  const { decision, reason, matched, winners, gates, redact, approval, policy_version } = raw;
  if (!(DECISIONS as readonly unknown[]).includes(decision))
    return { ok: false, reason: "unknown decision from policy" };
  if (typeof reason !== "string" || typeof policy_version !== "string")
    return { ok: false, reason: "malformed policy result" };
  if (!strings(matched) || !strings(winners) || !strings(redact))
    return { ok: false, reason: "malformed policy result lists" };
  if (!Array.isArray(gates)) return { ok: false, reason: "malformed policy gates" };
  const outGates: PolicyGate[] = [];
  for (const g of gates) {
    if (
      !isObj(g) ||
      typeof g["id"] !== "string" ||
      typeof g["type"] !== "string" ||
      !isObj(g["params"])
    ) {
      return { ok: false, reason: "malformed gate definition" };
    }
    outGates.push({
      id: g["id"],
      type: g["type"],
      params: g["params"],
      ...(typeof g["scope"] === "string" ? { scope: g["scope"] } : {}),
    });
  }
  let appr: ApprovalSpec | null = null;
  if (approval !== null) {
    if (
      !isObj(approval) ||
      !strings(approval["roles"]) ||
      typeof approval["sla_seconds"] !== "number" ||
      !strings(approval["escalate_to"])
    ) {
      return { ok: false, reason: "malformed approval spec" };
    }
    appr = {
      roles: approval["roles"],
      sla_seconds: approval["sla_seconds"],
      escalate_to: approval["escalate_to"],
      on_timeout: "DENY",
    };
  }
  if (decision === "REQUIRE_APPROVAL" && appr === null)
    return { ok: false, reason: "REQUIRE_APPROVAL without approval spec" };
  if (decision === "ALLOW_WITH_REDACTION" && redact.length === 0)
    return { ok: false, reason: "ALLOW_WITH_REDACTION without fields" };
  return {
    ok: true,
    value: {
      decision: decision as DecisionName,
      reason,
      matched,
      winners,
      gates: outGates,
      redact,
      approval: appr,
      policy_version,
    },
  };
}
