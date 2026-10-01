import {
  ApprovalError,
  RISK_LEVELS,
  type CreateApprovalInput,
  type EscalationLevel,
} from "./types.js";

/** Structural twin of the Risk Kernel's `ApprovalSpec` (kept structural so this package does not import the kernel). */
export interface ApprovalSpecLike {
  roles: string[];
  sla_seconds: number;
  escalate_to: string[];
  on_timeout: "DENY";
}

export const MAX_LEVELS = 6;
export const MAX_SLA_SECONDS = 30 * 24 * 3600;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TRACE_RE = /^[0-9a-f]{32}$/;
const HASH_RE = /^[0-9a-f]{64}$/;

export const invalid = (msg: string): ApprovalError => new ApprovalError("INVALID", msg);

const nonEmpty = (v: unknown, max = 256): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= max;

const isRoleList = (v: unknown): v is string[] =>
  Array.isArray(v) && v.length > 0 && v.length <= 32 && v.every((r) => nonEmpty(r, 128));

/**
 * Level 1 = spec.roles with spec.sla_seconds; level N+1 = [escalate_to[N-1]] with the same SLA.
 * `on_timeout` must be DENY: there is no configurable "approve on timeout" (fail-closed).
 */
export function chainFromSpec(spec: ApprovalSpecLike): EscalationLevel[] {
  if (typeof spec !== "object" || spec === null) throw invalid("approval spec missing");
  if (spec.on_timeout !== "DENY") throw invalid("on_timeout must be DENY");
  if (!isRoleList(spec.roles)) throw invalid("approval roles must be a non-empty list");
  if (
    !Number.isInteger(spec.sla_seconds) ||
    spec.sla_seconds < 1 ||
    spec.sla_seconds > MAX_SLA_SECONDS
  )
    throw invalid("sla_seconds out of range");
  if (!Array.isArray(spec.escalate_to) || spec.escalate_to.length > MAX_LEVELS - 1)
    throw invalid("escalate_to must be a list of at most 5 roles");
  if (!spec.escalate_to.every((r) => nonEmpty(r, 128)))
    throw invalid("escalate_to has an invalid role");
  const chain: EscalationLevel[] = [
    { level: 1, roles: [...spec.roles], sla_seconds: spec.sla_seconds },
  ];
  spec.escalate_to.forEach((role, i) => {
    chain.push({ level: i + 2, roles: [role], sla_seconds: spec.sla_seconds });
  });
  return chain;
}

export function validateCreate(input: CreateApprovalInput): void {
  if (typeof input !== "object" || input === null) throw invalid("input is not an object");
  if (!UUID_RE.test(String(input.tenant_id))) throw invalid("invalid tenant_id");
  if (!nonEmpty(input.run_id)) throw invalid("invalid run_id");
  if (!TRACE_RE.test(String(input.trace_id))) throw invalid("invalid trace_id");
  if (!nonEmpty(input.tool)) throw invalid("invalid tool");
  if (!HASH_RE.test(String(input.args_hash)))
    throw invalid("args_hash must be a sha-256 hex digest");
  if (!RISK_LEVELS.includes(input.risk_level)) throw invalid("invalid risk_level");
  const a = input.agent;
  if (typeof a !== "object" || a === null || !nonEmpty(a.name) || !nonEmpty(a.version))
    throw invalid("invalid agent");
  const r = input.requester;
  if (
    typeof r !== "object" ||
    r === null ||
    !["human", "agent", "system"].includes(r.type) ||
    !nonEmpty(r.id)
  )
    throw invalid("invalid requester");
  if (r.type === "agent" && !nonEmpty(r.pid)) throw invalid("agent requester needs a pid");
  if (
    input.conflicted !== undefined &&
    !(Array.isArray(input.conflicted) && input.conflicted.every((c) => nonEmpty(c)))
  )
    throw invalid("invalid conflicted list");
  if (input.idempotency_key !== undefined && !nonEmpty(input.idempotency_key))
    throw invalid("invalid idempotency_key");
  if (input.policy_version !== undefined && !nonEmpty(input.policy_version))
    throw invalid("invalid policy_version");
}
