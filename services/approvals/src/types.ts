import type { ApprovalSpecLike } from "./spec.js";

export const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";
export type Outcome = "APPROVED" | "DENIED" | "EXPIRED";

export interface Actor {
  type: "human" | "agent" | "system";
  id: string;
  pid?: string;
}

/** An authenticated approver. Authentication happens upstream (api-gateway); this service trusts the principal. */
export interface Principal {
  tenant_id: string;
  id: string;
  roles: string[];
}

export interface EscalationLevel {
  /** 1-based. Eligible approvers at level N are the union of the roles of levels 1..N. */
  level: number;
  roles: string[];
  sla_seconds: number;
}

export interface ApprovalRequest {
  id: string;
  tenant_id: string;
  run_id: string;
  trace_id: string;
  agent: { name: string; version: string; pid?: string };
  tool: string;
  /** SHA-256 hex of the canonical arguments. The approval is bound to exactly this hash. */
  args_hash: string;
  risk_level: RiskLevel;
  requester: Actor;
  /** Other principals barred from approving (e.g. the agent owner): separation of duties. */
  conflicted: string[];
  policy_version: string;
  chain: EscalationLevel[];
  level: number;
  created_at_ms: number;
  /** Deadline of the CURRENT level. Each level's deadline = previous deadline + its sla_seconds. */
  deadline_ms: number;
  status: ApprovalStatus;
  claimed_by: string | null;
  decided_by: string | null;
  decided_at_ms: number | null;
  decision_level: number | null;
  comment: string | null;
  reason: string | null;
  idempotency_key: string | null;
  /** Audit event of the terminal transition ("" if the append failed on a DENY-direction transition). */
  decision_audit_id: string | null;
  decision_audit_hash: string | null;
  /** Optimistic-concurrency counter, bumped on every write. */
  version: number;
}

export type TerminalStatus = Exclude<ApprovalStatus, "pending">;

export interface CreateApprovalInput {
  tenant_id: string;
  run_id: string;
  trace_id: string;
  agent: { name: string; version: string; pid?: string };
  tool: string;
  args_hash: string;
  risk_level: RiskLevel;
  requester: Actor;
  approval: ApprovalSpecLike;
  policy_version?: string;
  conflicted?: string[];
  idempotency_key?: string;
}

export interface DecisionRecord {
  request_id: string;
  tenant_id: string;
  run_id: string;
  tool: string;
  args_hash: string;
  outcome: Outcome;
  /** ALLOW only for APPROVED; every other outcome is DENY. */
  decision: "ALLOW" | "DENY";
  decided_by: string;
  decided_at: string;
  level: number;
  reason: string;
  audit_event_id: string;
  audit_hash: string;
  key_id: string;
  /** Base64 signature over the canonical JSON of this record without `signature`. */
  signature: string;
}

export type ErrorCode =
  | "INVALID"
  | "NOT_FOUND"
  | "FORBIDDEN_ROLE"
  | "SELF_APPROVAL"
  | "CONFLICT_OF_INTEREST"
  | "CLAIMED_BY_OTHER"
  | "NOT_DECIDED"
  | "ALREADY_DECIDED"
  | "CONFLICT"
  | "AUDIT_FAILED"
  | "SIGNING_FAILED";

export class ApprovalError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ApprovalError";
  }
}

export interface Logger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };
