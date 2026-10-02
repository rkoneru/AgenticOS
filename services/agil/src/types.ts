/**
 * AGIL explanation model (docs/spec/agil.md). The structured form is STABLE: `{summary, steps, decision_refs, remediation}`.
 * Everything here is derived from audit rows (and, optionally, run events and tenant-owned policy metadata) by pure functions.
 */

/** Which mechanism produced a decision. Derived from the audit `reason` the kernel/approvals service wrote, never from a model. */
export type GateKind =
  | "kill_switch"
  | "policy_rule"
  | "default_deny"
  | "amount_cap"
  | "target_cap"
  | "budget"
  | "rate_limit"
  | "staleness"
  | "approval"
  | "audit_unavailable"
  | "invalid_request"
  | "evaluation_failure"
  | "admin"
  | "other";

export interface DecisionRef {
  audit_event_id: string;
  seq: number;
  ts: string;
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION";
  enforcement_point: string;
  action: string;
  policy_version: string;
  /** Policy packs named by `policy_version` ("name@version" pairs), in order. */
  policy_packs: string[];
  gate: GateKind;
  /** Rule ids (`<pack>/<rule>`) named by the reason, when it names any. */
  rule_ids: string[];
  /** Gate id (`<pack>/<gate>`) when a gate decided. */
  gate_id?: string;
  /** Kill-switch scope when `gate` is `kill_switch`. */
  kill_switch_scope?: "global" | "tenant" | "agent" | "tool";
  /** Approval request id when the reason names one. */
  approval_id?: string;
  /** The audit reason, sanitised and length-bounded. */
  reason: string;
}

export interface ExplanationStep {
  /** 1-based, in reading order. */
  n: number;
  kind: "request" | "evaluation" | "outcome" | "context" | "run";
  text: string;
  /** Audit event this step is about, when it is about one. */
  audit_event_id?: string;
  seq?: number;
}

export interface Remediation {
  kind:
    | "release_kill_switch"
    | "add_policy_rule"
    | "review_policy_rule"
    | "adjust_request"
    | "raise_limit"
    | "wait"
    | "decide_approval"
    | "retry"
    | "contact_operator"
    | "inspect";
  text: string;
  /** Machine-readable hint (an API call, a rule id); never a secret or another tenant's data. */
  hint?: string;
}

export interface Explanation {
  summary: string;
  steps: ExplanationStep[];
  decision_refs: DecisionRef[];
  remediation: Remediation[];
}

/** Read-only run event projection AGIL may be handed (values, not a handle to the run service). */
export interface RunEventView {
  sequence: number;
  type: string;
  pid: string;
  at: string;
  data?: Record<string, unknown>;
}

/** Tenant-owned policy metadata used only to phrase hints (never to decide anything). */
export interface RuleMetadata {
  id: string;
  decision?: string;
  description?: string;
  approval?: { roles: string[]; slaSeconds?: number };
}

export interface PolicyMetadataSource {
  /** Metadata for the rule ids, scoped to the tenant. Unknown ids are simply absent from the result. */
  describeRules(tenantId: string, ruleIds: readonly string[]): Promise<RuleMetadata[]>;
}

export const EXPLANATION_KEYS = ["summary", "steps", "decision_refs", "remediation"] as const;
