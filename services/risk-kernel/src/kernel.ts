import { randomUUID } from "node:crypto";
import { hashJson, type AuditSink, type UnsealedEvent } from "@axis/contracts";
import {
  MemoryConsumedApprovals,
  type ApprovalRequester,
  type ApprovalVerifier,
  type ConsumedApprovals,
} from "./approvals.js";
import type { PolicyEngine } from "./engine.js";
import { evaluateGate, type GateResult } from "./gates.js";
import type { CounterStore, KillScope, KillSwitchStore } from "./stores.js";
import {
  validatePolicyResult,
  validateRequest,
  type ApprovalSpec,
  type GateRequest,
  type GateResponse,
  type PolicyResult,
} from "./types.js";

export interface Logger {
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export interface KernelDeps {
  engine: PolicyEngine;
  audit: AuditSink;
  killSwitches: KillSwitchStore;
  counters: CounterStore;
  /** Epoch milliseconds. Injectable for tests. */
  clock?: () => number;
  /** Budget for policy evaluation; over-budget or timed-out evaluations are denied. Default 25 ms. */
  policyTimeoutMs?: number;
  logger?: Logger;
  /** Max rejection audit records per tenant per minute; further rejections are counted and logged, not appended. Default 60. */
  rejectionAuditPerMinute?: number;
  /**
   * Opens approval requests for REQUIRE_APPROVAL outcomes. Absent: the outcome carries an empty `approval_id` (clients DENY).
   * A requester that throws, or returns no id, turns the decision into DENY.
   */
  approvalRequester?: ApprovalRequester;
  /**
   * Verifies the signed approval record a client presents (`context.approval`) when it re-submits an approved action.
   * Absent: presented records are ignored and can never authorise anything.
   */
  approvalVerifier?: ApprovalVerifier;
  /** Single-use ledger for verified approvals. Default: in-memory. */
  consumedApprovals?: ConsumedApprovals;
}

/** Hash that cannot throw: an unhashable payload still gets an audit record (with a sentinel hash), never none. */
const safeHash = (v: unknown): string => {
  try {
    return hashJson(v);
  } catch {
    return hashJson({ unhashable: true });
  }
};

const SCOPES: KillScope[] = ["global", "tenant", "agent", "tool"];
const MAX_REASON = 1000;

const silent: Logger = { warn: () => undefined, error: () => undefined };

class Timeout extends Error {}

/**
 * The Risk Kernel: the single fail-closed gate in front of every external action.
 *
 * Order: validate → kill-switches → policy → gates → audit → respond.
 * Any error, timeout, malformed policy output, failed gate or failed audit append yields DENY.
 * `evaluate` never throws.
 */
export class RiskKernel {
  private readonly clock: () => number;
  private readonly timeoutMs: number;
  private readonly log: Logger;
  private readonly rejectionLimit: number;
  private readonly consumed: ConsumedApprovals;
  private readonly rejections = new Map<
    string,
    { windowStart: number; count: number; dropped: number }
  >();

  constructor(private readonly deps: KernelDeps) {
    this.clock = deps.clock ?? Date.now;
    this.timeoutMs = deps.policyTimeoutMs ?? 25;
    this.log = deps.logger ?? silent;
    this.rejectionLimit = deps.rejectionAuditPerMinute ?? 60;
    this.consumed = deps.consumedApprovals ?? new MemoryConsumedApprovals();
  }

  async evaluate(raw: unknown): Promise<GateResponse> {
    try {
      const v = validateRequest(raw);
      if (!v.ok) {
        // No trustworthy tenant, so nothing can be attributed in the audit log; surfaced via the logger.
        this.log.warn("gate request rejected", { reason: v.reason });
        return this.response("DENY", `invalid request: ${v.reason}`, { policy_version: "" });
      }
      return await this.decide(v.value);
    } catch (err) {
      this.log.error("gate internal error", { error: String(err) });
      return this.response("DENY", "internal error", { policy_version: "" });
    }
  }

  private async decide(req: GateRequest): Promise<GateResponse> {
    const reservations: GateResult[] = [];
    const outcome = await this.outcome(req, reservations);
    return this.seal(req, outcome, reservations);
  }

  /** Undo capacity reserved by passing gates (best effort; a failed rollback is logged, never turned into an ALLOW). */
  private async rollback(results: GateResult[]): Promise<void> {
    for (const r of results) {
      try {
        await r.rollback?.();
      } catch (err) {
        this.log.error("gate rollback failed", { error: String(err) });
      }
    }
  }

  private async outcome(
    req: GateRequest,
    reservations: GateResult[],
  ): Promise<Omit<GateResponse, "audit_event_id">> {
    const now = this.clock();

    // 1. kill-switches, before any policy work. Tool-scope switches are checked against BOTH the declared tool name and the
    //    action, so omitting `context.tool.name` cannot sidestep a tool kill-switch.
    try {
      const declared = (req.context["tool"] as { name?: unknown } | undefined)?.name;
      const tools = [...new Set([req.action, ...(typeof declared === "string" ? [declared] : [])])];
      for (const scope of SCOPES) {
        for (const tool of scope === "tool" ? tools : [undefined]) {
          const engaged = await this.deps.killSwitches.isEngaged(scope, {
            tenantId: req.tenant_id,
            agent: req.blueprint.name,
            tool,
          });
          if (engaged) return this.base("DENY", `kill-switch engaged (${scope})`, "");
        }
      }
    } catch (err) {
      this.log.error("kill-switch store error", { error: String(err) });
      return this.base("DENY", "kill-switch state unavailable", "");
    }

    // 2. policy (kernel-owned fields overwrite anything the caller put in the context)
    let policy: PolicyResult;
    try {
      policy = await this.policy(req);
    } catch (err) {
      const reason =
        err instanceof Timeout ? "policy evaluation timed out" : "policy evaluation failed";
      this.log.error(reason, { error: String(err) });
      return this.base("DENY", reason, "");
    }
    const summary = {
      policy_version: policy.policy_version,
      matched_rule_ids: policy.matched,
    };
    if (policy.decision === "DENY") {
      return { ...this.base("DENY", policy.reason, policy.policy_version), ...summary };
    }

    // 3. gates (a failing gate forces DENY, for every non-DENY outcome). Gates that reserve capacity (target_cap) return a
    //    rollback, applied if a later gate fails so a denied request never consumes budget.
    const results: GateResult[] = [];
    for (const g of policy.gates) {
      const r = await evaluateGate(g, {
        now,
        req,
        killSwitches: this.deps.killSwitches,
        counters: this.deps.counters,
      });
      results.push(r);
      if (!r.pass) {
        await this.rollback(results);
        return { ...this.base("DENY", r.reason, policy.policy_version), ...summary };
      }
    }
    reservations.push(...results);

    if (policy.decision === "REQUIRE_APPROVAL" && policy.approval !== null) {
      return await this.approvalOutcome(req, policy, policy.approval, reservations);
    }

    return {
      decision: policy.decision,
      policy_version: policy.policy_version,
      reason: policy.reason,
      matched_rule_ids: policy.matched,
      redact_fields: policy.decision === "ALLOW_WITH_REDACTION" ? policy.redact : [],
      approval: policy.decision === "REQUIRE_APPROVAL" ? policy.approval : null,
      approval_id: "",
    };
  }

  /**
   * REQUIRE_APPROVAL, after kill-switches, DENY policies and every gate have already passed. Two ways forward:
   *  - the caller presents a decision record (`context.approval`): it must verify for exactly this tenant, run, tool and
   *    argument hash and be unused, and then the action is ALLOWED (an approval re-gates, it never bypasses the gate);
   *  - otherwise an approval request is opened through the approvals service and its id returned.
   * Every failure on either path is DENY.
   */
  private async approvalOutcome(
    req: GateRequest,
    policy: PolicyResult,
    spec: ApprovalSpec,
    reservations: GateResult[],
  ): Promise<Omit<GateResponse, "audit_event_id">> {
    const summary = { policy_version: policy.policy_version, matched_rule_ids: policy.matched };
    const deny = (reason: string): Omit<GateResponse, "audit_event_id"> => ({
      ...this.base("DENY", reason, policy.policy_version),
      ...summary,
    });
    const verifier = this.deps.approvalVerifier;
    const requester = this.deps.approvalRequester;
    const presented = req.context["approval"];

    if (presented !== undefined && verifier !== undefined) {
      const runId = (req.context["run"] as { id?: unknown } | undefined)?.id;
      if (typeof runId !== "string" || runId === "") return deny("approval needs context.run.id");
      let requestId = "";
      try {
        const expected = {
          tenant_id: req.tenant_id,
          run_id: runId,
          tool: req.action,
          args_hash: hashJson(req.context["args"] ?? {}),
        };
        if (!(await verifier.verify(presented, expected))) {
          return deny("approval record not valid for this action");
        }
        const rid = (presented as { request_id?: unknown }).request_id;
        if (typeof rid !== "string" || rid === "")
          return deny("approval record not valid for this action");
        requestId = rid;
        if (!(await this.consumed.consume(req.tenant_id, requestId)))
          return deny("approval already used");
      } catch (err) {
        this.log.error("approval verification failed", { error: String(err) });
        return deny("approval verification failed");
      }
      // Undone if the audit append below fails, so a decision that was never recorded does not burn the approval.
      reservations.push({
        pass: true,
        reason: "approval consumed",
        rollback: () => this.consumed.release(req.tenant_id, requestId),
      });
      return {
        decision: "ALLOW",
        policy_version: policy.policy_version,
        reason: `approved: request=${requestId}; ${policy.reason}`.slice(0, MAX_REASON),
        matched_rule_ids: policy.matched,
        redact_fields: [],
        approval: null,
        approval_id: requestId,
      };
    }

    const pending = {
      decision: "REQUIRE_APPROVAL" as const,
      policy_version: policy.policy_version,
      reason: policy.reason,
      matched_rule_ids: policy.matched,
      redact_fields: [],
      approval: spec,
      approval_id: "",
    };
    if (requester === undefined) return pending;
    try {
      const runId = (req.context["run"] as { id?: unknown } | undefined)?.id;
      if (typeof runId !== "string" || runId === "") return deny("approval needs context.run.id");
      const created = await requester.create({
        tenant_id: req.tenant_id,
        run_id: runId,
        trace_id: req.trace_id,
        agent: { name: req.blueprint.name, version: req.blueprint.version },
        tool: req.action,
        args_hash: hashJson(req.context["args"] ?? {}),
        risk_level: "high",
        requester: req.actor,
        approval: spec,
        policy_version: policy.policy_version,
      });
      if (typeof created?.id !== "string" || created.id === "")
        return deny("approval request could not be created");
      return {
        ...pending,
        reason: `${policy.reason}; request=${created.id}`.slice(0, MAX_REASON),
        approval_id: created.id,
      };
    } catch (err) {
      this.log.error("approval request failed", { error: String(err) });
      return deny("approval request could not be created");
    }
  }

  private async policy(req: GateRequest): Promise<PolicyResult> {
    // A presented approval record is evidence for the kernel's own check, never policy input.
    const context = { ...req.context };
    delete context["approval"];
    const input: Record<string, unknown> = {
      ...context,
      enforcement_point: req.enforcement_point,
      tenant: { id: req.tenant_id },
      agent: { name: req.blueprint.name, version: req.blueprint.version },
      actor: { type: req.actor.type, id: req.actor.id },
    };
    const started = performance.now();
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Timeout()), this.timeoutMs);
    });
    let raw: unknown;
    try {
      raw = await Promise.race([this.deps.engine.evaluate(input), timeout]);
    } finally {
      clearTimeout(timer);
    }
    if (performance.now() - started > this.timeoutMs) throw new Timeout();
    const v = validatePolicyResult(raw);
    if (!v.ok) throw new Error(v.reason);
    return v.value;
  }

  private base(
    decision: GateResponse["decision"],
    reason: string,
    policy_version: string,
  ): Omit<GateResponse, "audit_event_id"> {
    return {
      decision,
      policy_version,
      reason: reason.slice(0, MAX_REASON),
      matched_rule_ids: [],
      redact_fields: [],
      approval: null,
      approval_id: "",
    };
  }

  private response(
    decision: GateResponse["decision"],
    reason: string,
    extra: Partial<GateResponse>,
  ): GateResponse {
    return { ...this.base(decision, reason, ""), audit_event_id: "", ...extra };
  }

  /**
   * Records a rejected call (invalid request, tenant/credential mismatch, internal error) in the AUTHENTICATED tenant's
   * chain. The caller must have established `tenantId` from a credential, never from the request. Returns the audit id,
   * or "" if the append failed (logged).
   */
  async auditRejection(tenantId: string, reason: string): Promise<string> {
    // Bound the work an authenticated caller can force on the shared audit path: per-tenant budget per minute, the rest is
    // counted and logged (one line per window) but not appended. Only ever affects the caller's own chain.
    const now = this.clock();
    const w = this.rejections.get(tenantId);
    if (!w || now - w.windowStart >= 60_000) {
      if (w && w.dropped > 0)
        this.log.warn("rejection audits dropped", { tenant_id: tenantId, dropped: w.dropped });
      this.rejections.set(tenantId, { windowStart: now, count: 1, dropped: 0 });
    } else if (w.count >= this.rejectionLimit) {
      w.dropped++;
      return "";
    } else {
      w.count++;
    }
    try {
      const sealed = await this.deps.audit.append({
        schema_version: 1,
        id: randomUUID(),
        tenant_id: tenantId,
        ts: new Date(this.clock()).toISOString(),
        trace_id: randomUUID().replace(/-/g, ""),
        actor: { type: "system", id: "risk-kernel" },
        blueprint: { name: "unknown", version: "0" },
        policy_version: "none",
        enforcement_point: "admin",
        action: "request_rejected",
        decision: "DENY",
        reason: reason.slice(0, MAX_REASON),
        inputs_hash: safeHash({ rejected: true }),
        outputs_hash: safeHash({ decision: "DENY", reason }),
      });
      return sealed.id;
    } catch (err) {
      this.log.error("audit of rejection failed", { error: String(err) });
      return "";
    }
  }

  /** Appends the decision to the audit log BEFORE returning it. A failed append turns the decision into DENY. */
  private async seal(
    req: GateRequest,
    o: Omit<GateResponse, "audit_event_id">,
    reservations: GateResult[],
  ): Promise<GateResponse> {
    // Nothing executes for a REQUIRE_APPROVAL, so capacity reserved by its gates is released; the resumed action is
    // evaluated again (Phase 3 approvals flow) and reserves then.
    if (o.decision === "REQUIRE_APPROVAL") await this.rollback(reservations);
    const event: UnsealedEvent = {
      schema_version: 1,
      id: randomUUID(),
      tenant_id: req.tenant_id,
      ts: new Date(this.clock()).toISOString(),
      trace_id: req.trace_id,
      actor: req.actor,
      blueprint: req.blueprint,
      policy_version: o.policy_version || "none",
      enforcement_point: req.enforcement_point,
      action: req.action,
      decision: o.decision,
      reason: o.reason,
      inputs_hash: safeHash(req.context),
      outputs_hash: safeHash({
        decision: o.decision,
        matched_rule_ids: o.matched_rule_ids,
        redact_fields: o.redact_fields,
        approval: o.approval,
      }),
    };
    try {
      const sealed = await this.deps.audit.append(event);
      return { ...o, audit_event_id: sealed.id };
    } catch (err) {
      this.log.error("audit append failed; denying", { error: String(err) });
      await this.rollback(reservations);
      return { ...this.base("DENY", "audit unavailable", o.policy_version), audit_event_id: "" };
    }
  }
}
