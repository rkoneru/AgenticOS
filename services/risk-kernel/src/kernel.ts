import { randomUUID } from "node:crypto";
import { hashJson, type AuditSink, type UnsealedEvent } from "@axis/contracts";
import type { PolicyEngine } from "./engine.js";
import { evaluateGate, type GateResult } from "./gates.js";
import type { CounterStore, KillScope, KillSwitchStore } from "./stores.js";
import {
  validatePolicyResult,
  validateRequest,
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
}

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

  constructor(private readonly deps: KernelDeps) {
    this.clock = deps.clock ?? Date.now;
    this.timeoutMs = deps.policyTimeoutMs ?? 25;
    this.log = deps.logger ?? silent;
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
    const outcome = await this.outcome(req);
    return this.seal(req, outcome);
  }

  private async outcome(req: GateRequest): Promise<Omit<GateResponse, "audit_event_id">> {
    const now = this.clock();

    // 1. kill-switches, before any policy work
    try {
      const tool = (req.context["tool"] as { name?: unknown } | undefined)?.name;
      for (const scope of SCOPES) {
        const engaged = await this.deps.killSwitches.isEngaged(scope, {
          tenantId: req.tenant_id,
          agent: req.blueprint.name,
          tool: typeof tool === "string" ? tool : undefined,
        });
        if (engaged) return this.base("DENY", `kill-switch engaged (${scope})`, "");
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

    // 3. gates (a failing gate forces DENY, for every non-DENY outcome)
    const results: GateResult[] = [];
    for (const g of policy.gates)
      results.push(
        await evaluateGate(g, {
          now,
          req,
          killSwitches: this.deps.killSwitches,
          counters: this.deps.counters,
        }),
      );
    const failed = results.find((r) => !r.pass);
    if (failed) return { ...this.base("DENY", failed.reason, policy.policy_version), ...summary };
    try {
      for (const r of results) await r.commit?.();
    } catch (err) {
      this.log.error("gate commit failed", { error: String(err) });
      return { ...this.base("DENY", "gate state unavailable", policy.policy_version), ...summary };
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

  private async policy(req: GateRequest): Promise<PolicyResult> {
    const input: Record<string, unknown> = {
      ...req.context,
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

  /** Appends the decision to the audit log BEFORE returning it. A failed append turns the decision into DENY. */
  private async seal(
    req: GateRequest,
    o: Omit<GateResponse, "audit_event_id">,
  ): Promise<GateResponse> {
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
      inputs_hash: hashJson(req.context),
      outputs_hash: hashJson({
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
      return { ...this.base("DENY", "audit unavailable", o.policy_version), audit_event_id: "" };
    }
  }
}
