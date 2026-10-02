import type { AuditReader } from "@axis/audit";
import type { AuditEvent } from "@axis/contracts";
import { classifyReason, type ReasonClass } from "./classify.js";
import { sanitizeText } from "./sanitize.js";
import type {
  DecisionRef,
  Explanation,
  ExplanationStep,
  PolicyMetadataSource,
  Remediation,
  RuleMetadata,
  RunEventView,
} from "./types.js";

export const MAX_TRACE_EVENTS = 2000;
const MAX_STEPS = 60;

export interface ExplainerOptions {
  /** The ONLY window onto the system: a read-only audit view (`createAuditReader`). No gate, kernel or store handle exists here. */
  audit: AuditReader;
  /** Optional, read-only, tenant-scoped rule metadata for phrasing hints. */
  policies?: PolicyMetadataSource;
}

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

function packsOf(policyVersion: string): string[] {
  return policyVersion === "none" || policyVersion === ""
    ? []
    : policyVersion.split(",").filter((p) => p.length > 0);
}

function toRef(e: AuditEvent, c: ReasonClass): DecisionRef {
  return {
    audit_event_id: e.id,
    seq: e.seq,
    ts: e.ts,
    decision: e.decision,
    enforcement_point: e.enforcement_point,
    action: e.action,
    policy_version: e.policy_version,
    policy_packs: packsOf(e.policy_version),
    gate: c.gate,
    rule_ids: c.ruleIds,
    ...(c.gateId ? { gate_id: c.gateId } : {}),
    ...(c.killSwitchScope ? { kill_switch_scope: c.killSwitchScope } : {}),
    ...(c.approvalId ? { approval_id: c.approvalId } : {}),
    reason: sanitizeText(e.reason ?? ""),
  };
}

const classOf = (e: AuditEvent): ReasonClass =>
  classifyReason(e.reason, e.action, e.enforcement_point);

/** Why the gate said what it said, in one sentence. Pure function of the classification. */
export function describeGate(
  c: ReasonClass,
  e: Pick<AuditEvent, "decision" | "action" | "enforcement_point">,
): string {
  switch (c.gate) {
    case "kill_switch":
      return `a ${c.killSwitchScope ?? "kill"}-scope kill-switch was engaged${c.gateId ? ` (gate ${c.gateId})` : ""}`;
    case "default_deny":
      return "no policy rule matched, so the default decision (DENY) applied";
    case "policy_rule":
      return e.decision === "ALLOW" || e.decision === "ALLOW_WITH_REDACTION"
        ? `policy rule ${c.ruleIds.join(", ")} allowed it${e.decision === "ALLOW_WITH_REDACTION" ? " with redaction" : ""}`
        : e.decision === "REQUIRE_APPROVAL"
          ? `policy rule ${c.ruleIds.join(", ")} requires a human approval`
          : `policy rule ${c.ruleIds.join(", ")} denied it`;
    case "amount_cap":
      return `gate ${c.gateId} blocked it: ${c.field ?? "the amount"} exceeds the cap of ${c.limit}`;
    case "target_cap":
      return `gate ${c.gateId} blocked it: the cumulative daily cap of ${c.limit} for this target would be exceeded`;
    case "budget":
      return `gate ${c.gateId} blocked it: the hard ${c.metric ?? "budget"} limit was reached`;
    case "rate_limit":
      return `gate ${c.gateId} blocked it: the rate limit of ${c.limit} per ${c.detail ?? "window"} was exceeded`;
    case "staleness":
      return `gate ${c.gateId} blocked it: ${c.field ?? "a timestamp"} ${c.limit !== undefined ? `is older than ${c.limit} seconds` : (c.detail ?? "is not acceptable")}`;
    case "approval":
      return e.decision === "ALLOW"
        ? "a human approval was granted"
        : e.decision === "REQUIRE_APPROVAL"
          ? `an approval request was opened${c.approvalId ? ` (${c.approvalId})` : ""}`
          : "the approval was denied, expired or could not be verified";
    case "audit_unavailable":
      return "the audit log could not record the decision, so it was denied (fail-closed)";
    case "invalid_request":
      return `the gate rejected the request as malformed${c.detail ? ` (${sanitizeText(c.detail, 120)})` : ""}`;
    case "evaluation_failure":
      return `the gate could not evaluate the request (${c.detail ?? "error"}), so it was denied (fail-closed)`;
    case "admin":
      return "an administrative action recorded in the audit log";
    default:
      return c.detail
        ? `the gate reported: ${sanitizeText(c.detail, 120)}`
        : "no further detail was recorded";
  }
}

async function ruleNotes(
  src: PolicyMetadataSource | undefined,
  tenantId: string,
  ruleIds: readonly string[],
): Promise<Map<string, RuleMetadata>> {
  const out = new Map<string, RuleMetadata>();
  if (!src || ruleIds.length === 0) return out;
  try {
    for (const r of await src.describeRules(tenantId, [...new Set(ruleIds)].slice(0, 20)))
      if (ruleIds.includes(r.id)) out.set(r.id, r);
  } catch {
    // Metadata only phrases hints; its absence never changes an explanation's facts.
  }
  return out;
}

/** What would let the action through. Hints are derived from the audit reason and tenant-owned policy metadata only. */
export function remediationFor(
  c: ReasonClass,
  ref: DecisionRef,
  notes: ReadonlyMap<string, RuleMetadata>,
): Remediation[] {
  const out: Remediation[] = [];
  const allowed = ref.decision === "ALLOW" || ref.decision === "ALLOW_WITH_REDACTION";
  if (allowed) return out;
  const test = {
    kind: "inspect" as const,
    text: "Check a candidate change without running anything.",
    hint: "POST /v1/policies:test",
  };
  switch (c.gate) {
    case "kill_switch":
      out.push({
        kind: "release_kill_switch",
        text: `Release the ${c.killSwitchScope ?? ""} kill-switch if the stop is no longer intended (needs a role allowed to manage kill-switches).`.replace(
          "  ",
          " ",
        ),
        hint: "PUT /v1/kill-switches {engaged:false}",
      });
      break;
    case "default_deny":
      out.push({
        kind: "add_policy_rule",
        text: `Publish and activate a policy rule that allows "${ref.action}" at the ${ref.enforcement_point} enforcement point for this agent; until one matches, the answer stays DENY.`,
        hint: "POST /v1/policies",
      });
      out.push(test);
      break;
    case "policy_rule":
      for (const id of c.ruleIds) {
        const n = notes.get(id);
        out.push({
          kind: ref.decision === "REQUIRE_APPROVAL" ? "decide_approval" : "review_policy_rule",
          text:
            ref.decision === "REQUIRE_APPROVAL"
              ? `Rule ${id} requires approval${n?.approval ? ` by ${n.approval.roles.join(" or ")}` : ""}.`
              : `Review rule ${id}${n?.description ? ` ("${sanitizeText(n.description, 120)}")` : ""}: change the request so its conditions no longer match, or publish a policy version that adjusts it.`,
          hint: id,
        });
      }
      break;
    case "amount_cap":
      out.push({
        kind: "adjust_request",
        text: `Send ${c.field ?? "an amount"} at or below ${c.limit}, or raise the cap in gate ${c.gateId} through a new policy version.`,
        ...(c.gateId ? { hint: c.gateId } : {}),
      });
      break;
    case "target_cap":
      out.push({
        kind: "wait",
        text: `The cumulative cap of ${c.limit} resets at 00:00 UTC; wait for the next day or raise the cap in gate ${c.gateId}.`,
        ...(c.gateId ? { hint: c.gateId } : {}),
      });
      break;
    case "budget":
      out.push({
        kind: "raise_limit",
        text: `Raise the ${c.metric ?? "budget"} limit (tenant budgets or the gate's hard value) or wait for the budget window to roll over.`,
        ...(c.gateId ? { hint: c.gateId } : {}),
      });
      break;
    case "rate_limit":
      out.push({
        kind: "wait",
        text: `Retry after the ${c.detail ?? "window"} has passed, or raise the limit in gate ${c.gateId}.`,
        ...(c.gateId ? { hint: c.gateId } : {}),
      });
      break;
    case "staleness":
      out.push({
        kind: "adjust_request",
        text: `Supply a fresh ${c.field ?? "timestamp"} (within the gate's age limit).`,
        ...(c.gateId ? { hint: c.gateId } : {}),
      });
      break;
    case "approval":
      if (ref.decision === "REQUIRE_APPROVAL")
        out.push({
          kind: "decide_approval",
          text: "An approver with an eligible role decides the request; the action is then re-evaluated and, if approved, proceeds.",
          hint: ref.approval_id
            ? `POST /v1/approvals/${ref.approval_id}/decision`
            : "POST /v1/approvals/{id}/decision",
        });
      else
        out.push({
          kind: "retry",
          text: "Ask for a new approval: a denied, expired or consumed approval cannot be reused.",
        });
      break;
    case "audit_unavailable":
    case "evaluation_failure":
      out.push({
        kind: "retry",
        text: "Retry; the denial was fail-closed because a dependency was unavailable, not because a rule matched.",
      });
      out.push({
        kind: "contact_operator",
        text: "If it persists, ask the platform operator to check the audit log and policy service health.",
      });
      break;
    case "invalid_request":
      out.push({
        kind: "adjust_request",
        text: "Correct the request to match the action's schema.",
      });
      break;
    default:
      out.push({
        kind: "inspect",
        text: "Inspect the audit event and the active policy packs for the matching rule.",
      });
  }
  return out;
}

const verb = (d: DecisionRef["decision"]): string =>
  d === "ALLOW"
    ? "allowed"
    : d === "DENY"
      ? "denied"
      : d === "REQUIRE_APPROVAL"
        ? "sent for approval"
        : "allowed with redaction";

/**
 * AGIL: read-only explainer. It is never on the decision path (invariant 2): it receives an `AuditReader` only, so it cannot call
 * a gate, change a policy or write an event; its output is a pure function of the audit rows (and optional run events / metadata)
 * it was given, with no model call, clock or randomness.
 */
export class Explainer {
  constructor(private readonly o: ExplainerOptions) {}

  /** Explain one audit event (a denial, an approval step or any decision) in the context of its trace. */
  async explainEvent(tenantId: string, seq: number): Promise<Explanation | undefined> {
    if (!Number.isSafeInteger(seq) || seq < 1) return undefined;
    const rows = await this.o.audit.listEvents(tenantId, { fromSeq: seq, limit: 1 });
    const e = rows.find((r) => r.seq === seq && r.tenant_id === tenantId);
    if (!e) return undefined;
    const c = classOf(e);
    const ref = toRef(e, c);
    const notes = await ruleNotes(this.o.policies, tenantId, c.ruleIds);
    const trace = (await this.trace(tenantId, e.trace_id)).filter((r) => r.seq < e.seq);
    const earlier = trace.length;
    const steps: ExplanationStep[] = [
      {
        n: 1,
        kind: "request",
        text: `${e.actor.type} ${e.actor.id} (blueprint ${e.blueprint.name}@${e.blueprint.version}) asked to perform "${e.action}" at the ${e.enforcement_point} enforcement point.`,
        audit_event_id: e.id,
        seq: e.seq,
      },
      {
        n: 2,
        kind: "evaluation",
        text: ref.policy_packs.length
          ? `It was evaluated against policy ${ref.policy_packs.join(", ")}: ${describeGate(c, e)}.`
          : `No policy version is recorded for this event: ${describeGate(c, e)}.`,
        audit_event_id: e.id,
        seq: e.seq,
      },
      {
        n: 3,
        kind: "outcome",
        text: `Decision: ${e.decision} (recorded at ${e.ts} as audit event #${e.seq}).`,
        audit_event_id: e.id,
        seq: e.seq,
      },
    ];
    if (earlier > 0)
      steps.push({
        n: 4,
        kind: "context",
        text: `${plural(earlier, "earlier event")} on the same trace led up to this; ${summariseCounts(trace)}.`,
      });
    return {
      summary: `The ${e.enforcement_point} action "${e.action}" was ${verb(e.decision)}: ${describeGate(c, e)}.`,
      steps,
      decision_refs: [ref],
      remediation: remediationFor(c, ref, notes),
    };
  }

  /**
   * Explain a run from its trace: every gated decision, the denials and approvals in detail, and (when handed the run's own events)
   * how it ended. `runEvents` are plain values; AGIL has no way to call back into the run service.
   */
  async explainRun(
    tenantId: string,
    q: { traceId: string; runEvents?: readonly RunEventView[] },
  ): Promise<Explanation> {
    const events = await this.trace(tenantId, q.traceId);
    const refs = events.map((e) => toRef(e, classOf(e)));
    const classes = events.map(classOf);
    const gated = events.filter((e) => e.enforcement_point !== "admin");
    const denies = refs.filter((r) => r.decision === "DENY" && r.gate !== "admin");
    const needApproval = refs.filter((r) => r.decision === "REQUIRE_APPROVAL");
    const exit = runExit(q.runEvents);

    const notes = await ruleNotes(
      this.o.policies,
      tenantId,
      refs.flatMap((r) => r.rule_ids),
    );
    const steps: ExplanationStep[] = [];
    const push = (kind: ExplanationStep["kind"], text: string, e?: AuditEvent): void => {
      if (steps.length < MAX_STEPS)
        steps.push({
          n: steps.length + 1,
          kind,
          text,
          ...(e ? { audit_event_id: e.id, seq: e.seq } : {}),
        });
    };
    if (events.length === 0) {
      push("run", "No audit events were recorded for this run's trace.");
    } else {
      const first = events[0] as AuditEvent;
      push(
        "run",
        `The run executed blueprint ${first.blueprint.name}@${first.blueprint.version}; ${plural(gated.length, "action")} passed through the policy gate.`,
        first,
      );
      events.forEach((e, i) => {
        const c = classes[i] as ReasonClass;
        if (e.decision === "ALLOW" && c.gate !== "approval" && e.enforcement_point !== "admin")
          return;
        push(
          e.decision === "ALLOW" ? "outcome" : "evaluation",
          `#${e.seq} "${e.action}" (${e.enforcement_point}) was ${verb(e.decision)}: ${describeGate(c, e)}.`,
          e,
        );
      });
    }
    if (exit) push("run", exit.text);

    const remediation: Remediation[] = [];
    const seen = new Set<string>();
    for (const r of [...denies, ...needApproval]) {
      const rem = remediationFor(
        classOf(events.find((e) => e.id === r.audit_event_id) as AuditEvent),
        r,
        notes,
      );
      for (const m of rem) {
        const k = `${m.kind}|${m.text}`;
        if (!seen.has(k)) {
          seen.add(k);
          remediation.push(m);
        }
      }
    }
    return {
      summary: runSummary(events.length, gated.length, refs, denies, needApproval, exit?.summary),
      steps,
      decision_refs: refs.filter((r) => r.decision !== "ALLOW" || r.gate === "approval"),
      remediation: remediation.slice(0, 20),
    };
  }

  private async trace(tenantId: string, traceId: string): Promise<AuditEvent[]> {
    if (!/^[0-9a-f]{32}$/.test(traceId)) return [];
    const rows = await this.o.audit.listEvents(tenantId, { traceId, limit: MAX_TRACE_EVENTS });
    // Defence in depth: a reader that returned another tenant's row would be a bug; never explain it.
    return rows.filter((r) => r.tenant_id === tenantId).sort((a, b) => a.seq - b.seq);
  }
}

function summariseCounts(events: readonly AuditEvent[]): string {
  const n = (d: string): number => events.filter((e) => e.decision === d).length;
  return `${n("ALLOW") + n("ALLOW_WITH_REDACTION")} allowed, ${n("REQUIRE_APPROVAL")} sent for approval, ${n("DENY")} denied`;
}

function runSummary(
  total: number,
  gated: number,
  refs: readonly DecisionRef[],
  denies: readonly DecisionRef[],
  approvals: readonly DecisionRef[],
  exit: string | undefined,
): string {
  if (total === 0)
    return "No audit events were recorded for this run, so there is nothing to explain yet.";
  const allowed = refs.filter(
    (r) => r.decision === "ALLOW" || r.decision === "ALLOW_WITH_REDACTION",
  ).length;
  const parts = [
    `${plural(gated, "gated action")}: ${allowed} allowed, ${approvals.length} sent for approval, ${denies.length} denied.`,
  ];
  const d = denies[0];
  if (d)
    parts.push(
      `First denial: "${d.action}" at ${d.enforcement_point} (#${d.seq}), ${describeGateFromRef(d)}.`,
    );
  if (exit) parts.push(exit);
  return parts.join(" ");
}

const describeGateFromRef = (r: DecisionRef): string =>
  describeGate(
    {
      gate: r.gate,
      ruleIds: r.rule_ids,
      ...(r.gate_id ? { gateId: r.gate_id } : {}),
      ...(r.kill_switch_scope ? { killSwitchScope: r.kill_switch_scope } : {}),
      ...(r.approval_id ? { approvalId: r.approval_id } : {}),
      ...reasonParams(r),
    },
    r,
  );

function reasonParams(r: DecisionRef): Partial<ReasonClass> {
  const c = classifyReason(r.reason, r.action, r.enforcement_point);
  const out: Partial<ReasonClass> = {};
  if (c.field !== undefined) out.field = c.field;
  if (c.limit !== undefined) out.limit = c.limit;
  if (c.metric !== undefined) out.metric = c.metric;
  if (c.detail !== undefined) out.detail = c.detail;
  return out;
}

function runExit(
  events: readonly RunEventView[] | undefined,
): { text: string; summary: string } | undefined {
  if (!events || events.length === 0) return undefined;
  const sorted = [...events].sort((a, b) => a.sequence - b.sequence);
  const ended = sorted.filter(
    (e) => e.type === "process_transition" && e.data?.["to"] === "terminated",
  );
  const root = ended[ended.length - 1];
  const warnings = sorted.filter((e) => e.type === "budget_warning").length;
  const blocked = sorted.filter((e) => e.type === "action_blocked").length;
  const bits: string[] = [];
  if (root)
    bits.push(
      `The run ended with exit reason "${String(root.data?.["exit_reason"] ?? "unknown")}".`,
    );
  else bits.push("The run had not finished when it was read.");
  if (blocked > 0)
    bits.push(`${plural(blocked, "action")} did not run because the gate stopped them.`);
  if (warnings > 0) bits.push(`${plural(warnings, "budget warning")} were raised.`);
  const text = bits.join(" ");
  return { text, summary: text };
}
