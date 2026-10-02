import type { GateKind } from "./types.js";

export interface ReasonClass {
  gate: GateKind;
  ruleIds: string[];
  gateId?: string;
  killSwitchScope?: "global" | "tenant" | "agent" | "tool";
  approvalId?: string;
  /** Short parameters pulled from the reason: field, limit, window. All come from the kernel's PHI-safe reason text. */
  field?: string;
  limit?: number;
  metric?: string;
  detail?: string;
}

const ID = "[A-Za-z0-9][A-Za-z0-9_.-]*";
const NS_ID = `${ID}/${ID}`;
const RULE_LIST = new RegExp(`^${NS_ID}(?:, ${NS_ID})*$`);
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const APPROVAL = new RegExp(`(?:^|; |: )request=(${UUID})`);
const APPROVED = new RegExp(`^approved: request=${UUID}; (.*)$`);
const SCOPES = new Set(["global", "tenant", "agent", "tool"]);

const ruleList = (t: string): string[] => (RULE_LIST.test(t) ? t.split(", ") : []);

/** Splits `<pack>/<name>` ids and returns the pack. */
export const packOf = (id: string): string => id.slice(0, Math.max(0, id.indexOf("/")));

/**
 * Maps an audit `reason` (written by the Risk Kernel, the gates or the approvals service) to the mechanism behind it. The reason
 * formats are produced by `services/risk-kernel/src/{kernel,gates}.ts` and `services/approvals/src/service.ts`; anything this
 * function does not recognise is `other` (reported honestly, never guessed).
 */
export function classifyReason(
  reason: string | undefined,
  action: string,
  enforcementPoint: string,
): ReasonClass {
  const text = (reason ?? "").trim();
  const approvalId = APPROVAL.exec(text)?.[1];
  const base: Pick<ReasonClass, "approvalId"> = approvalId ? { approvalId } : {};

  if (enforcementPoint === "admin" && action.startsWith("approval."))
    return { gate: "approval", ruleIds: [], ...base };
  if (enforcementPoint === "admin") return { gate: "admin", ruleIds: [], ...base };

  let m = /^kill-switch engaged \((\w+)\)$/.exec(text);
  if (m && SCOPES.has(m[1] as string))
    return { gate: "kill_switch", ruleIds: [], killSwitchScope: m[1] as "global", ...base };

  m = new RegExp(`^gate (${NS_ID}): (.*)$`).exec(text);
  if (m) {
    const gateId = m[1] as string;
    const why = m[2] as string;
    const common = { ruleIds: [] as string[], gateId, ...base };
    const ks = /^kill-switch engaged \((\w+)\)$/.exec(why);
    if (ks && SCOPES.has(ks[1] as string))
      return { gate: "kill_switch", killSwitchScope: ks[1] as "global", ...common };
    let g = /^(\S+) exceeds cap (\S+)$/.exec(why);
    if (g) return { gate: "amount_cap", field: g[1] as string, limit: Number(g[2]), ...common };
    g = /^cumulative cap (\S+) would be exceeded$/.exec(why);
    if (g) return { gate: "target_cap", limit: Number(g[1]), ...common };
    g = /^hard (\S+) budget reached$/.exec(why);
    if (g) return { gate: "budget", metric: g[1] as string, ...common };
    g = /^run\.id missing for run-scoped budget$/.exec(why);
    if (g) return { gate: "budget", detail: "run id missing", ...common };
    g = /^rate limit (\d+)\/(\d+)s exceeded$/.exec(why);
    if (g) return { gate: "rate_limit", limit: Number(g[1]), detail: `${g[2]}s window`, ...common };
    g = /^(\S+) older than (\d+)s$/.exec(why);
    if (g) return { gate: "staleness", field: g[1] as string, limit: Number(g[2]), ...common };
    if (/^(\S+) (missing or not a timestamp|is in the future)$/.test(why))
      return { gate: "staleness", detail: why, ...common };
    if (/^ok/.test(why)) return { gate: "other", detail: why, ...common };
    return { gate: "other", detail: why, ...common };
  }

  if (text === "no matching rule (default deny)")
    return { gate: "default_deny", ruleIds: [], ...base };
  if (text === "audit unavailable") return { gate: "audit_unavailable", ruleIds: [], ...base };
  if (/^invalid request: /.test(text))
    return { gate: "invalid_request", ruleIds: [], detail: text.slice(17), ...base };
  if (
    text === "internal error" ||
    text === "policy evaluation timed out" ||
    text === "policy evaluation failed" ||
    text === "kill-switch state unavailable" ||
    /^no policy|no bundle|policy bundle/i.test(text)
  )
    return { gate: "evaluation_failure", ruleIds: [], detail: text, ...base };
  const ap = APPROVED.exec(text);
  if (ap) return { gate: "approval", ruleIds: ruleList(ap[1] as string), ...base };
  const head = text.split(";")[0] ?? "";
  if (approvalId !== undefined || /^approval /.test(text))
    return { gate: "approval", ruleIds: ruleList(head), ...base };

  if (RULE_LIST.test(head)) return { gate: "policy_rule", ruleIds: head.split(", "), ...base };
  return { gate: "other", ruleIds: [], detail: text, ...base };
}
