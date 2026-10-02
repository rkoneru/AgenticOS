import { validatePolicy } from "@axis/contracts";
import type { Capability } from "./capabilities.js";

type Rule = Record<string, unknown>;

const POINT: Record<string, string> = {
  function: "tool_call",
  agent: "tool_call",
  mcp: "mcp_call",
  code: "code_exec",
  browser: "browser_exec",
  channel: "message_send",
};

const slug = (s: string): string =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "x";

/**
 * The RECOMMENDED policy pack for an install: it allows exactly what the tenant consented to and DENIES everything else
 * (`defaultDecision: DENY`, plus explicit high-priority denials for the dangerous classes that were not granted). It is a stub
 * (the tenant publishes it through the control plane's policy API; nothing here activates it).
 */
export function recommendedPolicyPack(
  id: { namespace: string; name: string; version: string },
  granted: readonly Capability[],
): Record<string, unknown> {
  const tools = granted
    .filter((c) => c.key.startsWith("tool:"))
    .map((c) => ({
      kind: c.key.split(":")[1] as string,
      name: c.key.split(":").slice(2).join(":"),
    }));
  const has = (key: string): boolean => granted.some((c) => c.key === key);
  const rules: Rule[] = [];
  const seen = new Set<string>();
  for (const t of tools) {
    const rid = `allow-${slug(t.kind)}-${slug(t.name)}`;
    if (seen.has(rid)) continue;
    seen.add(rid);
    rules.push({
      id: rid,
      enforcementPoints: [POINT[t.kind] ?? "tool_call"],
      when: { field: "tool.name", op: "eq", value: t.name },
      decision: "ALLOW",
    });
  }
  rules.push({ id: "allow-model-calls", enforcementPoints: ["model_call"], decision: "ALLOW" });
  const names = tools.map((t) => t.name);
  const toolPoints = ["tool_call", "mcp_call", "code_exec", "browser_exec", "message_send"];
  rules.push(
    names.length
      ? {
          id: "deny-ungranted-tools",
          priority: 900,
          enforcementPoints: toolPoints,
          when: { not: { field: "tool.name", op: "in", value: names } },
          decision: "DENY",
        }
      : {
          id: "deny-ungranted-tools",
          priority: 900,
          enforcementPoints: toolPoints,
          decision: "DENY",
        },
  );
  if (!has("exec:code"))
    rules.push({
      id: "deny-code-exec",
      priority: 950,
      enforcementPoints: ["code_exec"],
      decision: "DENY",
    });
  if (!has("egress:browser"))
    rules.push({
      id: "deny-browser",
      priority: 950,
      enforcementPoints: ["browser_exec"],
      decision: "DENY",
    });
  if (!has("data:phi"))
    rules.push({
      id: "deny-phi",
      priority: 950,
      enforcementPoints: ["model_call", "tool_call", "mcp_call", "memory_write", "message_send"],
      when: { field: "data.phi", op: "eq", value: true },
      decision: "DENY",
    });
  if (!has("memory:long_term"))
    rules.push({
      id: "deny-long-term-memory",
      priority: 950,
      enforcementPoints: ["memory_write"],
      when: { field: "args.scope", op: "eq", value: "long_term" },
      decision: "DENY",
    });
  const pack = {
    apiVersion: "policy.axis.dev/v1",
    kind: "PolicyPack",
    metadata: {
      name: `mp-${slug(id.namespace)}-${slug(id.name)}`.slice(0, 62),
      version: id.version.replace(/[-+].*$/, ""),
      description: `Recommended deny-by-default pack for ${id.namespace}/${id.name}@${id.version}: allows only the capabilities the tenant admin consented to.`,
    },
    spec: { defaultDecision: "DENY", rules },
  };
  if (!validatePolicy(pack))
    throw new Error(
      `generated policy pack is invalid: ${JSON.stringify(validatePolicy.errors?.slice(0, 2))}`,
    );
  return pack;
}
