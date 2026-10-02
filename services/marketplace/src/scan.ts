import { compileAbl, type AblDocument, type Finding as LintFinding } from "@axis/abl";
import {
  capabilitiesOf,
  diffCapabilities,
  type Baseline,
  type Capability,
  type PermissionDiff,
} from "./capabilities.js";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const sevRank = (s: Severity): number => SEVERITIES.indexOf(s);

export interface ScanFinding {
  /** Stable id (`SEC-...`); never reused. */
  id: string;
  severity: Severity;
  path: string;
  message: string;
}

export interface ScanResult {
  findings: ScanFinding[];
  maxSeverity: Severity;
  capabilities: Capability[];
  diff: PermissionDiff;
  lint: { errors: number; warnings: number };
}

const SECRET_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9]{20,}/,
  /\bghp_[A-Za-z0-9]{30,}/,
  /xox[baprs]-[A-Za-z0-9-]{10,}/,
];
const HIDDEN_BEHAVIOUR = [
  /ignore (all )?(previous|prior|above) (instructions|rules)/i,
  /do not (tell|inform|reveal to) the user/i,
  /without (telling|informing) the user/i,
  /exfiltrat/i,
  /disable (the )?(audit|logging|safety|policy)/i,
];
const PRIVATE_HOST =
  /^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|\[?::1\]?$|.*\.internal$|.*\.local$)/i;

/**
 * What a regex must see: the text as a reader or a model would read it. Compatibility forms are folded (NFKC: full-width letters),
 * zero-width and bidi-control characters are removed and every run of whitespace is one space, so "ignore  all\nprevious
 * instructions" and "ig\u200bnore ..." match like the plain phrase.
 */
export function readable(text: string): string {
  return text
    .normalize("NFKC")
    .replace(/[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, "")
    .replace(/\s+/g, " ");
}

function urlFindings(url: string, path: string, what: string): ScanFinding[] {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    /* v8 ignore next 2 -- the ABL schema (format: uri) already rejects most malformed URLs; kept as defence in depth */
    return [{ id: "SEC-NET-001", severity: "high", path, message: `${what} is not a valid URL` }];
  }
  const out: ScanFinding[] = [];
  if (u.protocol !== "https:")
    out.push({ id: "SEC-NET-002", severity: "high", path, message: `${what} does not use https` });
  // An IPv6 literal (`[::1]`, `[fd00::1]`, `[::ffff:7f00:1]`) is a raw address like an IPv4 one; no legitimate publisher needs one.
  if (
    PRIVATE_HOST.test(u.hostname) ||
    /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname) ||
    u.hostname.startsWith("[")
  )
    out.push({
      id: "SEC-NET-003",
      severity: "high",
      path,
      message: `${what} points at a private, loopback or raw-IP host (${u.hostname})`,
    });
  return out;
}

/** Static analysis of what a blueprint ASKS for. Deterministic and side-effect free. Never executes anything. */
export function scanBlueprint(abl: AblDocument, baseline: Baseline): ScanResult {
  const findings: ScanFinding[] = [];
  const f = (id: string, severity: Severity, path: string, message: string): void =>
    void findings.push({ id, severity, path, message });
  const compiled = compileAbl(abl);
  const lintFindings: LintFinding[] = compiled.findings;
  if (!compiled.ok) {
    f("SEC-LINT-000", "critical", "/", "blueprint does not compile (schema or lint errors)");
    return {
      findings,
      maxSeverity: "critical",
      capabilities: [],
      diff: { added: [], removed: [], widening: false },
      lint: { errors: lintFindings.filter((x) => x.severity === "error").length, warnings: 0 },
    };
  }
  const m = compiled.manifest;
  for (const lf of lintFindings)
    f(`SEC-LINT-${lf.code}`, "low", lf.path, `lint warning ${lf.code}: ${lf.message}`);

  (abl.spec.tools ?? []).forEach((t, i) => {
    const path = `/spec/tools/${i}`;
    const effect = t.sideEffects ?? "write";
    if (effect === "external")
      f("SEC-TOOL-001", "high", path, `tool ${t.name} has external side effects`);
    else if (effect === "write") f("SEC-TOOL-002", "medium", path, `tool ${t.name} can write`);
    if (t.kind === "code") f("SEC-EXEC-001", "high", path, `tool ${t.name} executes code`);
    if (t.kind === "browser")
      f("SEC-EGRESS-001", "high", path, `tool ${t.name} drives a browser (arbitrary web egress)`);
    if (t.kind === "mcp") {
      f(
        "SEC-MCP-001",
        "medium",
        path,
        `tool ${t.name} calls MCP server ${t.mcpServer ?? "(unset)"}`,
      );
      if (t.mcpServer)
        for (const x of urlFindings(t.mcpServer, `${path}/mcpServer`, "MCP server"))
          findings.push(x);
    }
    if (t.kind === "channel")
      f("SEC-CHAN-001", "medium", path, `tool ${t.name} sends outbound messages`);
    if (t.kind === "agent")
      f(
        "SEC-AGENT-001",
        "low",
        path,
        `tool ${t.name} delegates to another agent (${t.ref ?? "no ref"})`,
      );
  });
  for (const [i, model] of [m.models.primary, ...m.models.fallbacks].entries())
    if (model.endpoint) {
      f(
        "SEC-EGRESS-002",
        "medium",
        `/spec/model/${i}`,
        `model ${model.model} uses a custom endpoint`,
      );
      for (const x of urlFindings(model.endpoint, `/spec/model/${i}/endpoint`, "model endpoint"))
        findings.push(x);
    }
  if (m.data.phi) {
    f("SEC-DATA-001", "high", "/spec/data/phi", "handles protected health information");
    if (m.memory.long_term)
      f("SEC-DATA-002", "high", "/spec/memory/longTerm", "PHI together with long-term memory");
    if (m.channels.some((c) => ["sms", "email", "whatsapp", "voice"].includes(c)))
      f("SEC-DATA-003", "high", "/spec/channels", "PHI together with an outbound consumer channel");
  }
  if (m.memory.long_term)
    f("SEC-MEM-001", "medium", "/spec/memory/longTerm", "persists long-term memory");
  if (m.memory.knowledge_bases.length)
    f("SEC-MEM-002", "low", "/spec/memory/knowledgeBases", "reads knowledge bases");
  if (m.channels.length)
    f("SEC-CHAN-002", "medium", "/spec/channels", `talks on channels: ${m.channels.join(", ")}`);
  if (m.budgets.cost_usd.hard === null)
    f("SEC-BUDGET-001", "medium", "/spec/budgets/costUsd", "no hard cost budget");
  if (m.budgets.tool_calls.hard === null && m.tools.length)
    f("SEC-BUDGET-002", "low", "/spec/budgets/toolCalls", "no hard tool-call budget");
  if (m.process.max_children > 10)
    f(
      "SEC-PROC-001",
      "medium",
      "/spec/process/maxChildren",
      `can spawn ${m.process.max_children} children`,
    );
  if (m.process.restart_policy === "always")
    f("SEC-PROC-002", "low", "/spec/process/restartPolicy", "restarts forever");
  if (!m.policy_packs.some((p) => p.startsWith("baseline-deny")))
    f("SEC-POLICY-001", "low", "/spec/policy/packs", "does not reference the baseline-deny pack");
  // Every free text the model is shown (system prompt, tool descriptions) or an end user reads (transparency notice, listing metadata).
  const rc = abl.spec.riskClassification as unknown as Record<string, unknown>;
  const texts: { path: string; text: string }[] = [
    { path: "/spec/instructions", text: abl.spec.instructions.system },
    { path: "/metadata/description", text: abl.metadata.description ?? "" },
    ...(abl.metadata.owner ? [{ path: "/metadata/owner", text: String(abl.metadata.owner) }] : []),
    ...Object.entries(abl.metadata.labels ?? {}).map(([k, v]) => ({
      path: `/metadata/labels/${k}`,
      text: `${k} ${String(v)}`,
    })),
    ...["rationale", "intendedPurpose", "transparencyNotice"].flatMap((k) =>
      typeof rc[k] === "string"
        ? [{ path: `/spec/riskClassification/${k}`, text: rc[k] as string }]
        : [],
    ),
    ...(abl.spec.tools ?? []).flatMap((t, i) =>
      t.description ? [{ path: `/spec/tools/${i}/description`, text: t.description }] : [],
    ),
  ].map((x) => ({ ...x, text: readable(x.text) }));
  const secret = texts.find((x) => SECRET_PATTERNS.some((r) => r.test(x.text)));
  if (secret) f("SEC-SECRET-001", "critical", secret.path, "contains what looks like a credential");
  const hidden = texts.find((x) => HIDDEN_BEHAVIOUR.some((r) => r.test(x.text)));
  if (hidden)
    f(
      "SEC-PROMPT-001",
      "high",
      hidden.path,
      "text the model or the user reads contains hidden-behaviour or policy-evasion phrasing",
    );
  if (/https?:\/\//i.test(abl.spec.instructions.system))
    f("SEC-PROMPT-002", "low", "/spec/instructions", "instructions embed a URL");

  const capabilities = capabilitiesOf(m);
  const diff = diffCapabilities(baseline.granted, capabilities);
  const order = (a: ScanFinding, b: ScanFinding): number =>
    sevRank(b.severity) - sevRank(a.severity) || (a.id + a.path < b.id + b.path ? -1 : 1);
  findings.sort(order);
  const max = findings.reduce<Severity>(
    (acc, x) => (sevRank(x.severity) > sevRank(acc) ? x.severity : acc),
    "info",
  );
  return {
    findings,
    maxSeverity: max,
    capabilities,
    diff,
    lint: { errors: 0, warnings: lintFindings.filter((x) => x.severity === "warning").length },
  };
}
