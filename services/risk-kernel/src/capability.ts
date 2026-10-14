import { readFileSync, statSync } from "node:fs";

/**
 * Capability classification of a tool call (ADR 0110, NEEDS 399).
 *
 * The side-effects label a blueprint declares for its own tools is attacker-influenced input (supply chain). The platform baseline
 * ALLOWs "read" tools, so the kernel must not hand that rule the blueprint's label as it stands. The effective label the policy sees is
 *
 *   1. the TENANT's tool catalog entry for the tool name, when the tenant has registered one (authoritative in both directions), else
 *   2. the strictest of the declared label and what the kernel infers from the tool NAME, KIND and ARGUMENT KEYS.
 *
 * An unknown or malformed declared label counts as `external`. The declared label stays visible to policy as
 * `tool.declared_side_effects`. The inference is deliberately conservative (it only ever raises the label) and is a net, not proof:
 * the tenant catalog is the robust control, the classifier covers tools nobody registered.
 */
export const SIDE_EFFECT_LEVELS = ["none", "read", "write", "external"] as const;
export type SideEffect = (typeof SIDE_EFFECT_LEVELS)[number];
const rank = (s: SideEffect): number => SIDE_EFFECT_LEVELS.indexOf(s);
const strictest = (a: SideEffect, b: SideEffect): SideEffect => (rank(a) >= rank(b) ? a : b);
export const isSideEffect = (v: unknown): v is SideEffect =>
  typeof v === "string" && (SIDE_EFFECT_LEVELS as readonly string[]).includes(v);

/** A tenant's pre-registered, approved side-effect classes per tool name. May throw: the kernel then denies. */
export interface ToolCatalog {
  get(tenantId: string, toolName: string): SideEffect | undefined | Promise<SideEffect | undefined>;
}

export class StaticToolCatalog implements ToolCatalog {
  constructor(
    private readonly byTenant: Readonly<Record<string, Readonly<Record<string, SideEffect>>>>,
  ) {}
  get(tenantId: string, toolName: string): SideEffect | undefined {
    const t = Object.hasOwn(this.byTenant, tenantId) ? this.byTenant[tenantId] : undefined;
    return t && Object.hasOwn(t, toolName) ? t[toolName] : undefined;
  }
}

/** The same catalog read from a JSON file `{tenant: {tool: effect}}` on every change (mtime). A missing or malformed file THROWS: deny. */
export class FileToolCatalog implements ToolCatalog {
  private cached: { mtimeMs: number; size: number; inner: StaticToolCatalog } | undefined;
  constructor(private readonly path: string) {}
  get(tenantId: string, toolName: string): SideEffect | undefined {
    const st = statSync(this.path);
    if (!this.cached || this.cached.mtimeMs !== st.mtimeMs || this.cached.size !== st.size) {
      const raw = JSON.parse(readFileSync(this.path, "utf8")) as Record<
        string,
        Record<string, unknown>
      >;
      for (const t of Object.values(raw))
        for (const v of Object.values(t))
          if (!isSideEffect(v)) throw new Error("tool catalog: bad side-effect value");
      this.cached = {
        mtimeMs: st.mtimeMs,
        size: st.size,
        inner: new StaticToolCatalog(raw as never),
      };
    }
    return this.cached.inner.get(tenantId, toolName);
  }
}

const EXTERNAL_WORDS = new Set([
  "send",
  "post",
  "email",
  "mail",
  "sms",
  "message",
  "msg",
  "publish",
  "notify",
  "tweet",
  "dm",
  "http",
  "https",
  "request",
  "curl",
  "webhook",
  "exec",
  "execute",
  "run",
  "shell",
  "bash",
  "sh",
  "cmd",
  "command",
  "eval",
  "spawn",
  "invoke",
  "call",
  "wire",
  "pay",
  "payment",
  "transfer",
  "payout",
  "refund",
  "charge",
  "deploy",
  "delegate",
  "forward",
  "reply",
  "share",
  "export",
  "sync",
  "push",
  "grant",
  "revoke",
  "approve",
  "sudo",
  "download",
]);
const WRITE_WORDS = new Set([
  "write",
  "create",
  "update",
  "delete",
  "remove",
  "set",
  "put",
  "patch",
  "insert",
  "save",
  "store",
  "upload",
  "drop",
  "purge",
  "edit",
  "modify",
  "rename",
  "move",
  "append",
  "add",
  "remember",
  "erase",
  "clear",
  "reset",
  "truncate",
  "commit",
  "merge",
  "close",
  "cancel",
]);
const EXTERNAL_ARG_KEYS = new Set([
  "to",
  "cc",
  "bcc",
  "recipient",
  "recipients",
  "destination",
  "dest",
  "webhook",
  "webhook_url",
  "callback",
  "callback_url",
  "url",
  "uri",
  "endpoint",
  "href",
  "host",
  "command",
  "cmd",
  "script",
  "shell",
  "argv",
  "phone",
  "email_to",
]);
// Kinds whose very nature is an effect outside the process. `mcp` is NOT here (ADR 0110, revision 2): an MCP tool is judged by its
// name and arguments like a function tool, because a blanket floor denied every legitimate read-only lookup; the tenant catalog is
// the control for MCP servers whose tool names say nothing. `agent` is handled separately (a spawn: the child's own actions are gated).
const EXTERNAL_KINDS = new Set(["code", "browser", "channel", "voice"]);

/**
 * Verbs that clearly READ. When one LEADS the tool name (`get-message`, `listRequests`, `lookup-payment-status`), the remaining words
 * are its object: the nouns below (`message`, `request`, `email`, `http`, ...) are not read as the verbs they can also be. A
 * connector word (`get-and-send`, `list-then-reply`) switches the carve-out off, and real verbs (`send`, `post`, `delete`, ...)
 * keep their meaning wherever they stand.
 */
const READ_VERBS = new Set([
  "get",
  "list",
  "lookup",
  "read",
  "search",
  "find",
  "query",
  "describe",
  "show",
  "view",
  "count",
  "check",
  "recall",
  "inspect",
  "browse",
]);
const OBJECT_NOUNS = new Set([
  "email",
  "mail",
  "sms",
  "message",
  "msg",
  "request",
  "http",
  "https",
  "webhook",
  "command",
  "cmd",
  "shell",
  "bash",
  "sh",
  "payment",
  "export",
  "reply",
  "share",
  "call",
  "sync",
  "store",
  "commit",
  "merge",
  "close",
  "cancel",
]);
const CONNECTORS = new Set([
  "and",
  "then",
  "to",
  "via",
  "with",
  "after",
  "before",
  "plus",
  "into",
  "on",
]);

/** Words of a tool name: split on non-alphanumerics and camelCase / digit boundaries, lower-cased. */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

export function inferSideEffects(
  name: string,
  kind: string | undefined,
  args: Readonly<Record<string, unknown>> | undefined,
): SideEffect {
  // A child-agent spawn: the name is the parent's delegation handle (`delegate-a`), and what the child may do is decided by the
  // child's own gated actions. The runtime executes kind `agent` as a spawn and nothing else, so claiming the kind buys no capability.
  if (kind === "agent") return "none";
  let level: SideEffect = "none";
  if (kind !== undefined && EXTERNAL_KINDS.has(kind.split(":")[0] ?? kind)) level = "external";
  if (kind?.startsWith("memory:") && kind !== "memory:read") level = strictest(level, "write");
  const words = nameWords(name);
  // `server/tool` of an MCP call: the leading read verb is the tool's, not the server's.
  const verbFirst = nameWords(name.includes("/") ? name.slice(name.lastIndexOf("/") + 1) : name)[0];
  const readLeads =
    verbFirst !== undefined && READ_VERBS.has(verbFirst) && !words.some((w) => CONNECTORS.has(w));
  for (const w of words) {
    if (readLeads && OBJECT_NOUNS.has(w)) continue;
    if (EXTERNAL_WORDS.has(w)) level = strictest(level, "external");
    else if (WRITE_WORDS.has(w)) level = strictest(level, "write");
  }
  if (args && typeof args === "object") {
    const keys = Object.keys(args).map((k) => k.toLowerCase());
    if (keys.some((k) => EXTERNAL_ARG_KEYS.has(k))) level = strictest(level, "external");
    else if (
      keys.some((k) => ["content", "body", "data", "text", "payload"].includes(k)) &&
      keys.some((k) => ["path", "file", "filename", "key", "id"].includes(k))
    )
      level = strictest(level, "write");
  }
  return level;
}

export interface Effective {
  effective: SideEffect;
  declared: string | null;
  source: "catalog" | "declared" | "inferred";
}

export function effectiveSideEffects(
  tool: { name?: unknown; kind?: unknown; side_effects?: unknown },
  args: Readonly<Record<string, unknown>> | undefined,
  catalogued: SideEffect | undefined,
): Effective {
  const declared = typeof tool.side_effects === "string" ? tool.side_effects : null;
  if (catalogued !== undefined) return { effective: catalogued, declared, source: "catalog" };
  const claimed: SideEffect = isSideEffect(declared) ? declared : "external";
  const inferred = inferSideEffects(
    typeof tool.name === "string" ? tool.name : "",
    typeof tool.kind === "string" ? tool.kind : undefined,
    args,
  );
  const effective = strictest(claimed, inferred);
  return {
    effective,
    declared,
    source: effective === claimed && claimed === declared ? "declared" : "inferred",
  };
}
