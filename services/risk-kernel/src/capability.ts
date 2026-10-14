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
  "dispatch",
  "trigger",
  "submit",
  "broadcast",
  "text",
  "whatsapp",
  "slack",
  "telegram",
  "discord",
  "twilio",
  "smtp",
  "sendgrid",
  "ssh",
  "scp",
  "sftp",
  "ftp",
  "netcat",
  "nc",
  "kill",
  "terminate",
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
  "destroy",
  "wipe",
  "replace",
  "overwrite",
  "upsert",
  "mutate",
  "persist",
  "flush",
  "rm",
  "mv",
  "chmod",
  "chown",
  "unlink",
  "revert",
  "rollback",
  "restore",
  "enable",
  "disable",
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

/** Every name longer than this is classified `external`: a megabyte-long name buys nothing legitimate and is only a way to burn time. */
export const MAX_NAME_LENGTH = 256;
/** Arguments are scanned to this depth and key count (a bound, then `external`: an argument tree that deep is not a lookup). */
const MAX_ARG_DEPTH = 6;
const MAX_ARG_KEYS = 512;

/**
 * Words of a tool name: split on non-alphanumerics and camelCase / digit boundaries, lower-cased. Compatibility forms are folded
 * (NFKC, so full-width letters become ASCII) and zero-width / combining characters are dropped so `se\u200bnd` reads as `send`.
 */
export function nameWords(name: string): string[] {
  return foldName(name)
    .replace(/([a-z])([0-9])/gi, "$1 $2")
    .replace(/([0-9])([a-z])/gi, "$1 $2")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function foldName(name: string): string {
  return name
    .normalize("NFKC")
    .normalize("NFD")
    .replace(/[\p{M}\p{Cf}]/gu, "")
    .normalize("NFC");
}

/** Letters that survive folding yet are not ASCII (Cyrillic `\u0435` in `s\u0435nd`, Greek, ...): a homoglyph net, see inferSideEffects. */
const hasNonAsciiWord = (name: string): boolean => /[^\x00-\x7f]/u.test(foldName(name));

// Verbs unambiguous enough to be recognised INSIDE a glued word (`sendemail`, `deleterecord`). Deliberately not `post`, `run`, `set`,
// `put`, `add`, `drop`, ...: those are inside too many ordinary words (`postgres`, `runtime`, `setting`).
const GLUED_EXTERNAL = [
  "send",
  "publish",
  "notify",
  "webhook",
  "execute",
  "transfer",
  "payout",
  "refund",
  "deploy",
  "forward",
  "approve",
  "revoke",
  "download",
  "email",
  "dispatch",
  "broadcast",
  "terminate",
];
const GLUED_WRITE = [
  "write",
  "create",
  "update",
  "delete",
  "remove",
  "insert",
  "upload",
  "purge",
  "modify",
  "rename",
  "append",
  "erase",
  "truncate",
  "destroy",
  "overwrite",
  "replace",
  "upsert",
  "persist",
];
const INFLECTED = /^(?:d|ed|s|es|ing|er|ers|ion|ions|or|ors|able)?$/;

function gluedLevel(token: string, skipNouns: boolean): SideEffect {
  for (const [list, lvl] of [
    [GLUED_EXTERNAL, "external"],
    [GLUED_WRITE, "write"],
  ] as const)
    for (const kw of list) {
      const i = token.indexOf(kw);
      if (i < 0) continue;
      // A read-led name keeps its object nouns (`get-email`, `list-messages`) and its past participles (`get-updated-items`).
      if (skipNouns && OBJECT_NOUNS.has(kw)) continue;
      if (skipNouns && i === 0 && INFLECTED.test(token.slice(kw.length))) continue;
      return lvl;
    }
  return "none";
}

const EXTERNAL_ARG_WORDS = new Set([
  "url",
  "uri",
  "webhook",
  "recipient",
  "recipients",
  "cc",
  "bcc",
  "destination",
  "endpoint",
  "href",
  "command",
  "cmd",
  "script",
  "shell",
  "argv",
  "phone",
  "callback",
]);

/** Walks an argument tree: every key, however deep, and the sets of key words it saw. */
function argKeys(args: unknown): { keys: string[]; truncated: boolean } {
  const keys: string[] = [];
  let truncated = false;
  const walk = (v: unknown, depth: number): void => {
    if (typeof v !== "object" || v === null) return;
    if (depth > MAX_ARG_DEPTH) {
      truncated = true;
      return;
    }
    const entries = Array.isArray(v) ? v.map((x, i) => [String(i), x] as const) : Object.entries(v);
    for (const [k, x] of entries) {
      if (keys.length >= MAX_ARG_KEYS) {
        truncated = true;
        return;
      }
      if (!Array.isArray(v)) keys.push(k);
      walk(x, depth + 1);
    }
  };
  walk(args, 0);
  return { keys, truncated };
}

function inferOne(name: string, kind: string | undefined): SideEffect {
  if (name.length > MAX_NAME_LENGTH || hasNonAsciiWord(name)) return "external";
  let level: SideEffect = "none";
  const words = nameWords(name);
  // `server/tool` of an MCP call: the leading read verb is the tool's, not the server's.
  const verbFirst = nameWords(name.includes("/") ? name.slice(name.lastIndexOf("/") + 1) : name)[0];
  // `getanddelete`: a glued read verb leads only when what follows it is not a connector.
  const gluedRead =
    verbFirst === undefined
      ? undefined
      : [...READ_VERBS].find(
          (v) =>
            verbFirst.startsWith(v) &&
            verbFirst.length > v.length &&
            ![...CONNECTORS].some((c) => verbFirst.slice(v.length).startsWith(c)),
        );
  const readLeads =
    verbFirst !== undefined &&
    (READ_VERBS.has(verbFirst) || gluedRead !== undefined) &&
    !words.some((w) => CONNECTORS.has(w));
  for (const w of words) {
    if (readLeads && OBJECT_NOUNS.has(w)) continue;
    if (EXTERNAL_WORDS.has(w)) level = strictest(level, "external");
    else if (WRITE_WORDS.has(w)) level = strictest(level, "write");
    else level = strictest(level, gluedLevel(w, readLeads));
  }
  if (kind !== undefined && EXTERNAL_KINDS.has(kind.split(":")[0] ?? kind)) level = "external";
  return level;
}

export function inferSideEffects(
  name: string | readonly string[],
  kind: string | undefined,
  args: Readonly<Record<string, unknown>> | undefined,
): SideEffect {
  // A child-agent spawn: the name is the parent's delegation handle (`delegate-a`), and what the child may do is decided by the
  // child's own gated actions. The runtime executes kind `agent` as a spawn and nothing else, so claiming the kind buys no capability.
  if (kind === "agent") return "none";
  let level: SideEffect = "none";
  if (kind?.startsWith("memory:") && kind !== "memory:read") level = strictest(level, "write");
  // Every name the call is known by: the agent-facing name, the action and the executed `ref` (ADR 0114).
  for (const n of Array.isArray(name) ? name : [name as string])
    level = strictest(level, inferOne(n, kind));
  if (args && typeof args === "object") {
    const { keys, truncated } = argKeys(args);
    if (truncated) level = strictest(level, "external");
    const lower = keys.map((k) => k.toLowerCase());
    const wordSets = keys.map((k) => nameWords(k));
    if (
      lower.some((k) => EXTERNAL_ARG_KEYS.has(k)) ||
      wordSets.some((ws) => ws.some((w) => EXTERNAL_ARG_WORDS.has(w)))
    )
      level = strictest(level, "external");
    else if (
      wordSets.some((ws) =>
        ws.some((w) => ["content", "body", "data", "text", "payload"].includes(w)),
      ) &&
      wordSets.some((ws) => ws.some((w) => ["path", "file", "filename", "key", "id"].includes(w)))
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
  tool: { name?: unknown; kind?: unknown; side_effects?: unknown; ref?: unknown },
  args: Readonly<Record<string, unknown>> | undefined,
  catalogued: SideEffect | undefined,
  alsoNamed: readonly string[] = [],
): Effective {
  const declared = typeof tool.side_effects === "string" ? tool.side_effects : null;
  if (catalogued !== undefined) return { effective: catalogued, declared, source: "catalog" };
  const claimed: SideEffect = isSideEffect(declared) ? declared : "external";
  const inferred = inferSideEffects(
    [
      typeof tool.name === "string" ? tool.name : "",
      ...(typeof tool.ref === "string" ? [tool.ref] : []),
      ...alsoNamed,
    ],
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
