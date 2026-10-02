import { canonicalJson, compileAbl, type AblDocument, type RuntimeManifest } from "@axis/abl";
import { createHash } from "node:crypto";
import { RegistryError } from "@axis/registry";

/**
 * A capability is something the blueprint asks the platform to let it do. `level` orders capabilities of the same key by breadth
 * (a side-effect rank, a budget cap): a higher level is a WIDER permission. Booleans have level 1.
 */
export interface Capability {
  key: string;
  level: number;
}

export const UNBOUNDED = 1e15;
export const EFFECT_RANK: Readonly<Record<string, number>> = {
  none: 1,
  read: 2,
  write: 3,
  external: 4,
};

export interface Baseline {
  granted: Capability[];
}
/** What a tenant has pre-approved for every blueprint until it says otherwise: working memory only. */
export const DEFAULT_BASELINE: Baseline = { granted: [{ key: "memory:run", level: 1 }] };

const host = (url: string): string => {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};

/** Pure: the capability set a blueprint requests (from the compiled manifest, so defaults are applied). Sorted by key. */
export function capabilitiesOf(m: RuntimeManifest): Capability[] {
  const out = new Map<string, number>();
  const add = (key: string, level = 1): void => {
    out.set(key, Math.max(out.get(key) ?? 0, level));
  };
  for (const model of [m.models.primary, ...m.models.fallbacks]) {
    add(`model:${model.provider}`);
    if (model.endpoint) add(`egress:endpoint:${host(model.endpoint)}`);
  }
  for (const t of m.tools) {
    add(`tool:${t.kind}:${t.name}`, EFFECT_RANK[t.side_effects] ?? EFFECT_RANK["external"]!);
    if (t.kind === "mcp" && t.mcp_server) add(`mcp:${t.mcp_server}`);
    if (t.kind === "code") add("exec:code");
    if (t.kind === "browser") add("egress:browser");
  }
  if (m.memory.run) add("memory:run");
  if (m.memory.session) add("memory:session");
  if (m.memory.long_term) add("memory:long_term");
  for (const kb of m.memory.knowledge_bases) add(`memory:kb:${kb}`);
  if (m.data.phi) add("data:phi");
  for (const c of m.channels) add(`channel:${c}`);
  for (const [name, b] of Object.entries(m.budgets)) add(`budget:${name}`, b.hard ?? UNBOUNDED);
  add("process:max_children", m.process.max_children + 1);
  if (m.process.restart_policy === "always") add("process:restart_always");
  return [...out.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([key, level]) => ({ key, level }));
}

export function capabilitiesOfAbl(abl: unknown): {
  capabilities: Capability[];
  manifest: RuntimeManifest;
} {
  const c = compileAbl(abl);
  if (!c.ok) throw new RegistryError("invalid", "blueprint does not compile");
  return { capabilities: capabilitiesOf(c.manifest), manifest: c.manifest };
}

export interface DiffEntry {
  key: string;
  /** `new`: not granted before. `raised`: granted at a lower level. */
  change: "new" | "raised";
  level: number;
  previousLevel: number | null;
}

export interface PermissionDiff {
  added: DiffEntry[];
  /** Capabilities that were granted and are no longer requested, or requested at a lower level. */
  removed: { key: string; level: number; newLevel: number | null }[];
  /** True when the request goes beyond what was granted: consent is REQUIRED. */
  widening: boolean;
}

/** requested vs granted. Pure and total: anything not granted at (at least) the requested level is an addition. */
export function diffCapabilities(
  granted: readonly Capability[],
  requested: readonly Capability[],
): PermissionDiff {
  const g = new Map(granted.map((c) => [c.key, c.level]));
  const r = new Map(requested.map((c) => [c.key, c.level]));
  const added: DiffEntry[] = [];
  for (const [key, level] of r) {
    const prev = g.get(key);
    if (prev === undefined) added.push({ key, change: "new", level, previousLevel: null });
    else if (level > prev) added.push({ key, change: "raised", level, previousLevel: prev });
  }
  const removed: PermissionDiff["removed"] = [];
  for (const [key, level] of g) {
    const now = r.get(key);
    if (now === undefined) removed.push({ key, level, newLevel: null });
    else if (now < level) removed.push({ key, level, newLevel: now });
  }
  const byKey = (a: { key: string }, b: { key: string }): number => (a.key < b.key ? -1 : 1);
  return { added: added.sort(byKey), removed: removed.sort(byKey), widening: added.length > 0 };
}

/**
 * What the admin consents to: binds the exact blueprint (name, version, content hash) AND the exact set of additions. If the blueprint
 * or the tenant's baseline changes between preview and install, the digest differs and the install is refused (TOCTOU defence).
 */
export function consentDigest(
  id: { namespace: string; name: string; version: string; contentHash: string },
  diff: PermissionDiff,
): string {
  return createHash("sha256")
    .update(canonicalJson({ ...id, added: diff.added }), "utf8")
    .digest("hex");
}

export const isCapability = (v: unknown): v is Capability =>
  typeof v === "object" &&
  v !== null &&
  typeof (v as Capability).key === "string" &&
  Number.isFinite((v as Capability).level);

export type { AblDocument };
