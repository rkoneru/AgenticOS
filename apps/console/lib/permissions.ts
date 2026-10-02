import type { PermissionSet } from "./api";

export interface PermissionDiff {
  added: Array<{ kind: string; value: string }>;
  removed: Array<{ kind: string; value: string }>;
  unchanged: Array<{ kind: string; value: string }>;
  riskRaised: boolean;
  /** True when the user must explicitly consent (anything added, or a first install). */
  needsConsent: boolean;
}

const RISK = { minimal: 0, limited: 1, high: 2 } as const;
const kinds: Array<[keyof Omit<PermissionSet, "max_risk_level">, string]> = [
  ["tools", "Tool"],
  ["data_classes", "Data class"],
  ["egress_hosts", "Network egress"],
];

export function diffPermissions(
  requested: PermissionSet,
  installed?: PermissionSet | null,
): PermissionDiff {
  const added: PermissionDiff["added"] = [];
  const removed: PermissionDiff["removed"] = [];
  const unchanged: PermissionDiff["unchanged"] = [];
  for (const [key, kind] of kinds) {
    const want = new Set(requested[key]);
    const have = new Set(installed ? installed[key] : []);
    for (const v of want) (have.has(v) ? unchanged : added).push({ kind, value: v });
    for (const v of have) if (!want.has(v)) removed.push({ kind, value: v });
  }
  const riskRaised = !installed || RISK[requested.max_risk_level] > RISK[installed.max_risk_level];
  return {
    added,
    removed,
    unchanged,
    riskRaised,
    needsConsent: !installed || added.length > 0 || riskRaised,
  };
}
