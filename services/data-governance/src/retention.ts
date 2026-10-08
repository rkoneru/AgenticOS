import { randomUUID } from "node:crypto";
import type { GovernanceAudit } from "./audit.js";
import { requireOfficer } from "./authz.js";
import { classWideHold, subjectScopedHolds } from "./holds.js";
import type { HoldRegistry } from "./registry.js";
import type { GovernanceStore } from "./store.js";
import {
  DATA_CLASSES,
  GovernanceError,
  isDataClass,
  type DataClass,
  type Identifier,
  type Principal,
  type SubjectDataProvider,
} from "./types.js";

const DAY_MS = 86_400_000;

export interface ClassBounds {
  defaultDays: number;
  minDays: number;
  maxDays: number;
  /** false: the purge job NEVER deletes this class (append-only chain). */
  purgeable: boolean;
  basis: string;
}
/**
 * Configurable defaults and bounds per class, NOT legal advice (docs/spec/data-governance.md). `minDays` is a floor a tenant cannot
 * go below: billing records and audit are kept at least as long as typical tax / security-record rules require.
 */
export const CLASS_BOUNDS: Readonly<Record<DataClass, ClassBounds>> = {
  conversation: {
    defaultDays: 30,
    minDays: 1,
    maxDays: 3650,
    purgeable: true,
    basis: "purpose limitation; tenant setting",
  },
  memory: {
    defaultDays: 365,
    minDays: 1,
    maxDays: 3650,
    purgeable: true,
    basis: "purpose limitation; tenant setting",
  },
  run_logs: {
    defaultDays: 365,
    minDays: 30,
    maxDays: 3650,
    purgeable: true,
    basis: "operational debugging; replay window",
  },
  transcripts: {
    defaultDays: 30,
    minDays: 1,
    maxDays: 3650,
    purgeable: true,
    basis: "purpose limitation; tenant setting",
  },
  eval_data: {
    defaultDays: 730,
    minDays: 30,
    maxDays: 3650,
    purgeable: true,
    basis: "evaluation reproducibility",
  },
  telemetry: {
    defaultDays: 30,
    minDays: 1,
    maxDays: 400,
    purgeable: true,
    basis: "operational telemetry",
  },
  billing: {
    defaultDays: 2555,
    minDays: 2190,
    maxDays: 3650,
    purgeable: true,
    basis: "tax/accounting records (typically 6-10 years; tenant jurisdiction decides)",
  },
  audit: {
    defaultDays: 2555,
    minDays: 365,
    maxDays: 3650,
    purgeable: false,
    basis: "security accountability; hash chain is append-only (ADR-0080)",
  },
};
/** PHI-mode tenants: HIPAA documentation retention floor (6 years) for the audit class. */
export const PHI_AUDIT_MIN_DAYS = 2190;

export interface TenantRetentionSettings {
  retentionAuditDays: number;
  retentionTranscriptDays: number;
  retentionMemoryDays: number;
  phiMode?: boolean;
}
/** Read port onto the control plane's tenant settings (services/control-plane `tenant_settings` + `tenants.phi_mode`). */
export interface RetentionSettingsPort {
  get(tenantId: string): Promise<TenantRetentionSettings | undefined>;
}

export interface ResolvedRetention {
  dataClass: DataClass;
  requestedDays: number;
  effectiveDays: number;
  clamped: "min" | "max" | null;
  source: "control_plane" | "governance" | "default";
}

export function boundsFor(cls: DataClass, phi: boolean): { min: number; max: number } {
  const b = CLASS_BOUNDS[cls];
  return {
    min: cls === "audit" && phi ? Math.max(b.minDays, PHI_AUDIT_MIN_DAYS) : b.minDays,
    max: b.maxDays,
  };
}

/** The decision: clamp the requested period into [min, max]. A request below the floor is raised, never honoured. */
export function effectiveRetention(
  cls: DataClass,
  requestedDays: number,
  phi: boolean,
): { days: number; clamped: "min" | "max" | null } {
  const { min, max } = boundsFor(cls, phi);
  if (!Number.isInteger(requestedDays) || requestedDays < 1) return { days: min, clamped: "min" };
  if (requestedDays < min) return { days: min, clamped: "min" };
  if (requestedDays > max) return { days: max, clamped: "max" };
  return { days: requestedDays, clamped: null };
}

export interface ClassReport {
  dataClass: DataClass;
  status:
    | "purged"
    | "dry_run"
    | "skipped_hold"
    | "retained_by_policy"
    | "no_store"
    | "error"
    | "settings_unavailable";
  requestedDays: number;
  effectiveDays: number;
  clamped: "min" | "max" | null;
  cutoff: string | null;
  matched: number;
  purged: number;
  protectedByHold: number;
  holdId?: string;
  error?: string;
}
export interface RetentionReport {
  runId: string;
  tenantId: string;
  dryRun: boolean;
  startedAt: string;
  classes: ClassReport[];
}

export interface RetentionDeps {
  store: GovernanceStore;
  providers: readonly SubjectDataProvider[];
  settings: RetentionSettingsPort;
  holds: HoldRegistry;
  audit: GovernanceAudit;
  now?: () => Date;
}

export class RetentionEngine {
  private readonly now: () => Date;
  constructor(private readonly d: RetentionDeps) {
    this.now = d.now ?? (() => new Date());
  }

  async resolve(tenantId: string): Promise<ResolvedRetention[] | undefined> {
    let s: TenantRetentionSettings | undefined;
    try {
      s = await this.d.settings.get(tenantId);
    } catch {
      return undefined;
    }
    if (!s) return undefined;
    const overrides = await this.d.store.getPolicies(tenantId);
    const phi = s.phiMode === true;
    return DATA_CLASSES.map((cls) => {
      let requested: number = CLASS_BOUNDS[cls].defaultDays;
      let source: ResolvedRetention["source"] = "default";
      if (cls === "audit") [requested, source] = [s.retentionAuditDays, "control_plane"];
      else if (cls === "conversation" || cls === "transcripts")
        [requested, source] = [s.retentionTranscriptDays, "control_plane"];
      else if (cls === "memory") [requested, source] = [s.retentionMemoryDays, "control_plane"];
      const o = overrides[cls];
      if (o !== undefined && source !== "control_plane") [requested, source] = [o, "governance"];
      const e = effectiveRetention(cls, requested, phi);
      return {
        dataClass: cls,
        requestedDays: requested,
        effectiveDays: e.days,
        clamped: e.clamped,
        source,
      };
    });
  }

  /** Governance-owned classes (run_logs, eval_data, telemetry, billing) are set here; the others live in the control plane. */
  async setPolicy(p: Principal, cls: DataClass, days: number): Promise<void> {
    requireOfficer(p, p.tenantId);
    if (!isDataClass(cls)) throw new GovernanceError("invalid", "unknown data class");
    if (["audit", "conversation", "transcripts", "memory"].includes(cls))
      throw new GovernanceError("invalid", `${cls} retention is a control-plane tenant setting`);
    const b = CLASS_BOUNDS[cls];
    if (!Number.isInteger(days) || days < b.minDays || days > b.maxDays)
      throw new GovernanceError(
        "invalid",
        `${cls} retention must be ${b.minDays}..${b.maxDays} days`,
      );
    await this.d.audit.emit({
      tenantId: p.tenantId,
      action: "retention.policy.set",
      actorId: p.id,
      input: { class: cls, days },
    });
    await this.d.store.setPolicy(p.tenantId, cls, days, p.id, this.now());
  }

  async run(
    p: Principal,
    opts: { dryRun?: boolean; classes?: readonly DataClass[] } = {},
  ): Promise<RetentionReport> {
    const t = p.tenantId;
    requireOfficer(p, t);
    const dryRun = opts.dryRun ?? false;
    const runId = randomUUID();
    const startedAt = this.now();
    const resolved = await this.resolve(t);
    const classes = (opts.classes ?? DATA_CLASSES).filter(isDataClass);
    const report: RetentionReport = {
      runId,
      tenantId: t,
      dryRun,
      startedAt: startedAt.toISOString(),
      classes: [],
    };
    await this.d.store.insertRun({
      tenantId: t,
      id: runId,
      dryRun,
      startedAt,
      finishedAt: null,
      report: {},
    });
    const holds = await this.d.store.listHolds(t, true);
    const groups = await this.d.holds.activeGroups(t, holds);

    for (const cls of classes) {
      const r = resolved?.find((x) => x.dataClass === cls);
      const base: ClassReport = {
        dataClass: cls,
        status: "settings_unavailable",
        requestedDays: r?.requestedDays ?? 0,
        effectiveDays: r?.effectiveDays ?? 0,
        clamped: r?.clamped ?? null,
        cutoff: null,
        matched: 0,
        purged: 0,
        protectedByHold: 0,
      };
      report.classes.push(base);
      if (!r) continue; // fail-closed: without the tenant's settings nothing is purged
      base.cutoff = new Date(startedAt.getTime() - r.effectiveDays * DAY_MS).toISOString();
      if (!CLASS_BOUNDS[cls].purgeable) {
        base.status = "retained_by_policy";
        continue;
      }
      const wide = classWideHold(holds, cls);
      if (wide) {
        base.status = "skipped_hold";
        base.holdId = wide.id;
        continue;
      }
      const provs = this.d.providers.filter(
        (x) => x.declaration.dataClasses.includes(cls) && x.purge,
      );
      if (provs.length === 0) {
        base.status = "no_store";
        continue;
      }
      const protect: Identifier[][] = subjectScopedHolds(holds, cls).flatMap(
        (h) => groups.get(h.id) ?? [],
      );
      try {
        for (const prov of provs) {
          const ctx = {
            tenantId: t,
            now: startedAt,
            pseudonym: async () => {
              throw new GovernanceError("invalid", "purge does not pseudonymise by subject");
            },
          };
          const res = await (prov.purge as NonNullable<SubjectDataProvider["purge"]>)(ctx, {
            dataClass: cls,
            olderThan: new Date(base.cutoff),
            dryRun,
            protect: { subjects: protect },
          });
          base.matched += res.matched;
          base.purged += res.purged;
          base.protectedByHold += res.protectedByHold;
        }
        base.status = dryRun ? "dry_run" : "purged";
      } catch (e) {
        base.status = "error";
        base.error = (e as Error).message.slice(0, 200);
      }
    }

    const finished = this.now();
    await this.d.store.finishRun(t, runId, finished, report as unknown as Record<string, unknown>);
    await this.d.audit.emit({
      tenantId: t,
      action: dryRun ? "retention.dry_run.completed" : "retention.purge.completed",
      actorId: p.id,
      input: { run_id: runId, dry_run: dryRun },
      output: Object.fromEntries(
        report.classes.map((c) => [
          c.dataClass,
          { status: c.status, purged: c.purged, matched: c.matched },
        ]),
      ),
    });
    return report;
  }
}
