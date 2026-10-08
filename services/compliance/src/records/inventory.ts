import { requireRole } from "../authz.js";
import { denyAudit, guarded, iso, makeCtx, mutate, type Ctx, type CtxOptions } from "../context.js";
import { conflict, invalid, notFound } from "../errors.js";
import type { ComplianceActor } from "../authz.js";
import type { LifecycleStage, RiskLevel, SystemInput, SystemRecord } from "../types.js";
import {
  LIFECYCLE_STAGES,
  Problems,
  RISK_LEVELS,
  SYSTEM_ID,
  blueprintRefs,
  oneOf,
  stakeholders,
  strings,
  text,
  MAX_SHORT,
} from "./validate.js";

export interface SystemFilter {
  risk_level?: RiskLevel;
  lifecycle_stage?: LifecycleStage;
}

export class InventoryService {
  constructor(private readonly c: Ctx) {}

  static from(o: CtxOptions): InventoryService {
    return new InventoryService(makeCtx(o));
  }

  private parse(input: unknown, existing?: SystemRecord): Omit<SystemRecord, keyof Meta> {
    const pr = new Problems();
    const o = (typeof input === "object" && input !== null ? input : {}) as Record<string, unknown>;
    if (typeof input !== "object" || input === null || Array.isArray(input)) pr.add("");
    const rec = {
      name: text(pr, "/name", o["name"], MAX_SHORT),
      purpose: text(pr, "/purpose", o["purpose"]),
      owner: text(pr, "/owner", o["owner"], MAX_SHORT),
      risk_level: oneOf(pr, "/risk_level", o["risk_level"], RISK_LEVELS),
      lifecycle_stage: oneOf(
        pr,
        "/lifecycle_stage",
        o["lifecycle_stage"],
        LIFECYCLE_STAGES,
        existing?.lifecycle_stage ?? "design",
      ),
      blueprints: blueprintRefs(pr, "/blueprints", o["blueprints"]),
      data_categories: strings(pr, "/data_categories", o["data_categories"]),
      stakeholders: stakeholders(pr, "/stakeholders", o["stakeholders"]),
    };
    pr.done("system");
    return rec;
  }

  async create(p: ComplianceActor, input: SystemInput): Promise<SystemRecord> {
    try {
      requireRole(p, "compliance.write");
    } catch (e) {
      return denyAudit(this.c, p, "compliance.system.create", e);
    }
    const fields = this.parse(input);
    const raw = (input as { system_id?: unknown }).system_id;
    if (raw !== undefined && (typeof raw !== "string" || !SYSTEM_ID.test(raw)))
      throw invalid("system: invalid fields", ["/system_id"]);
    const id =
      (raw as string | undefined) ?? `sys-${this.c.newId().replaceAll("-", "").slice(-12)}`;
    const at = iso(this.c.now());
    const rec: SystemRecord = {
      system_id: id,
      version: 1,
      ...fields,
      created_at: at,
      created_by: p.subject,
      updated_at: at,
      updated_by: p.subject,
    };
    return mutate(this.c, p, "compliance.system.create", { system_id: id }, () =>
      guarded(async () => {
        await this.c.docs.insert(p.tenantId, "systems", id, rec);
        await this.c.docs.insert(p.tenantId, "system_versions", `${id}@1`, rec);
        return rec;
      }, "system"),
    );
  }

  /** A new version of the record (full replacement of the editable fields); `expected_version` must be the current one. */
  async update(
    p: ComplianceActor,
    systemId: string,
    expectedVersion: number,
    input: Partial<SystemInput>,
  ): Promise<SystemRecord> {
    try {
      requireRole(p, "compliance.write");
    } catch (e) {
      return denyAudit(this.c, p, "compliance.system.update", e);
    }
    const head = await this.c.docs.get<SystemRecord>(p.tenantId, "systems", systemId);
    if (!head) throw notFound("system not found");
    const cur = head.data;
    if (cur.version !== expectedVersion) throw conflict("system changed since it was read");
    const merged = this.parse({ ...cur, ...input }, cur);
    const next: SystemRecord = {
      ...cur,
      ...merged,
      version: cur.version + 1,
      updated_at: iso(this.c.now()),
      updated_by: p.subject,
    };
    return mutate(
      this.c,
      p,
      "compliance.system.update",
      { system_id: systemId, version: next.version },
      () =>
        guarded(async () => {
          await this.c.docs.update(p.tenantId, "systems", systemId, head.rev, next);
          await this.c.docs.insert(
            p.tenantId,
            "system_versions",
            `${systemId}@${next.version}`,
            next,
          );
          return next;
        }, "system"),
    );
  }

  async get(p: ComplianceActor, systemId: string, version?: number): Promise<SystemRecord> {
    requireRole(p, "compliance.read");
    const d =
      version === undefined
        ? await this.c.docs.get<SystemRecord>(p.tenantId, "systems", systemId)
        : await this.c.docs.get<SystemRecord>(
            p.tenantId,
            "system_versions",
            `${systemId}@${version}`,
          );
    if (!d) throw notFound("system not found");
    return d.data;
  }

  async list(p: ComplianceActor, f: SystemFilter = {}): Promise<SystemRecord[]> {
    requireRole(p, "compliance.read");
    const filter: Record<string, string> = {};
    if (f.risk_level) filter["risk_level"] = f.risk_level;
    if (f.lifecycle_stage) filter["lifecycle_stage"] = f.lifecycle_stage;
    return (await this.c.docs.find<SystemRecord>(p.tenantId, "systems", filter)).map((d) => d.data);
  }

  async history(p: ComplianceActor, systemId: string): Promise<SystemRecord[]> {
    requireRole(p, "compliance.read");
    const rows = await this.c.docs.find<SystemRecord>(p.tenantId, "system_versions", {
      system_id: systemId,
    });
    return rows.map((d) => d.data).sort((a, b) => a.version - b.version);
  }
}

type Meta = Pick<
  SystemRecord,
  "system_id" | "version" | "created_at" | "created_by" | "updated_at" | "updated_by"
>;
