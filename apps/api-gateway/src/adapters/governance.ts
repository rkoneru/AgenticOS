import {
  GovernanceError,
  PRIVACY_OFFICER,
  isDataClass,
  type DsarRequest,
  type GovernanceKit,
  type Hold,
  type Principal as GovPrincipal,
  type RetentionRun,
} from "@axis/data-governance";
import {
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type GovernancePort,
  type Principal,
} from "../ports.js";

type Rec = Record<string, unknown>;

/** Reads: the roles that may see the queue, the holds and the reports. Writes and erasure: the privacy officer, nobody else. */
export const GOVERNANCE_READ_ROLES: ReadonlySet<string> = new Set([
  "owner",
  "admin",
  "auditor",
  PRIVACY_OFFICER,
]);
export const GOVERNANCE_WRITE_ROLES: ReadonlySet<string> = new Set([PRIVACY_OFFICER]);

/** Translates the service's refusals. A residency refusal is a 403, a hold or an unverified requester a 409. */
export function fromGovernanceError(e: unknown): never {
  if (e instanceof GovernanceError) {
    switch (e.code) {
      case "not_found":
        throw new PortNotFound(e.message);
      case "forbidden":
      case "restricted":
      case "residency":
        throw new PortForbidden(e.message);
      case "conflict":
      case "not_verified":
      case "held":
        throw new PortConflict(e.message);
      case "invalid":
        throw new PortInvalid(e.message, [{ path: "/", message: e.message, keyword: e.code }]);
      case "unavailable":
        throw new PortUnavailable(e.message);
      default:
        // residual_data: erasure could not be proven; nothing was shredded. Surfaces as 500 so it is never mistaken for done.
        throw new Error(e.message);
    }
  }
  throw e;
}

const wrap = async <T>(f: () => Promise<T>): Promise<T> => {
  try {
    return await f();
  } catch (e) {
    return fromGovernanceError(e);
  }
};

const dsarView = (r: DsarRequest): Rec => ({
  id: r.id,
  kind: r.kind,
  subject_ref: r.subjectRef,
  status: r.status,
  received_at: r.receivedAt.toISOString(),
  due_at: (r.extendedUntil ?? r.dueAt).toISOString(),
  extended: r.extendedUntil !== null,
  verified_at: r.verifiedAt?.toISOString() ?? null,
  verified_method: r.verifiedMethod,
  destination_region: r.destinationRegion,
  result: r.result,
});
const holdView = (h: Hold): Rec => ({
  id: h.id,
  kind: h.kind,
  scope: h.scope,
  case_ref: h.caseRef,
  classes: h.dataClasses,
  reason: h.reason,
  placed_by: h.placedBy,
  placed_at: h.placedAt.toISOString(),
  released_at: h.releasedAt?.toISOString() ?? null,
});

interface ClassReportLike {
  dataClass: string;
  status: string;
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
const reportView = (
  runId: string,
  dryRun: boolean,
  startedAt: string,
  finishedAt: string | null,
  classes: readonly ClassReportLike[],
): Rec => ({
  run_id: runId,
  dry_run: dryRun,
  started_at: startedAt,
  finished_at: finishedAt,
  classes: classes.map((c) => ({
    data_class: c.dataClass,
    status: c.status,
    requested_days: c.requestedDays,
    effective_days: c.effectiveDays,
    clamped: c.clamped ?? null,
    cutoff: c.cutoff ?? null,
    matched: c.matched,
    purged: c.purged,
    protected_by_hold: c.protectedByHold,
    ...(c.holdId !== undefined ? { hold_id: c.holdId } : {}),
    ...(c.error !== undefined ? { error: c.error } : {}),
  })),
});
const runView = (r: RetentionRun): Rec => {
  const rep = r.report as { classes?: ClassReportLike[] };
  return reportView(
    r.id,
    r.dryRun,
    r.startedAt.toISOString(),
    r.finishedAt?.toISOString() ?? null,
    rep.classes ?? [],
  );
};

/**
 * The gateway side of the data-governance service. The tenant, the member and the role come from the authenticated principal and
 * nothing else; the ROLE is checked here as well as by the route's authorisation action (two independent checks): reads need one of
 * `owner | admin | auditor | privacy_officer`, writes and erasure need `privacy_officer`. The engine itself insists on the
 * privacy-officer role even for reads, so a permitted read is executed under an engine principal built from the gateway principal
 * (same tenant, same member id), never under the caller-supplied one.
 */
export class GovernanceAdapter implements GovernancePort {
  constructor(private readonly kit: GovernanceKit) {}

  private reader(p: Principal): GovPrincipal {
    if (!GOVERNANCE_READ_ROLES.has(p.role))
      throw new PortForbidden("your role may not read governance data");
    return { tenantId: p.tenantId, id: p.memberId, roles: [PRIVACY_OFFICER] };
  }
  private officer(p: Principal): GovPrincipal {
    if (!GOVERNANCE_WRITE_ROLES.has(p.role))
      throw new PortForbidden("only the privacy officer may change or act on governance data");
    return { tenantId: p.tenantId, id: p.memberId, roles: [PRIVACY_OFFICER] };
  }

  listDsarRequests(p: Principal, q: { status?: string }): Promise<Rec[]> {
    const g = this.reader(p);
    return wrap(async () =>
      (await this.kit.dsar.list(g, q.status ? [q.status as DsarRequest["status"]] : undefined)).map(
        dsarView,
      ),
    );
  }
  createDsarRequest(p: Principal, body: Rec): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () =>
      dsarView(
        await this.kit.dsar.open(g, {
          kind: body["kind"] as never,
          identifiers: body["identifiers"] as never,
          ...(typeof body["destination_region"] === "string"
            ? { destinationRegion: body["destination_region"] }
            : {}),
        }),
      ),
    );
  }
  getDsarRequest(p: Principal, id: string): Promise<Rec> {
    const g = this.reader(p);
    return wrap(async () => dsarView(await this.kit.dsar.get(g, id)));
  }
  verifyDsarRequest(p: Principal, id: string, evidence: Rec): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () => dsarView(await this.kit.dsar.verify(g, id, evidence)));
  }
  exportDsarRequest(p: Principal, id: string): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () => (await this.kit.dsar.export(g, id)) as unknown as Rec);
  }
  eraseDsarRequest(p: Principal, id: string): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () => {
      const o = await this.kit.dsar.erase(g, id);
      return {
        status: o.status,
        request: dsarView(o.request),
        providers: o.providers as unknown as Rec[],
      };
    });
  }
  restrictDsarRequest(p: Principal, id: string, reason: string): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () => dsarView(await this.kit.dsar.applyRestriction(g, id, reason)));
  }

  listHolds(p: Principal, q: { all?: boolean }): Promise<Rec[]> {
    const g = this.reader(p);
    return wrap(async () => (await this.kit.holds.list(g, q.all !== true)).map(holdView));
  }
  placeHold(p: Principal, body: Rec): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () =>
      holdView(
        await this.kit.holds.placeHold(g, {
          scope: body["scope"] as never,
          reason: String(body["reason"] ?? ""),
          ...(body["classes"] ? { dataClasses: body["classes"] as never } : {}),
          ...(typeof body["case_ref"] === "string" ? { caseRef: body["case_ref"] } : {}),
          ...(body["groups"] ? { groups: body["groups"] as never } : {}),
        }),
      ),
    );
  }
  releaseHold(p: Principal, id: string): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () => holdView(await this.kit.holds.release(g, id)));
  }

  getRetention(p: Principal): Promise<Rec[]> {
    const g = this.reader(p);
    return wrap(async () => {
      const r = await this.kit.retention.resolve(g.tenantId);
      if (!r) throw new GovernanceError("unavailable", "the tenant's retention settings are unavailable");
      return r.map((x) => ({
        data_class: x.dataClass,
        requested_days: x.requestedDays,
        effective_days: x.effectiveDays,
        clamped: x.clamped,
        source: x.source,
      }));
    });
  }
  setRetention(p: Principal, dataClass: string, days: number): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () => {
      if (!isDataClass(dataClass)) throw new GovernanceError("invalid", "unknown data class");
      await this.kit.retention.setPolicy(g, dataClass, days);
      return { data_class: dataClass, days };
    });
  }
  listRetentionRuns(p: Principal): Promise<Rec[]> {
    const g = this.reader(p);
    return wrap(async () => (await this.kit.retention.runs(g)).map(runView));
  }
  runRetention(p: Principal, q: { dry_run?: boolean; classes?: string[] }): Promise<Rec> {
    const g = this.officer(p);
    return wrap(async () => {
      const rep = await this.kit.retention.run(g, {
        dryRun: q.dry_run !== false,
        ...(q.classes ? { classes: q.classes.filter(isDataClass) } : {}),
      });
      const stored = (await this.kit.retention.runs(g)).find((r) => r.id === rep.runId);
      return reportView(
        rep.runId,
        rep.dryRun,
        rep.startedAt,
        stored?.finishedAt?.toISOString() ?? null,
        rep.classes as unknown as ClassReportLike[],
      );
    });
  }

  getResidency(p: Principal): Promise<Rec> {
    const g = this.reader(p);
    return wrap(async () => {
      const t = await this.kit.regions.resolve(g.tenantId).catch(() => undefined);
      if (!t) throw new GovernanceError("unavailable", "the tenant's residency policy is unavailable");
      return {
        home_region: t.homeRegion,
        allowed_regions: await this.kit.residency.allowedRegions(g.tenantId),
      };
    });
  }
}

/** Fail-closed stand-in for a gateway wired without the governance kit: every operation is a 503, never an empty success. */
export class UnavailableGovernance implements GovernancePort {
  private fail(): never {
    throw new PortUnavailable("the data-governance service is not configured on this gateway");
  }
  listDsarRequests = () => this.fail();
  createDsarRequest = () => this.fail();
  getDsarRequest = () => this.fail();
  verifyDsarRequest = () => this.fail();
  exportDsarRequest = () => this.fail();
  eraseDsarRequest = () => this.fail();
  restrictDsarRequest = () => this.fail();
  listHolds = () => this.fail();
  placeHold = () => this.fail();
  releaseHold = () => this.fail();
  getRetention = () => this.fail();
  setRetention = () => this.fail();
  listRetentionRuns = () => this.fail();
  runRetention = () => this.fail();
  getResidency = () => this.fail();
}
