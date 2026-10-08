import { randomUUID } from "node:crypto";
import { withTenant } from "@axis/db";
import type { ClientBase, PoolClient } from "pg";
import { GovernanceError, type DataClass } from "./types.js";

export type RequestKind = "export" | "erase" | "restrict";
export type RequestStatus =
  "received" | "verified" | "processing" | "completed" | "rejected" | "cancelled";
export const OPEN_STATUSES: readonly RequestStatus[] = ["received", "verified", "processing"];

export interface DsarRequest {
  tenantId: string;
  id: string;
  kind: RequestKind;
  subjectId: string;
  subjectRef: string;
  status: RequestStatus;
  receivedAt: Date;
  dueAt: Date;
  extendedUntil: Date | null;
  extensionReason: string | null;
  verifiedAt: Date | null;
  verifiedMethod: string | null;
  requestedBy: string;
  destinationRegion: string | null;
  sealedIdentifiers: Buffer | null;
  result: Record<string, unknown>;
  rev: number;
}

export interface StepRecord {
  tenantId: string;
  requestId: string;
  provider: string;
  phase: "export" | "erase" | "verify";
  status: "done" | "failed";
  result: Record<string, unknown>;
}

export type HoldKind = "legal_hold" | "restriction";
export type HoldScope = "tenant" | "subject" | "case";
export interface Hold {
  tenantId: string;
  id: string;
  kind: HoldKind;
  scope: HoldScope;
  subjectId: string | null;
  caseRef: string | null;
  /** null = every class. */
  dataClasses: DataClass[] | null;
  reason: string;
  sealedIdentifiers: Buffer | null;
  placedBy: string;
  placedAt: Date;
  releasedBy: string | null;
  releasedAt: Date | null;
}

export interface RetentionRun {
  tenantId: string;
  id: string;
  dryRun: boolean;
  startedAt: Date;
  finishedAt: Date | null;
  report: Record<string, unknown>;
}

export interface SubjectRow {
  subjectId: string;
  salt: Buffer | null;
  shreddedAt: Date | null;
}

/** Tenant-scoped governance state. Every method names the tenant; Postgres enforces it with forced RLS. */
export interface GovernanceStore {
  findSubjects(tenantId: string, lookups: readonly string[]): Promise<string[]>;
  createSubject(
    tenantId: string,
    lookups: readonly { hmac: string; kind: string }[],
    salt: Buffer,
  ): Promise<string>;
  addLookups(
    tenantId: string,
    subjectId: string,
    lookups: readonly { hmac: string; kind: string }[],
  ): Promise<void>;
  getSubject(tenantId: string, subjectId: string): Promise<SubjectRow | undefined>;
  /** Crypto-shred: delete every lookup row, null the salt. Idempotent. Returns lookup rows deleted. */
  shredSubject(tenantId: string, subjectId: string, now: Date): Promise<number>;

  insertRequest(r: DsarRequest): Promise<void>;
  getRequest(tenantId: string, id: string): Promise<DsarRequest | undefined>;
  /** Compare-and-set on `rev`; returns the stored request or throws conflict. */
  updateRequest(next: DsarRequest, expectRev: number): Promise<DsarRequest>;
  listRequests(tenantId: string, statuses?: readonly RequestStatus[]): Promise<DsarRequest[]>;

  getStep(
    tenantId: string,
    requestId: string,
    provider: string,
    phase: StepRecord["phase"],
  ): Promise<StepRecord | undefined>;
  putStep(s: StepRecord): Promise<void>;
  listSteps(tenantId: string, requestId: string): Promise<StepRecord[]>;

  insertHold(h: Hold): Promise<void>;
  getHold(tenantId: string, id: string): Promise<Hold | undefined>;
  releaseHold(tenantId: string, id: string, by: string, at: Date): Promise<Hold>;
  listHolds(tenantId: string, activeOnly: boolean): Promise<Hold[]>;

  getPolicies(tenantId: string): Promise<Partial<Record<DataClass, number>>>;
  setPolicy(tenantId: string, cls: DataClass, days: number, by: string, at: Date): Promise<void>;
  insertRun(r: RetentionRun): Promise<void>;
  finishRun(tenantId: string, id: string, at: Date, report: Record<string, unknown>): Promise<void>;
  listRuns(tenantId: string): Promise<RetentionRun[]>;
}

const clone = <T>(v: T): T => structuredClone(v);

export class MemoryGovernanceStore implements GovernanceStore {
  private subjects = new Map<string, SubjectRow>(); // tenant|subject
  private lookups = new Map<string, { subjectId: string; kind: string }>(); // tenant|hmac
  private requests = new Map<string, DsarRequest>();
  private steps = new Map<string, StepRecord>();
  private holds = new Map<string, Hold>();
  private policies = new Map<string, number>();
  private runs = new Map<string, RetentionRun>();

  async findSubjects(t: string, hmacs: readonly string[]): Promise<string[]> {
    const out = new Set<string>();
    for (const h of hmacs) {
      const r = this.lookups.get(`${t}|${h}`);
      if (r) out.add(r.subjectId);
    }
    return [...out].sort();
  }
  async createSubject(t: string, lk: readonly { hmac: string; kind: string }[], salt: Buffer) {
    const id = randomUUID();
    this.subjects.set(`${t}|${id}`, { subjectId: id, salt, shreddedAt: null });
    await this.addLookups(t, id, lk);
    return id;
  }
  async addLookups(t: string, subjectId: string, lk: readonly { hmac: string; kind: string }[]) {
    if (!this.subjects.has(`${t}|${subjectId}`)) throw new GovernanceError("not_found", "subject");
    for (const l of lk)
      if (!this.lookups.has(`${t}|${l.hmac}`))
        this.lookups.set(`${t}|${l.hmac}`, { subjectId, kind: l.kind });
  }
  async getSubject(t: string, id: string) {
    const s = this.subjects.get(`${t}|${id}`);
    return s && clone(s);
  }
  async shredSubject(t: string, id: string, now: Date) {
    let n = 0;
    for (const [k, v] of this.lookups)
      if (k.startsWith(`${t}|`) && v.subjectId === id) {
        this.lookups.delete(k);
        n++;
      }
    const s = this.subjects.get(`${t}|${id}`);
    if (s && s.salt !== null)
      this.subjects.set(`${t}|${id}`, { ...s, salt: null, shreddedAt: now });
    return n;
  }

  async insertRequest(r: DsarRequest) {
    const k = `${r.tenantId}|${r.id}`;
    if (this.requests.has(k)) throw new GovernanceError("conflict", "request exists");
    this.requests.set(k, clone(r));
  }
  async getRequest(t: string, id: string) {
    const r = this.requests.get(`${t}|${id}`);
    return r && clone(r);
  }
  async updateRequest(next: DsarRequest, expectRev: number) {
    const k = `${next.tenantId}|${next.id}`;
    const cur = this.requests.get(k);
    if (!cur) throw new GovernanceError("not_found", "request");
    if (cur.rev !== expectRev) throw new GovernanceError("conflict", "stale request revision");
    const stored = clone({ ...next, rev: expectRev + 1 });
    this.requests.set(k, stored);
    return clone(stored);
  }
  async listRequests(t: string, statuses?: readonly RequestStatus[]) {
    return [...this.requests.values()]
      .filter((r) => r.tenantId === t && (!statuses || statuses.includes(r.status)))
      .sort((a, b) => a.receivedAt.getTime() - b.receivedAt.getTime() || (a.id < b.id ? -1 : 1))
      .map(clone);
  }

  async getStep(t: string, req: string, provider: string, phase: StepRecord["phase"]) {
    const s = this.steps.get(`${t}|${req}|${provider}|${phase}`);
    return s && clone(s);
  }
  async putStep(s: StepRecord) {
    this.steps.set(`${s.tenantId}|${s.requestId}|${s.provider}|${s.phase}`, clone(s));
  }
  async listSteps(t: string, req: string) {
    return [...this.steps.values()]
      .filter((s) => s.tenantId === t && s.requestId === req)
      .map(clone);
  }

  async insertHold(h: Hold) {
    this.holds.set(`${h.tenantId}|${h.id}`, clone(h));
  }
  async getHold(t: string, id: string) {
    const h = this.holds.get(`${t}|${id}`);
    return h && clone(h);
  }
  async releaseHold(t: string, id: string, by: string, at: Date) {
    const h = this.holds.get(`${t}|${id}`);
    if (!h) throw new GovernanceError("not_found", "hold");
    if (h.releasedAt === null) {
      h.releasedAt = at;
      h.releasedBy = by;
    }
    return clone(h);
  }
  async listHolds(t: string, activeOnly: boolean) {
    return [...this.holds.values()]
      .filter((h) => h.tenantId === t && (!activeOnly || h.releasedAt === null))
      .map(clone);
  }

  async getPolicies(t: string) {
    const out: Partial<Record<DataClass, number>> = {};
    for (const [k, v] of this.policies)
      if (k.startsWith(`${t}|`)) out[k.slice(t.length + 1) as DataClass] = v;
    return out;
  }
  async setPolicy(t: string, cls: DataClass, days: number) {
    this.policies.set(`${t}|${cls}`, days);
  }
  async insertRun(r: RetentionRun) {
    this.runs.set(`${r.tenantId}|${r.id}`, clone(r));
  }
  async finishRun(t: string, id: string, at: Date, report: Record<string, unknown>) {
    const r = this.runs.get(`${t}|${id}`);
    if (r) {
      r.finishedAt = at;
      r.report = clone(report);
    }
  }
  async listRuns(t: string) {
    return [...this.runs.values()].filter((r) => r.tenantId === t).map(clone);
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------

export interface PgPoolLike {
  connect(): Promise<PoolClient>;
}
export interface PgGovOptions {
  pool: PgPoolLike;
  /** `SET LOCAL ROLE` per transaction. Production connects as a member of axis_governance and sets it to "axis_governance". */
  role?: string;
}

/** Run `fn` in a tenant-scoped transaction as the governance role. Shared by the store and every Postgres provider. */
export async function governedTx<T>(
  o: PgGovOptions,
  tenantId: string,
  fn: (c: ClientBase) => Promise<T>,
): Promise<T> {
  const client = await o.pool.connect();
  try {
    return await withTenant(client, tenantId, fn, o.role ? { role: o.role } : {});
  } finally {
    client.release();
  }
}

type Row = Record<string, unknown>;
const toRequest = (r: Row): DsarRequest => ({
  tenantId: r["tenant_id"] as string,
  id: r["id"] as string,
  kind: r["kind"] as RequestKind,
  subjectId: r["subject_id"] as string,
  subjectRef: r["subject_ref"] as string,
  status: r["status"] as RequestStatus,
  receivedAt: r["received_at"] as Date,
  dueAt: r["due_at"] as Date,
  extendedUntil: (r["extended_until"] as Date | null) ?? null,
  extensionReason: (r["extension_reason"] as string | null) ?? null,
  verifiedAt: (r["verified_at"] as Date | null) ?? null,
  verifiedMethod: (r["verified_method"] as string | null) ?? null,
  requestedBy: r["requested_by"] as string,
  destinationRegion: (r["destination_region"] as string | null) ?? null,
  sealedIdentifiers: (r["sealed_identifiers"] as Buffer | null) ?? null,
  result: r["result"] as Record<string, unknown>,
  rev: r["rev"] as number,
});
const toHold = (r: Row): Hold => ({
  tenantId: r["tenant_id"] as string,
  id: r["id"] as string,
  kind: r["kind"] as HoldKind,
  scope: r["scope"] as HoldScope,
  subjectId: (r["subject_id"] as string | null) ?? null,
  caseRef: (r["case_ref"] as string | null) ?? null,
  dataClasses: (r["data_classes"] as DataClass[] | null) ?? null,
  reason: r["reason"] as string,
  sealedIdentifiers: (r["sealed_identifiers"] as Buffer | null) ?? null,
  placedBy: r["placed_by"] as string,
  placedAt: r["placed_at"] as Date,
  releasedBy: (r["released_by"] as string | null) ?? null,
  releasedAt: (r["released_at"] as Date | null) ?? null,
});

export class PgGovernanceStore implements GovernanceStore {
  constructor(private readonly o: PgGovOptions) {}
  private tx<T>(t: string, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    return governedTx(this.o, t, fn);
  }

  findSubjects(t: string, hmacs: readonly string[]): Promise<string[]> {
    if (hmacs.length === 0) return Promise.resolve([]);
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        "SELECT DISTINCT subject_id FROM governance_subject_identifiers WHERE lookup_hmac = ANY($1::text[]) ORDER BY 1",
        [hmacs],
      );
      return rows.map((r: Row) => r["subject_id"] as string);
    });
  }
  createSubject(t: string, lk: readonly { hmac: string; kind: string }[], salt: Buffer) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        "INSERT INTO governance_subjects (tenant_id, salt) VALUES ($1, $2) RETURNING subject_id",
        [t, salt],
      );
      const id = (rows[0] as Row)["subject_id"] as string;
      await this.insertLookups(c, t, id, lk);
      return id;
    });
  }
  private async insertLookups(
    c: ClientBase,
    t: string,
    id: string,
    lk: readonly { hmac: string; kind: string }[],
  ): Promise<void> {
    for (const l of lk)
      await c.query(
        "INSERT INTO governance_subject_identifiers (tenant_id, lookup_hmac, subject_id, kind) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
        [t, l.hmac, id, l.kind],
      );
  }
  addLookups(t: string, id: string, lk: readonly { hmac: string; kind: string }[]) {
    return this.tx(t, (c) => this.insertLookups(c, t, id, lk));
  }
  getSubject(t: string, id: string) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        "SELECT subject_id, salt, shredded_at FROM governance_subjects WHERE subject_id = $1",
        [id],
      );
      const r = rows[0] as Row | undefined;
      return r
        ? {
            subjectId: r["subject_id"] as string,
            salt: (r["salt"] as Buffer | null) ?? null,
            shreddedAt: (r["shredded_at"] as Date | null) ?? null,
          }
        : undefined;
    });
  }
  shredSubject(t: string, id: string, now: Date) {
    return this.tx(t, async (c) => {
      const del = await c.query(
        "DELETE FROM governance_subject_identifiers WHERE subject_id = $1",
        [id],
      );
      await c.query(
        "UPDATE governance_subjects SET salt = NULL, shredded_at = $2 WHERE subject_id = $1 AND salt IS NOT NULL",
        [id, now],
      );
      return del.rowCount ?? 0;
    });
  }

  insertRequest(r: DsarRequest) {
    return this.tx(r.tenantId, async (c) => {
      try {
        await c.query(
          `INSERT INTO governance_requests (tenant_id, id, kind, subject_id, subject_ref, status, received_at, due_at, extended_until,
             extension_reason, verified_at, verified_method, requested_by, destination_region, sealed_identifiers, result, rev)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,1)`,
          [
            r.tenantId,
            r.id,
            r.kind,
            r.subjectId,
            r.subjectRef,
            r.status,
            r.receivedAt,
            r.dueAt,
            r.extendedUntil,
            r.extensionReason,
            r.verifiedAt,
            r.verifiedMethod,
            r.requestedBy,
            r.destinationRegion,
            r.sealedIdentifiers,
            JSON.stringify(r.result),
          ],
        );
      } catch (e) {
        if ((e as { code?: string }).code === "23505")
          throw new GovernanceError("conflict", "request exists");
        throw e;
      }
    });
  }
  getRequest(t: string, id: string) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query("SELECT * FROM governance_requests WHERE id = $1", [id]);
      return rows[0] ? toRequest(rows[0] as Row) : undefined;
    });
  }
  updateRequest(n: DsarRequest, expectRev: number) {
    return this.tx(n.tenantId, async (c) => {
      const { rows } = await c.query(
        `UPDATE governance_requests SET status=$3, due_at=$4, extended_until=$5, extension_reason=$6, verified_at=$7, verified_method=$8,
           destination_region=$9, sealed_identifiers=$10, result=$11, rev = rev + 1, updated_at = now()
         WHERE id = $1 AND rev = $2 RETURNING *`,
        [
          n.id,
          expectRev,
          n.status,
          n.dueAt,
          n.extendedUntil,
          n.extensionReason,
          n.verifiedAt,
          n.verifiedMethod,
          n.destinationRegion,
          n.sealedIdentifiers,
          JSON.stringify(n.result),
        ],
      );
      if (!rows[0]) throw new GovernanceError("conflict", "stale request revision");
      return toRequest(rows[0] as Row);
    });
  }
  listRequests(t: string, statuses?: readonly RequestStatus[]) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        "SELECT * FROM governance_requests WHERE ($1::text[] IS NULL OR status = ANY($1::text[])) ORDER BY received_at, id",
        [statuses ? [...statuses] : null],
      );
      return rows.map((r: Row) => toRequest(r));
    });
  }

  getStep(t: string, req: string, provider: string, phase: StepRecord["phase"]) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        "SELECT * FROM governance_steps WHERE request_id=$1 AND provider=$2 AND phase=$3",
        [req, provider, phase],
      );
      const r = rows[0] as Row | undefined;
      return r
        ? ({
            tenantId: t,
            requestId: req,
            provider,
            phase,
            status: r["status"],
            result: r["result"],
          } as StepRecord)
        : undefined;
    });
  }
  putStep(s: StepRecord) {
    return this.tx(s.tenantId, async (c) => {
      await c.query(
        `INSERT INTO governance_steps (tenant_id, request_id, provider, phase, status, result) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (tenant_id, request_id, provider, phase) DO UPDATE SET status = EXCLUDED.status, result = EXCLUDED.result, at = now()`,
        [s.tenantId, s.requestId, s.provider, s.phase, s.status, JSON.stringify(s.result)],
      );
    });
  }
  listSteps(t: string, req: string) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        "SELECT * FROM governance_steps WHERE request_id=$1 ORDER BY at",
        [req],
      );
      return rows.map(
        (r: Row) =>
          ({
            tenantId: t,
            requestId: req,
            provider: r["provider"],
            phase: r["phase"],
            status: r["status"],
            result: r["result"],
          }) as StepRecord,
      );
    });
  }

  insertHold(h: Hold) {
    return this.tx(h.tenantId, async (c) => {
      await c.query(
        `INSERT INTO governance_holds (tenant_id, id, kind, scope, subject_id, case_ref, data_classes, reason, sealed_identifiers, placed_by, placed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          h.tenantId,
          h.id,
          h.kind,
          h.scope,
          h.subjectId,
          h.caseRef,
          h.dataClasses,
          h.reason,
          h.sealedIdentifiers,
          h.placedBy,
          h.placedAt,
        ],
      );
    });
  }
  getHold(t: string, id: string) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query("SELECT * FROM governance_holds WHERE id=$1", [id]);
      return rows[0] ? toHold(rows[0] as Row) : undefined;
    });
  }
  releaseHold(t: string, id: string, by: string, at: Date) {
    return this.tx(t, async (c) => {
      await c.query(
        "UPDATE governance_holds SET released_by=$2, released_at=$3 WHERE id=$1 AND released_at IS NULL",
        [id, by, at],
      );
      const { rows } = await c.query("SELECT * FROM governance_holds WHERE id=$1", [id]);
      if (!rows[0]) throw new GovernanceError("not_found", "hold");
      return toHold(rows[0] as Row);
    });
  }
  listHolds(t: string, activeOnly: boolean) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        `SELECT * FROM governance_holds WHERE (NOT $1::boolean OR released_at IS NULL) ORDER BY placed_at, id`,
        [activeOnly],
      );
      return rows.map((r: Row) => toHold(r));
    });
  }

  getPolicies(t: string) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query("SELECT data_class, days FROM governance_retention_policies");
      const out: Partial<Record<DataClass, number>> = {};
      for (const r of rows as Row[]) out[r["data_class"] as DataClass] = r["days"] as number;
      return out;
    });
  }
  setPolicy(t: string, cls: DataClass, days: number, by: string, at: Date) {
    return this.tx(t, async (c) => {
      await c.query(
        `INSERT INTO governance_retention_policies (tenant_id, data_class, days, updated_by, updated_at) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id, data_class) DO UPDATE SET days = EXCLUDED.days, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
        [t, cls, days, by, at],
      );
    });
  }
  insertRun(r: RetentionRun) {
    return this.tx(r.tenantId, async (c) => {
      await c.query(
        "INSERT INTO governance_retention_runs (tenant_id, id, dry_run, started_at, finished_at, report) VALUES ($1,$2,$3,$4,$5,$6)",
        [r.tenantId, r.id, r.dryRun, r.startedAt, r.finishedAt, JSON.stringify(r.report)],
      );
    });
  }
  finishRun(t: string, id: string, at: Date, report: Record<string, unknown>) {
    return this.tx(t, async (c) => {
      await c.query("UPDATE governance_retention_runs SET finished_at=$2, report=$3 WHERE id=$1", [
        id,
        at,
        JSON.stringify(report),
      ]);
    });
  }
  listRuns(t: string) {
    return this.tx(t, async (c) => {
      const { rows } = await c.query(
        "SELECT * FROM governance_retention_runs ORDER BY started_at, id",
      );
      return rows.map(
        (r: Row) =>
          ({
            tenantId: t,
            id: r["id"],
            dryRun: r["dry_run"],
            startedAt: r["started_at"],
            finishedAt: r["finished_at"] ?? null,
            report: r["report"],
          }) as RetentionRun,
      );
    });
  }
}
