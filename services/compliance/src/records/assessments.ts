import { requireRole, type ComplianceActor } from "../authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "../context.js";
import { conflict, forbidden, invalid, notFound } from "../errors.js";
import type {
  AssessmentInput,
  AssessmentRecord,
  AssessmentState,
  AssessmentView,
  SystemRecord,
} from "../types.js";
import type { Doc } from "../docstore.js";
import { isFinal, nextState, overdueReason, reviewerConflict } from "./states.js";
import {
  MAX_SHORT,
  Problems,
  RATINGS,
  affectedGroups,
  blueprintRefs,
  isoDate,
  oneOf,
  risks,
  stakeholders,
  text,
} from "./validate.js";

export interface AssessmentFilter {
  system_id?: string;
  state?: AssessmentState;
  overdue?: boolean;
}

export type ReviewDecision = "approve" | "reject";

const key = (id: string, v: number): string => `${id}@${v}`;
const ID_RE = /^[A-Za-z0-9-]{8,64}$/;

/**
 * AI impact assessments (ISO/IEC 42001 clause 6.1.4 / Annex A.5). Versioned records with a review workflow:
 * draft -> in_review -> approved | rejected. A version that has been reviewed never changes; revising it creates the next version.
 * The reviewer is never the author, a contributor, or the member who submitted the version (service check AND database constraint).
 */
export class AssessmentService {
  constructor(private readonly c: Ctx) {}

  private view(a: AssessmentRecord, latest: number): AssessmentView {
    const superseded = a.version < latest;
    const reason = superseded ? null : overdueReason(a, this.c.now(), this.c.reviewGraceMs);
    return { ...a, overdue: reason !== null, overdue_reason: reason, superseded };
  }

  private async docs(tenantId: string, id: string): Promise<Doc<AssessmentRecord>[]> {
    if (!ID_RE.test(id)) return [];
    const rows = await this.c.docs.find<AssessmentRecord>(tenantId, "assessments", {
      assessment_id: id,
    });
    return rows.sort((a, b) => a.data.version - b.data.version);
  }

  private async versions(tenantId: string, id: string): Promise<AssessmentRecord[]> {
    return (await this.docs(tenantId, id)).map((d) => d.data);
  }

  /** The latest version together with the revision the update must be conditional on. */
  private async latest(tenantId: string, id: string): Promise<AssessmentRecord & { _rev: number }> {
    const all = await this.docs(tenantId, id);
    const last = all[all.length - 1];
    if (!last) throw notFound("assessment not found");
    return { ...last.data, _rev: last.rev };
  }

  private async systemOf(tenantId: string, systemId: string): Promise<SystemRecord> {
    const s = await this.c.docs.get<SystemRecord>(tenantId, "systems", systemId);
    if (!s) throw invalid("assessment: invalid fields", ["/system_id"]);
    return s.data;
  }

  private parse(input: unknown): Required<AssessmentInput> {
    const pr = new Problems();
    const o = (typeof input === "object" && input !== null ? input : {}) as Record<string, unknown>;
    if (typeof input !== "object" || input === null || Array.isArray(input)) pr.add("");
    const systemId = text(pr, "/system_id", o["system_id"], 63);
    const rec = {
      system_id: systemId,
      title: text(pr, "/title", o["title"], MAX_SHORT),
      risk_rating: oneOf(pr, "/risk_rating", o["risk_rating"], RATINGS),
      intended_use: text(pr, "/intended_use", o["intended_use"]),
      blueprints: blueprintRefs(pr, "/blueprints", o["blueprints"]),
      affected_groups: affectedGroups(pr, "/affected_groups", o["affected_groups"]),
      risks: risks(pr, "/risks", o["risks"]),
      stakeholders: stakeholders(pr, "/stakeholders", o["stakeholders"]),
      review_due: isoDate(pr, "/review_due", o["review_due"]),
    };
    pr.done("assessment");
    return rec;
  }

  async create(p: ComplianceActor, input: AssessmentInput): Promise<AssessmentView> {
    try {
      requireRole(p, "compliance.write");
    } catch (e) {
      return denyAudit(this.c, p, "compliance.assessment.create", e);
    }
    const f = this.parse(input);
    await this.systemOf(p.tenantId, f.system_id);
    const id = this.c.newId();
    const at = iso(this.c.now());
    const rec: AssessmentRecord = {
      assessment_id: id,
      version: 1,
      ...f,
      state: "draft",
      author: p.subject,
      contributors: [p.subject],
      created_at: at,
      updated_at: at,
      submitted_by: null,
      submitted_at: null,
      reviewed_by: null,
      reviewed_at: null,
      review_comment: null,
      supersedes: null,
    };
    return mutate(
      this.c,
      p,
      "compliance.assessment.create",
      { assessment_id: id, system_id: f.system_id },
      () =>
        guarded(async () => {
          await this.c.docs.insert(p.tenantId, "assessments", key(id, 1), rec);
          return this.view(rec, 1);
        }, "assessment"),
    );
  }

  /**
   * Edits the latest version in place while it is a draft; when the latest version has been reviewed (approved or rejected) it creates
   * the NEXT version as a new draft authored by the caller. A version waiting for review cannot be edited (withdraw it first).
   */
  async revise(
    p: ComplianceActor,
    id: string,
    expectedVersion: number,
    patch: Partial<AssessmentInput>,
  ): Promise<AssessmentView> {
    try {
      requireRole(p, "compliance.write");
    } catch (e) {
      return denyAudit(this.c, p, "compliance.assessment.revise", e);
    }
    const { _rev: rev, ...cur } = await this.latest(p.tenantId, id);
    if (cur.version !== expectedVersion) throw conflict("assessment changed since it was read");
    if (cur.state === "in_review")
      throw conflict("assessment is waiting for review; withdraw it first");
    const f = this.parse({ ...cur, ...patch, system_id: cur.system_id });
    const at = iso(this.c.now());
    const fresh = isFinal(cur.state);
    const next: AssessmentRecord = fresh
      ? {
          ...cur,
          ...f,
          version: cur.version + 1,
          state: "draft",
          author: p.subject,
          contributors: [p.subject],
          created_at: at,
          updated_at: at,
          submitted_by: null,
          submitted_at: null,
          reviewed_by: null,
          reviewed_at: null,
          review_comment: null,
          supersedes: cur.version,
        }
      : {
          ...cur,
          ...f,
          updated_at: at,
          contributors: cur.contributors.includes(p.subject)
            ? cur.contributors
            : [...cur.contributors, p.subject],
        };
    return mutate(
      this.c,
      p,
      "compliance.assessment.revise",
      { assessment_id: id, version: next.version },
      () =>
        guarded(async () => {
          if (fresh)
            await this.c.docs.insert(p.tenantId, "assessments", key(id, next.version), next);
          else {
            await this.c.docs.update(p.tenantId, "assessments", key(id, cur.version), rev, next);
          }
          return this.view(next, next.version);
        }, "assessment"),
    );
  }

  private async transition(
    p: ComplianceActor,
    id: string,
    expectedVersion: number,
    event: "submit" | "withdraw",
  ): Promise<AssessmentView> {
    const action = `compliance.assessment.${event}`;
    try {
      requireRole(p, "compliance.write");
    } catch (e) {
      return denyAudit(this.c, p, action, e);
    }
    const { _rev: rev, ...cur } = await this.latest(p.tenantId, id);
    if (cur.version !== expectedVersion) throw conflict("assessment changed since it was read");
    const state = nextState(cur.state, event);
    const at = iso(this.c.now());
    const next: AssessmentRecord = {
      ...cur,
      state,
      updated_at: at,
      submitted_by: event === "submit" ? p.subject : null,
      submitted_at: event === "submit" ? at : null,
    };
    return mutate(this.c, p, action, { assessment_id: id, version: cur.version }, () =>
      guarded(async () => {
        await this.c.docs.update(p.tenantId, "assessments", key(id, cur.version), rev, next);
        return this.view(next, next.version);
      }, "assessment"),
    );
  }

  submit(p: ComplianceActor, id: string, expectedVersion: number): Promise<AssessmentView> {
    return this.transition(p, id, expectedVersion, "submit");
  }

  withdraw(p: ComplianceActor, id: string, expectedVersion: number): Promise<AssessmentView> {
    return this.transition(p, id, expectedVersion, "withdraw");
  }

  /** Approve or reject the version waiting for review. The reviewer must be independent of everyone who worked on the version. */
  async review(
    p: ComplianceActor,
    id: string,
    expectedVersion: number,
    decision: ReviewDecision,
    comment: string,
  ): Promise<AssessmentView> {
    const action = "compliance.assessment.review";
    try {
      requireRole(p, "compliance.review");
    } catch (e) {
      return denyAudit(this.c, p, action, e);
    }
    if (decision !== "approve" && decision !== "reject")
      throw invalid("review: invalid fields", ["/decision"]);
    const pr = new Problems();
    const note = text(pr, "/comment", comment, 2000, decision === "reject");
    pr.done("review");
    const { _rev: rev, ...cur } = await this.latest(p.tenantId, id);
    if (cur.version !== expectedVersion) throw conflict("assessment changed since it was read");
    const state = nextState(cur.state, decision);
    const why = reviewerConflict(cur, p.subject);
    if (why !== null) {
      const err = forbidden(`review refused: ${why}`);
      return denyAudit(this.c, p, action, err);
    }
    const at = iso(this.c.now());
    const next: AssessmentRecord = {
      ...cur,
      state,
      updated_at: at,
      reviewed_by: p.subject,
      reviewed_at: at,
      review_comment: note === "" ? null : note,
    };
    return mutate(this.c, p, action, { assessment_id: id, version: cur.version, decision }, () =>
      guarded(async () => {
        await this.c.docs.update(p.tenantId, "assessments", key(id, cur.version), rev, next);
        return this.view(next, next.version);
      }, "assessment"),
    );
  }

  async get(p: ComplianceActor, id: string, version?: number): Promise<AssessmentView> {
    requireRole(p, "compliance.read");
    const all = await this.versions(p.tenantId, id);
    const last = all[all.length - 1];
    if (!last) throw notFound("assessment not found");
    const a = version === undefined ? last : all.find((x) => x.version === version);
    if (!a) throw notFound("assessment version not found");
    return this.view(a, last.version);
  }

  /** History of one assessment, oldest first. */
  async history(p: ComplianceActor, id: string): Promise<AssessmentView[]> {
    requireRole(p, "compliance.read");
    const all = await this.versions(p.tenantId, id);
    const last = all[all.length - 1];
    if (!last) throw notFound("assessment not found");
    return all.map((a) => this.view(a, last.version));
  }

  /** The LATEST version of every assessment (filtered), ordered by id. Older versions are reachable through `get(id, version)`. */
  async list(p: ComplianceActor, f: AssessmentFilter = {}): Promise<AssessmentView[]> {
    requireRole(p, "compliance.read");
    const rows = (
      await this.c.docs.find<AssessmentRecord>(p.tenantId, "assessments", {
        ...(f.system_id ? { system_id: f.system_id } : {}),
      })
    ).map((d) => d.data);
    const latest = new Map<string, number>();
    for (const a of rows)
      latest.set(a.assessment_id, Math.max(latest.get(a.assessment_id) ?? 0, a.version));
    // The latest version is computed over ALL versions of the tenant's assessments of the system (not only the filtered state).
    return rows
      .filter((a) => a.version === latest.get(a.assessment_id))
      .map((a) => this.view(a, a.version))
      .filter((v) => (f.state ? v.state === f.state : true))
      .filter((v) => (f.overdue === undefined ? true : v.overdue === f.overdue))
      .sort((a, b) =>
        a.assessment_id < b.assessment_id ? -1 : a.assessment_id > b.assessment_id ? 1 : 0,
      );
  }
}
