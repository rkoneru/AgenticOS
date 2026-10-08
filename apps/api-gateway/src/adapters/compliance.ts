import { ComplianceError, type Compliance, type ComplianceActor } from "@axis/compliance";
import {
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type CompliancePort,
  type Principal,
} from "../ports.js";

/** Translates the service's refusals. A validation failure carries the failing paths to the caller. */
export function fromComplianceError(e: unknown): never {
  if (!(e instanceof ComplianceError)) throw e;
  switch (e.code) {
    case "not_found":
      throw new PortNotFound(e.message);
    case "forbidden":
    case "unauthenticated":
      throw new PortForbidden(e.message);
    case "conflict":
      throw new PortConflict(e.message);
    case "invalid":
      throw new PortInvalid(
        e.message,
        (e.checks.length > 0 ? e.checks : [""]).map((c) => ({
          path: c === "" ? "/" : c,
          message: e.message,
          keyword: e.code,
        })),
      );
    default:
      throw new PortUnavailable(e.message);
  }
}

/** The tenant, the member and the role come from the authenticated gateway principal and nothing else. */
export const complianceActor = (p: Principal): ComplianceActor => ({
  tenantId: p.tenantId,
  subject: p.memberId,
  role: p.role,
});

const wrap = async <T>(f: () => Promise<T>): Promise<T> => {
  try {
    return await f();
  } catch (e) {
    return fromComplianceError(e);
  }
};

type Rec = Record<string, unknown>;

export class ComplianceAdapter implements CompliancePort {
  constructor(private readonly c: Compliance) {}

  listSystems(p: Principal, q: { risk_level?: string; lifecycle_stage?: string }): Promise<Rec[]> {
    return wrap(
      async () =>
        (await this.c.systems.list(complianceActor(p), {
          ...(q.risk_level ? { risk_level: q.risk_level as never } : {}),
          ...(q.lifecycle_stage ? { lifecycle_stage: q.lifecycle_stage as never } : {}),
        })) as unknown as Rec[],
    );
  }
  createSystem(p: Principal, body: Rec): Promise<Rec> {
    return wrap(
      async () =>
        (await this.c.systems.create(complianceActor(p), body as never)) as unknown as Rec,
    );
  }
  getSystem(p: Principal, id: string, version?: number): Promise<Rec> {
    return wrap(
      async () => (await this.c.systems.get(complianceActor(p), id, version)) as unknown as Rec,
    );
  }
  updateSystem(p: Principal, id: string, expected: number, body: Rec): Promise<Rec> {
    return wrap(
      async () =>
        (await this.c.systems.update(
          complianceActor(p),
          id,
          expected,
          body as never,
        )) as unknown as Rec,
    );
  }
  listAssessments(
    p: Principal,
    q: { system_id?: string; state?: string; overdue?: boolean },
  ): Promise<Rec[]> {
    return wrap(
      async () =>
        (await this.c.assessments.list(complianceActor(p), {
          ...(q.system_id ? { system_id: q.system_id } : {}),
          ...(q.state ? { state: q.state as never } : {}),
          ...(q.overdue !== undefined ? { overdue: q.overdue } : {}),
        })) as unknown as Rec[],
    );
  }
  createAssessment(p: Principal, body: Rec): Promise<Rec> {
    return wrap(
      async () =>
        (await this.c.assessments.create(complianceActor(p), body as never)) as unknown as Rec,
    );
  }
  getAssessment(p: Principal, id: string, version?: number): Promise<Rec> {
    return wrap(
      async () => (await this.c.assessments.get(complianceActor(p), id, version)) as unknown as Rec,
    );
  }
  reviseAssessment(p: Principal, id: string, expected: number, body: Rec): Promise<Rec> {
    return wrap(
      async () =>
        (await this.c.assessments.revise(
          complianceActor(p),
          id,
          expected,
          body as never,
        )) as unknown as Rec,
    );
  }
  submitAssessment(p: Principal, id: string, expected: number): Promise<Rec> {
    return wrap(
      async () =>
        (await this.c.assessments.submit(complianceActor(p), id, expected)) as unknown as Rec,
    );
  }
  withdrawAssessment(p: Principal, id: string, expected: number): Promise<Rec> {
    return wrap(
      async () =>
        (await this.c.assessments.withdraw(complianceActor(p), id, expected)) as unknown as Rec,
    );
  }
  reviewAssessment(
    p: Principal,
    id: string,
    r: { expected_version: number; decision: "approve" | "reject"; comment?: string },
  ): Promise<Rec> {
    return wrap(
      async () =>
        (await this.c.assessments.review(
          complianceActor(p),
          id,
          r.expected_version,
          r.decision,
          r.comment ?? "",
        )) as unknown as Rec,
    );
  }
  generateDocument(
    p: Principal,
    blueprint: { name: string; version: string },
  ): Promise<{ document: Rec; created: boolean }> {
    return wrap(async () => {
      const r = await this.c.documents.generate(complianceActor(p), blueprint);
      return { document: r.document as unknown as Rec, created: r.created };
    });
  }
  listDocuments(
    p: Principal,
    q: { blueprint_name?: string; blueprint_version?: string },
  ): Promise<Rec[]> {
    return wrap(
      async () => (await this.c.documents.list(complianceActor(p), q)) as unknown as Rec[],
    );
  }
  getDocument(p: Principal, id: string): Promise<{ document: Rec; verification: Rec }> {
    return wrap(async () => {
      const r = await this.c.documents.get(complianceActor(p), id);
      return {
        document: r.document as unknown as Rec,
        verification: r.verification as unknown as Rec,
      };
    });
  }
}

/** Fail-closed stand-in for a gateway that was wired without the compliance service: every operation is a 503, never an empty success. */
export class UnavailableCompliance implements CompliancePort {
  private fail(): never {
    throw new PortUnavailable("the compliance service is not configured on this gateway");
  }
  listSystems = () => this.fail();
  createSystem = () => this.fail();
  getSystem = () => this.fail();
  updateSystem = () => this.fail();
  listAssessments = () => this.fail();
  createAssessment = () => this.fail();
  getAssessment = () => this.fail();
  reviseAssessment = () => this.fail();
  submitAssessment = () => this.fail();
  withdrawAssessment = () => this.fail();
  reviewAssessment = () => this.fail();
  generateDocument = () => this.fail();
  listDocuments = () => this.fail();
  getDocument = () => this.fail();
}
