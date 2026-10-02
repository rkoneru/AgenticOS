import {
  ApprovalError,
  eligibleRoles,
  type ApprovalRequest,
  type ApprovalService,
} from "@axis/approvals";
import {
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type ApprovalDto,
  type ApprovalsPort,
  type Page,
  type Principal,
} from "../ports.js";

const PID = /^axp_[0-9A-HJKMNP-TV-Z]{26}$/;

/** Service status -> API status. The API distinguishes an approval escalated beyond its first level from a fresh one. */
export function apiStatus(r: Pick<ApprovalRequest, "status" | "level">): ApprovalDto["status"] {
  if (r.status === "denied") return "rejected";
  if (r.status === "pending" && r.level > 1) return "escalated";
  return r.status;
}

export function toApproval(r: ApprovalRequest): ApprovalDto {
  return {
    id: r.id,
    status: apiStatus(r),
    run_id: r.run_id,
    ...(r.agent.pid && PID.test(r.agent.pid) ? { pid: r.agent.pid } : {}),
    action: r.tool,
    roles: eligibleRoles(r),
    requested_at: new Date(r.created_at_ms).toISOString(),
    sla_deadline: new Date(r.deadline_ms).toISOString(),
    decided_by: r.decided_by,
    decided_at: r.decided_at_ms === null ? null : new Date(r.decided_at_ms).toISOString(),
    comment: r.comment,
  };
}

function fromApprovalError(e: unknown): never {
  if (!(e instanceof ApprovalError)) throw e;
  switch (e.code) {
    case "NOT_FOUND":
      throw new PortNotFound(e.message);
    case "FORBIDDEN_ROLE":
    case "SELF_APPROVAL":
    case "CONFLICT_OF_INTEREST":
      throw new PortForbidden(e.message);
    case "ALREADY_DECIDED":
    case "CONFLICT":
    case "CLAIMED_BY_OTHER":
    case "NOT_DECIDED":
      throw new PortConflict(e.message);
    case "INVALID":
      throw new PortInvalid(e.message, [{ path: "/", message: e.message }]);
    default:
      throw new PortUnavailable("the approvals service could not complete the request; retry");
  }
}

/**
 * Fronts the approvals service. The service trusts the principal it is given, so this adapter builds it ONLY from the authenticated
 * gateway principal: tenant and member id from the credential, the member's role as the approver role. Another tenant's approval is
 * indistinguishable from a missing one (the service scopes every read by tenant and answers NOT_FOUND).
 */
export class ApprovalsAdapter implements ApprovalsPort {
  constructor(private readonly svc: Pick<ApprovalService, "list" | "approve" | "deny">) {}

  private who(p: Principal): { tenant_id: string; id: string; roles: string[] } {
    return { tenant_id: p.tenantId, id: p.memberId, roles: [p.role] };
  }

  async list(
    p: Principal,
    q: { status?: ApprovalDto["status"]; limit: number; after?: string },
  ): Promise<Page<ApprovalDto>> {
    try {
      const svcStatus =
        q.status === undefined
          ? undefined
          : q.status === "rejected"
            ? "denied"
            : q.status === "escalated"
              ? "pending"
              : q.status;
      const rows = await this.svc.list(this.who(p), {
        limit: 200,
        ...(svcStatus ? { status: svcStatus } : {}),
      });
      const keyed = rows
        .filter((r) => q.status === undefined || apiStatus(r) === q.status)
        .map((r) => ({ key: `${String(r.created_at_ms).padStart(15, "0")}|${r.id}`, r }))
        .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
        .filter((x) => q.after === undefined || x.key > q.after);
      const slice = keyed.slice(0, q.limit);
      return {
        items: slice.map((x) => toApproval(x.r)),
        next: keyed.length > q.limit ? (slice[slice.length - 1] as { key: string }).key : undefined,
      };
    } catch (e) {
      return fromApprovalError(e);
    }
  }

  async decide(
    p: Principal,
    id: string,
    d: { decision: "approve" | "reject"; comment?: string },
  ): Promise<ApprovalDto> {
    try {
      const r =
        d.decision === "approve"
          ? await this.svc.approve(this.who(p), id, d.comment)
          : await this.svc.deny(this.who(p), id, d.comment);
      return toApproval(r);
    } catch (e) {
      return fromApprovalError(e);
    }
  }
}
