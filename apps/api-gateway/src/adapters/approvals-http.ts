import { ApprovalError, type ApprovalRequest, type ErrorCode } from "@axis/approvals";

/** The slice of `ApprovalService` the gateway's `ApprovalsAdapter` uses. */
export interface ApprovalsClient {
  list(
    p: { tenant_id: string; id: string; roles: string[] },
    q?: { status?: "pending" | "approved" | "denied" | "expired"; limit?: number },
  ): Promise<ApprovalRequest[]>;
  get(p: { tenant_id: string; id: string; roles: string[] }, id: string): Promise<ApprovalRequest>;
  approve(
    p: { tenant_id: string; id: string; roles: string[] },
    id: string,
    comment?: string,
  ): Promise<ApprovalRequest>;
  deny(
    p: { tenant_id: string; id: string; roles: string[] },
    id: string,
    comment?: string,
  ): Promise<ApprovalRequest>;
}

const CODES: readonly ErrorCode[] = [
  "INVALID",
  "NOT_FOUND",
  "FORBIDDEN_ROLE",
  "SELF_APPROVAL",
  "CONFLICT_OF_INTEREST",
  "CLAIMED_BY_OTHER",
  "NOT_DECIDED",
  "ALREADY_DECIDED",
  "CONFLICT",
  "AUDIT_FAILED",
  "SIGNING_FAILED",
];

/**
 * DEV client of the approvals service's loopback bridge (`services/approvals/src/dev-bridge.ts`), which is how the Risk Kernel process
 * hosts the service today. The TENANT is the bearer's (`tokenFor(tenant)`); the principal's id and role come from the gateway's
 * authenticated principal, never from a request. Anything that is not a clean answer becomes an `ApprovalError`, which the adapter
 * maps (an unreachable service is `AUDIT_FAILED` -> 503, never a silent success).
 */
export class HttpApprovalsClient implements ApprovalsClient {
  constructor(
    private readonly baseUrl: string,
    private readonly tokenFor: (tenantId: string) => string | undefined,
    private readonly timeoutMs = 10_000,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async call(
    tenantId: string,
    route: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const token = this.tokenFor(tenantId);
    if (!token) throw new ApprovalError("AUDIT_FAILED", "no approvals credential for this tenant");
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl.replace(/\/$/, "")}/v1/approvals/${route}`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      throw new ApprovalError("AUDIT_FAILED", "the approvals service is unavailable");
    }
    let json: Record<string, unknown> | undefined;
    try {
      json = (await res.json()) as Record<string, unknown>;
    } catch {
      json = undefined;
    }
    if (res.status === 200 && json) return json;
    const err = (json?.["error"] ?? {}) as { code?: string; message?: string };
    const code = CODES.find((c) => c === err.code);
    if (code) throw new ApprovalError(code, err.message ?? code);
    throw new ApprovalError("AUDIT_FAILED", "the approvals service could not complete the request");
  }

  async list(
    p: { tenant_id: string; id: string; roles: string[] },
    q: { status?: "pending" | "approved" | "denied" | "expired"; limit?: number } = {},
  ): Promise<ApprovalRequest[]> {
    const r = await this.call(p.tenant_id, "list", {
      principal: { id: p.id, roles: p.roles },
      ...(q.status ? { status: q.status } : {}),
    });
    const items = r["requests"];
    if (!Array.isArray(items)) throw new ApprovalError("AUDIT_FAILED", "malformed answer");
    return (items as ApprovalRequest[]).slice(0, q.limit ?? 200);
  }

  async get(
    p: { tenant_id: string; id: string; roles: string[] },
    id: string,
  ): Promise<ApprovalRequest> {
    const r = await this.call(p.tenant_id, "get", { request_id: id });
    return this.one(r);
  }

  approve(
    p: { tenant_id: string; id: string; roles: string[] },
    id: string,
    comment?: string,
  ): Promise<ApprovalRequest> {
    return this.decide("approve", p, id, comment);
  }
  deny(
    p: { tenant_id: string; id: string; roles: string[] },
    id: string,
    comment?: string,
  ): Promise<ApprovalRequest> {
    return this.decide("deny", p, id, comment);
  }

  private async decide(
    route: "approve" | "deny",
    p: { tenant_id: string; id: string; roles: string[] },
    id: string,
    comment?: string,
  ): Promise<ApprovalRequest> {
    const r = await this.call(p.tenant_id, route, {
      request_id: id,
      principal: { id: p.id, roles: p.roles },
      ...(comment !== undefined ? { comment } : {}),
    });
    return this.one(r);
  }

  private one(r: Record<string, unknown>): ApprovalRequest {
    const x = r["request"];
    if (typeof x !== "object" || x === null)
      throw new ApprovalError("AUDIT_FAILED", "malformed answer");
    return x as ApprovalRequest;
  }
}
