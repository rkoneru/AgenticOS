import type { ApprovalRequest, ApprovalStatus } from "./types.js";

export interface ListFilter {
  status?: ApprovalStatus;
  limit: number;
}

/**
 * Persistence port. EVERY method except `listDue` is scoped by tenant: there is no query path without a tenant.
 * `listDue` is the system sweeper's cross-tenant view and returns only identifiers.
 * Writes are compare-and-set on `version` so a stale writer can never overwrite a decided request.
 */
export interface ApprovalStore {
  insert(r: ApprovalRequest): Promise<void>;
  get(tenantId: string, id: string): Promise<ApprovalRequest | undefined>;
  findByIdempotencyKey(tenantId: string, key: string): Promise<ApprovalRequest | undefined>;
  /** Replace the stored request iff its stored version equals `expectedVersion`. Returns false otherwise. */
  compareAndSet(next: ApprovalRequest, expectedVersion: number): Promise<boolean>;
  list(tenantId: string, filter: ListFilter): Promise<ApprovalRequest[]>;
  listDue(nowMs: number, limit: number): Promise<{ tenant_id: string; id: string }[]>;
}

/**
 * In-memory store. NOT durable and single-instance: a restart loses pending approvals (which then never resolve, and
 * callers treat that as DENY). The Postgres `approvals` table (packages/db 0002) lacks requester, args_hash, level and
 * risk columns, so a durable store needs a migration + ADR: docs/NEEDS.md #41.
 */
export class MemoryApprovalStore implements ApprovalStore {
  private readonly byTenant = new Map<string, Map<string, ApprovalRequest>>();
  private readonly keys = new Map<string, string>();

  async insert(r: ApprovalRequest): Promise<void> {
    const t = this.byTenant.get(r.tenant_id) ?? new Map<string, ApprovalRequest>();
    if (t.has(r.id)) throw new Error("duplicate approval id");
    t.set(r.id, structuredClone(r));
    this.byTenant.set(r.tenant_id, t);
    if (r.idempotency_key !== null) this.keys.set(`${r.tenant_id}\u0000${r.idempotency_key}`, r.id);
  }

  async get(tenantId: string, id: string): Promise<ApprovalRequest | undefined> {
    const r = this.byTenant.get(tenantId)?.get(id);
    return r && structuredClone(r);
  }

  async findByIdempotencyKey(tenantId: string, key: string): Promise<ApprovalRequest | undefined> {
    const id = this.keys.get(`${tenantId}\u0000${key}`);
    return id === undefined ? undefined : this.get(tenantId, id);
  }

  async compareAndSet(next: ApprovalRequest, expectedVersion: number): Promise<boolean> {
    const t = this.byTenant.get(next.tenant_id);
    const cur = t?.get(next.id);
    if (!t || !cur || cur.version !== expectedVersion) return false;
    t.set(next.id, structuredClone(next));
    return true;
  }

  async list(tenantId: string, filter: ListFilter): Promise<ApprovalRequest[]> {
    const all = [...(this.byTenant.get(tenantId)?.values() ?? [])]
      .filter((r) => filter.status === undefined || r.status === filter.status)
      .sort((a, b) => a.created_at_ms - b.created_at_ms || (a.id < b.id ? -1 : 1));
    return structuredClone(all.slice(0, filter.limit));
  }

  async listDue(nowMs: number, limit: number): Promise<{ tenant_id: string; id: string }[]> {
    const out: { tenant_id: string; id: string }[] = [];
    for (const t of this.byTenant.values()) {
      for (const r of t.values()) {
        if (r.status === "pending" && r.deadline_ms <= nowMs) {
          out.push({ tenant_id: r.tenant_id, id: r.id });
          if (out.length >= limit) return out;
        }
      }
    }
    return out;
  }
}
