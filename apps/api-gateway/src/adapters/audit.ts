import { createAuditReader, type AuditReader } from "@axis/audit";
import { Explainer, type PolicyMetadataSource } from "@axis/agil";
import type { AuditEvent, ChainVerdict } from "@axis/contracts";
import type { AuditPort, ExplainPort, RunEventDto } from "../ports.js";
import { PortUnavailable } from "../ports.js";

/** What the gateway needs of an audit store: reads, the chain head and chain verification (PgAuditLog and MemoryAuditLog fit). */
export interface AuditStoreLike extends AuditReader {
  head(tenantId: string): Promise<AuditEvent | undefined>;
  verify(tenantId: string, range?: { fromSeq?: number; toSeq?: number }): Promise<ChainVerdict>;
}

export class AuditAdapter implements AuditPort {
  constructor(private readonly store: AuditStoreLike) {}

  async list(
    tenantId: string,
    q: { fromSeq?: number; traceId?: string; limit: number },
  ): Promise<AuditEvent[]> {
    try {
      return await this.store.listEvents(tenantId, {
        limit: q.limit,
        ...(q.fromSeq !== undefined ? { fromSeq: q.fromSeq } : {}),
        ...(q.traceId ? { traceId: q.traceId } : {}),
      });
    } catch {
      throw new PortUnavailable("the audit log is unavailable; retry");
    }
  }

  async head(tenantId: string): Promise<number> {
    try {
      return (await this.store.head(tenantId))?.seq ?? 0;
    } catch {
      throw new PortUnavailable("the audit log is unavailable; retry");
    }
  }

  async verify(
    tenantId: string,
    range: { fromSeq?: number; toSeq?: number },
  ): Promise<ChainVerdict> {
    try {
      return await this.store.verify(tenantId, range);
    } catch {
      throw new PortUnavailable("the audit log is unavailable; retry");
    }
  }
}

/**
 * AGIL behind the gateway. The explainer is constructed with `createAuditReader(store)`: a frozen, `listEvents`-only view. It never
 * receives the gate, the kernel or any writable store, so it cannot be on the decision path (invariant 2).
 */
export class AgilExplain implements ExplainPort {
  private readonly explainer: Explainer;
  constructor(store: AuditReader, policies?: PolicyMetadataSource) {
    this.explainer = new Explainer({
      audit: createAuditReader(store),
      ...(policies ? { policies } : {}),
    });
  }

  explainRun(tenantId: string, q: { traceId: string; runEvents: RunEventDto[] }): Promise<unknown> {
    return this.explainer.explainRun(tenantId, {
      traceId: q.traceId,
      runEvents: q.runEvents.map((e) => ({
        sequence: e.sequence,
        type: e.type,
        pid: e.pid,
        at: e.at,
        ...(e.data ? { data: e.data } : {}),
      })),
    });
  }

  explainEvent(tenantId: string, seq: number): Promise<unknown | undefined> {
    return this.explainer.explainEvent(tenantId, seq);
  }
}
