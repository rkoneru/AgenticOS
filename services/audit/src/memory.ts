import type { AuditEvent, ChainVerdict } from "@axis/contracts";
import { assertSeq, verifyRange } from "./chain.js";
import { AuditConflictError } from "./errors.js";
import { contentKey, prepare, sealValidated } from "./prepare.js";
import { assertListQuery } from "./query.js";
import type { AuditInput, AuditStore, ListQuery, ReadRange, VerifyRange } from "./types.js";

/** In-process audit log with the same semantics as PgAuditLog (tests, local dev). Not durable. */
export class MemoryAuditLog implements AuditStore {
  protected readonly chains = new Map<string, AuditEvent[]>();
  protected readonly byId = new Map<string, AuditEvent>();
  private readonly now: () => Date;

  constructor(opts: { now?: () => Date } = {}) {
    this.now = opts.now ?? (() => new Date());
  }

  // No `await` between reading the head and pushing: each append is atomic on the event loop.
  async append(input: AuditInput): Promise<AuditEvent> {
    return this.appendSync(input);
  }

  private appendSync(input: AuditInput): AuditEvent {
    const { event, tsSupplied } = prepare(input, this.now);
    const key = `${event.tenant_id}/${event.id}`;
    const existing = this.byId.get(key);
    if (existing) {
      if (contentKey(existing, tsSupplied) !== contentKey(event, tsSupplied)) {
        throw new AuditConflictError(
          `audit event id ${event.id} already exists with different content`,
        );
      }
      return structuredClone(existing);
    }
    let chain = this.chains.get(event.tenant_id);
    if (!chain) {
      chain = [];
      this.chains.set(event.tenant_id, chain);
    }
    const sealed = sealValidated(event, chain.at(-1));
    chain.push(sealed);
    this.byId.set(key, sealed);
    return structuredClone(sealed);
  }

  async head(tenantId: string): Promise<AuditEvent | undefined> {
    const h = this.chains.get(tenantId)?.at(-1);
    return h && structuredClone(h);
  }

  async read(tenantId: string, range: ReadRange = {}): Promise<AuditEvent[]> {
    assertSeq("fromSeq", range.fromSeq);
    assertSeq("toSeq", range.toSeq);
    const from = range.fromSeq ?? 1;
    const to = range.toSeq ?? Number.MAX_SAFE_INTEGER;
    const out = (this.chains.get(tenantId) ?? []).filter((e) => e.seq >= from && e.seq <= to);
    return structuredClone(range.limit === undefined ? out : out.slice(0, range.limit));
  }

  async listEvents(tenantId: string, query: ListQuery): Promise<AuditEvent[]> {
    assertListQuery(query);
    const from = query.fromSeq ?? 1;
    const out = (this.chains.get(tenantId) ?? []).filter(
      (e) => e.seq >= from && (query.traceId === undefined || e.trace_id === query.traceId),
    );
    return structuredClone(out.slice(0, query.limit));
  }

  async verify(tenantId: string, range: VerifyRange = {}): Promise<ChainVerdict> {
    return verifyRange(this, tenantId, range);
  }
}
