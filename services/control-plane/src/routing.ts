import type { AuditEvent, AuditSink, UnsealedEvent } from "@axis/contracts";
import type { AuditReaderLike } from "./admin.js";
import type { TenantRouter } from "./tenancy.js";

/** What a per-database audit log offers (a `PgAuditLog` satisfies it). */
export interface RoutableAuditLog extends AuditSink, AuditReaderLike {}

/**
 * An audit sink/reader that sends each tenant's events to the database its placement names (`TenantRouter`): shared RLS tenants
 * to the shared database, `dedicated_db` tenants to their own. The router fails closed (no placement, no pool, shared pool for a
 * dedicated tenant), so an event is never written to the wrong database; a routing failure is `unavailable`, which the admin layer
 * treats as "cannot audit, do not perform". `open(pool)` builds the per-database log; logs are cached per pool.
 */
export class RoutedAuditLog implements AuditSink, AuditReaderLike {
  private readonly logs = new Map<unknown, RoutableAuditLog>();
  constructor(
    private readonly o: {
      router: TenantRouter;
      open: (pool: Awaited<ReturnType<TenantRouter["resolve"]>>["pool"]) => RoutableAuditLog;
    },
  ) {}

  private async log(tenantId: string): Promise<RoutableAuditLog> {
    const route = await this.o.router.resolve(tenantId);
    let l = this.logs.get(route.pool);
    if (!l) {
      l = this.o.open(route.pool);
      this.logs.set(route.pool, l);
    }
    return l;
  }

  async append(event: UnsealedEvent): Promise<AuditEvent> {
    return (await this.log(event.tenant_id)).append(event);
  }

  async listEvents(
    tenantId: string,
    q: { fromSeq?: number; limit: number },
  ): Promise<AuditEvent[]> {
    return (await this.log(tenantId)).listEvents(tenantId, q);
  }
}
