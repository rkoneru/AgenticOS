import { sealEvent, type AuditEvent, type AuditSink, type UnsealedEvent } from "@axis/contracts";

/**
 * Minimal in-memory per-tenant hash chain. DEV/TEST ONLY: nothing is durable. Production uses the audit service
 * (services/audit), which implements the same `AuditSink` interface.
 */
export class MemoryAuditSink implements AuditSink {
  readonly events = new Map<string, AuditEvent[]>();

  append(event: UnsealedEvent): Promise<AuditEvent> {
    const chain = this.events.get(event.tenant_id) ?? [];
    const sealed = sealEvent(event, chain[chain.length - 1]);
    chain.push(sealed);
    this.events.set(event.tenant_id, chain);
    return Promise.resolve(sealed);
  }
}
