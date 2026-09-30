import type { AuditEvent, UnsealedEvent } from "./audit-chain.js";

/**
 * The only way components write audit events. Implementations assign `seq`, `prev_hash` and `hash`
 * (per-tenant chain) and MUST NOT acknowledge before the event is durably appended.
 * Callers on the decision path treat a rejected append as DENY (fail-closed).
 */
export interface AuditSink {
  append(event: UnsealedEvent): Promise<AuditEvent>;
}
