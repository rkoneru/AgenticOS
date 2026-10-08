import type { AuditEvent, AuditSink } from "@axis/contracts";
import { hashJson } from "@axis/contracts";
import { randomUUID } from "node:crypto";
import { unavailable } from "./errors.js";

export interface ComplianceAuditEntry {
  tenantId: string;
  actor: { type: "human" | "system"; id: string };
  action: string;
  decision: "ALLOW" | "DENY";
  /** `key=value` text, <= 1000 chars. Never a secret and never document content. */
  reason: string;
  /** Hashed (canonical JSON), never stored: pass non-secret metadata only. */
  inputs?: unknown;
  outputs?: unknown;
  traceId?: string;
}

/**
 * Writes service events into the TENANT's hash chain (enforcement point `admin`). An append failure throws `unavailable`: a mutation
 * whose decision cannot be recorded is not performed (fail-closed, same rule as the registry and the eval hub).
 */
export class ComplianceAudit {
  constructor(
    private readonly sink: AuditSink,
    private readonly now: () => Date = () => new Date(),
    private readonly newId: () => string = randomUUID,
  ) {}

  async record(e: ComplianceAuditEntry): Promise<AuditEvent> {
    try {
      return await this.sink.append({
        schema_version: 1,
        id: this.newId(),
        tenant_id: e.tenantId,
        ts: this.now().toISOString(),
        trace_id: e.traceId ?? randomUUID().replaceAll("-", ""),
        actor: e.actor,
        blueprint: { name: "compliance", version: "1" },
        policy_version: "compliance-v1",
        enforcement_point: "admin",
        action: e.action,
        decision: e.decision,
        reason: e.reason.slice(0, 1000),
        inputs_hash: hashJson(e.inputs ?? {}),
        outputs_hash: hashJson(e.outputs ?? {}),
      });
    } catch {
      throw unavailable("audit log unavailable");
    }
  }
}
