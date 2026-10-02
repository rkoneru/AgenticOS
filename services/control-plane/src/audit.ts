import { canonicalize, sha256Hex, type AuditEvent, type AuditSink } from "@axis/contracts";
import { randomUUID } from "node:crypto";
import { CpError } from "./errors.js";

export interface AdminAuditEntry {
  tenantId: string;
  actor: { type: "human" | "system"; id: string };
  action: string;
  decision: "ALLOW" | "DENY";
  policyVersion: string;
  /** `key=value` text, <= 1000 chars. Never a secret. */
  reason: string;
  /** Hashed (canonical JSON), never stored: pass non-secret metadata only. */
  inputs: unknown;
  outputs: unknown;
  traceId?: string;
}

export const CONTROL_PLANE_BLUEPRINT = { name: "control-plane", version: "1" } as const;

/**
 * Writes admin events into the TENANT's chain (enforcement point `admin`). The tenant comes from the entry, which the services
 * fill from the authenticated principal. An append failure throws `unavailable`: callers treat that as DENY for mutations.
 */
export class AdminAudit {
  constructor(
    private readonly sink: AuditSink,
    private readonly now: () => Date = () => new Date(),
    private readonly newId: () => string = randomUUID,
  ) {}

  async record(e: AdminAuditEntry): Promise<AuditEvent> {
    try {
      return await this.sink.append({
        schema_version: 1,
        id: this.newId(),
        tenant_id: e.tenantId,
        ts: this.now().toISOString(),
        trace_id: e.traceId ?? randomHex32(),
        actor: e.actor,
        blueprint: { ...CONTROL_PLANE_BLUEPRINT },
        policy_version: e.policyVersion,
        enforcement_point: "admin",
        action: e.action,
        decision: e.decision,
        reason: e.reason.slice(0, 1000),
        inputs_hash: sha256Hex(canonicalize(e.inputs ?? {})),
        outputs_hash: sha256Hex(canonicalize(e.outputs ?? {})),
      });
    } catch {
      throw new CpError("unavailable", "audit log unavailable");
    }
  }
}

function randomHex32(): string {
  return randomUUID().replaceAll("-", "");
}
