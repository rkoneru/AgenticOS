import { randomBytes, randomUUID } from "node:crypto";
import { MemoryAuditLog, createAuditReader, type AuditInput } from "@axis/audit";

export const PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV";
export const hex32 = (): string => randomBytes(16).toString("hex");
const h64 = (): string => randomBytes(32).toString("hex");

export function ev(tenantId: string, over: Partial<AuditInput> = {}): AuditInput {
  return {
    schema_version: 1,
    tenant_id: tenantId,
    trace_id: hex32(),
    actor: { type: "agent", id: "claims", pid: PID },
    blueprint: { name: "claims", version: "1.0.0" },
    policy_version: "tenant-acme@1.0.0",
    enforcement_point: "tool_call",
    action: "lookup-claim",
    decision: "ALLOW",
    reason: "tenant-acme/allow-reads",
    inputs_hash: h64(),
    outputs_hash: h64(),
    ...over,
  };
}

export function world() {
  const log = new MemoryAuditLog();
  return { log, reader: createAuditReader(log), tenant: randomUUID(), other: randomUUID() };
}
