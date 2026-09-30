import type { AuditEvent, UnsealedEvent } from "../src/index.js";

export const T1 = "11111111-1111-4111-8111-111111111111";
export const T2 = "22222222-2222-4222-8222-222222222222";

export function unsealed(tenant: string, n: number): UnsealedEvent {
  return {
    schema_version: 1,
    id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    tenant_id: tenant,
    ts: `2026-01-01T00:00:${String(n % 60).padStart(2, "0")}.000Z`,
    trace_id: "a".repeat(32),
    actor: { type: "agent", id: "claims-triage", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    blueprint: { name: "claims-triage", version: "1.0.0" },
    policy_version: "baseline-deny@1.0.0",
    enforcement_point: "tool_call",
    action: "lookup-policy",
    decision: "ALLOW",
    inputs_hash: "b".repeat(64),
    outputs_hash: "c".repeat(64),
  };
}

export function chain(
  tenant: string,
  length: number,
  seal: (e: UnsealedEvent, p: AuditEvent | undefined) => AuditEvent,
): AuditEvent[] {
  const out: AuditEvent[] = [];
  for (let i = 1; i <= length; i++) out.push(seal(unsealed(tenant, i), out[i - 2]));
  return out;
}
