import { randomBytes } from "node:crypto";
import { hashJson, type AuditEvent, type UnsealedEvent } from "@axis/contracts";
import { GovernanceError } from "./types.js";

/** What `AuditStore.append` accepts (id and ts optional). Structural, so `@axis/audit` stores satisfy it without a dependency. */
export type GovAuditInput = Omit<UnsealedEvent, "id" | "ts"> & { id?: string; ts?: string };
export interface GovAuditSink {
  append(event: GovAuditInput): Promise<AuditEvent>;
}

export interface EmitSpec {
  tenantId: string;
  action: string;
  /** Who: a human principal id (opaque IdP id) or "system". */
  actorId: string;
  actorType?: "human" | "system";
  decision?: "ALLOW" | "DENY";
  /** Short code or sentence WITHOUT personal data (checked). */
  reason?: string;
  /** Becomes `inputs_hash` (hashed, never stored raw): request id, kind, subject_ref... */
  input: Record<string, unknown>;
  /** Becomes `outputs_hash`: counts and digests. */
  output?: Record<string, unknown>;
  /** Raw identifier values that must not appear anywhere in the event. */
  raw?: readonly string[];
}

const MIN_SCAN = 4; // shorter values would false-positive inside hex digests

/** The audit-chain rule of ADR-0080: no raw personal data in an event. Throws instead of writing a leaking event. */
export function assertNoRawPii(event: GovAuditInput, raw: readonly string[]): void {
  const text = JSON.stringify(event).toLowerCase();
  for (const v of raw) {
    const needle = v.toLowerCase().trim();
    if (needle.length >= MIN_SCAN && text.includes(needle))
      throw new GovernanceError("invalid", "audit event would contain raw personal data");
  }
}

/** Writes governance events. Fail-closed: an append failure is surfaced and the caller must not proceed to mutate. */
export class GovernanceAudit {
  constructor(
    private readonly sink: GovAuditSink,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async emit(s: EmitSpec): Promise<AuditEvent> {
    const event: GovAuditInput = {
      schema_version: 1,
      tenant_id: s.tenantId,
      trace_id: randomBytes(16).toString("hex"),
      ts: this.now().toISOString(),
      actor: { type: s.actorType ?? "human", id: s.actorId },
      blueprint: { name: "data-governance", version: "1" },
      policy_version: "governance-v1",
      enforcement_point: "admin",
      action: s.action,
      decision: s.decision ?? "ALLOW",
      ...(s.reason !== undefined ? { reason: s.reason } : {}),
      inputs_hash: hashJson(s.input),
      outputs_hash: hashJson(s.output ?? {}),
    } as GovAuditInput;
    assertNoRawPii(event, s.raw ?? []);
    try {
      return await this.sink.append(event);
    } catch {
      throw new GovernanceError("unavailable", "audit append failed; refusing to proceed");
    }
  }
}
