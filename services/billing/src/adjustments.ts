import { randomBytes, randomUUID } from "node:crypto";
import { hashJson, type AuditSink } from "@axis/contracts";
import { BillingError } from "./errors.js";
import type { UsageLedger } from "./ledger.js";
import type { AppendResult, Dimensions, Meter } from "./types.js";

export interface AdjustmentRequest {
  tenantId: string;
  idempotencyKey: string;
  meter: Meter;
  /** Signed, non-zero. Negative reduces what is billed. */
  quantity: bigint;
  eventTime: Date;
  dimensions?: Dimensions;
  reason: string;
  /** Who is asking (an authenticated admin id). Recorded in the ledger and the audit chain. */
  actor: string;
  correctsKey?: string;
}

/**
 * The ONLY way to change what a tenant is billed after the fact: a compensating ledger entry with a reason, written after the audit
 * event (no audit, no change). Reconciliation reports; it never calls this.
 */
export class AdjustmentApi {
  constructor(
    private readonly o: {
      ledger: UsageLedger;
      audit: AuditSink;
      now?: () => Date;
      policyVersion?: string;
    },
  ) {}

  async adjust(r: AdjustmentRequest): Promise<AppendResult> {
    if (typeof r.reason !== "string" || r.reason.trim().length < 3)
      throw new BillingError("INVALID", "an adjustment needs a reason");
    if (typeof r.actor !== "string" || r.actor === "")
      throw new BillingError("INVALID", "an adjustment needs an actor");
    const now = (this.o.now ?? (() => new Date()))();
    try {
      await this.o.audit.append({
        schema_version: 1,
        id: randomUUID(),
        tenant_id: r.tenantId,
        ts: now.toISOString(),
        trace_id: randomBytes(16).toString("hex"),
        actor: { type: "human", id: r.actor },
        blueprint: { name: "billing", version: "1" },
        policy_version: this.o.policyVersion ?? "billing-1",
        enforcement_point: "lifecycle",
        action: "billing.usage.adjust",
        decision: "ALLOW",
        reason:
          `meter=${r.meter} quantity=${r.quantity} key=${r.idempotencyKey} reason=${r.reason}`.slice(
            0,
            1000,
          ),
        inputs_hash: hashJson({
          meter: r.meter,
          quantity: r.quantity.toString(),
          key: r.idempotencyKey,
          corrects: r.correctsKey ?? null,
        }),
        outputs_hash: hashJson({ requested: true }),
      });
    } catch {
      throw new BillingError("AUDIT_FAILED", "audit append failed: adjustment not applied");
    }
    return this.o.ledger.append({
      entryType: "adjustment",
      tenantId: r.tenantId,
      idempotencyKey: r.idempotencyKey,
      meter: r.meter,
      quantity: r.quantity,
      eventTime: r.eventTime,
      ...(r.dimensions ? { dimensions: r.dimensions } : {}),
      source: "adjustment-api",
      reason: r.reason,
      actor: r.actor,
      ...(r.correctsKey ? { correctsKey: r.correctsKey } : {}),
    });
  }
}
