import type { ApprovalSpec } from "./types.js";

/**
 * Ports through which the kernel talks to the approvals service. They are structural so this package does not import
 * `@axis/approvals` (the glue lives in the process entry point). Both are OPTIONAL: with neither injected a
 * REQUIRE_APPROVAL policy outcome is returned with an empty `approval_id`, which clients treat as DENY (fail-closed).
 */
export interface ApprovalRequestInput {
  tenant_id: string;
  run_id: string;
  trace_id: string;
  agent: { name: string; version: string; pid?: string };
  tool: string;
  /** SHA-256 hex of the canonical `context.args`, computed by the kernel (never taken from the caller). */
  args_hash: string;
  risk_level: "low" | "medium" | "high" | "critical";
  requester: { type: "human" | "agent" | "system"; id: string; pid?: string };
  approval: ApprovalSpec;
  policy_version: string;
}

export interface ApprovalRequester {
  /** Opens an approval request (audited in the tenant's chain by the service). Any rejection makes the kernel DENY. */
  create(input: ApprovalRequestInput): Promise<{ id: string }>;
}

/** What an approval must be bound to: exactly this tenant, run, tool and argument hash. */
export interface ExpectedApproval {
  tenant_id: string;
  run_id: string;
  tool: string;
  args_hash: string;
}

export interface ApprovalVerifier {
  /**
   * True only for a signed, APPROVED decision record for exactly `expected`. `record` is untrusted wire data. A false
   * answer or a throw both mean "not approved".
   */
  verify(record: unknown, expected: ExpectedApproval): Promise<boolean>;
}

/** Single-use ledger: an approval authorises ONE re-gated execution. */
export interface ConsumedApprovals {
  /** True if this call consumed it; false if it was already consumed. Tenant-scoped. */
  consume(tenantId: string, requestId: string): Promise<boolean>;
  /** Undo a consume when the decision could not be recorded (audit failure) so the approval is not burned. */
  release(tenantId: string, requestId: string): Promise<void>;
}

/** In-memory, single-instance. A kernel restart forgets consumption (docs/NEEDS.md: durable consumed-approval store). */
export class MemoryConsumedApprovals implements ConsumedApprovals {
  private readonly used = new Set<string>();
  private static key(tenantId: string, requestId: string): string {
    return JSON.stringify([tenantId, requestId]);
  }
  consume(tenantId: string, requestId: string): Promise<boolean> {
    const k = MemoryConsumedApprovals.key(tenantId, requestId);
    if (this.used.has(k)) return Promise.resolve(false);
    this.used.add(k);
    return Promise.resolve(true);
  }
  release(tenantId: string, requestId: string): Promise<void> {
    this.used.delete(MemoryConsumedApprovals.key(tenantId, requestId));
    return Promise.resolve();
  }
}
