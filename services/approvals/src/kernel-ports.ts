import { isApprovalValidFor, type DecisionSigner, type ExpectedAction } from "./signer.js";
import type { ApprovalService } from "./service.js";
import type { ApprovalSpecLike } from "./spec.js";
import type { Actor, DecisionRecord, RiskLevel } from "./types.js";

/**
 * Structural twins of the Risk Kernel's `ApprovalRequester` / `ApprovalVerifier` ports (this package does not import the kernel,
 * and the kernel does not import this package; the process entry point joins them).
 */
export interface KernelApprovalRequestInput {
  tenant_id: string;
  run_id: string;
  trace_id: string;
  agent: { name: string; version: string; pid?: string };
  tool: string;
  args_hash: string;
  risk_level: RiskLevel;
  requester: Actor;
  approval: ApprovalSpecLike;
  policy_version: string;
}

export interface KernelApprovalPorts {
  requester: { create(input: KernelApprovalRequestInput): Promise<{ id: string }> };
  verifier: { verify(record: unknown, expected: ExpectedAction): Promise<boolean> };
}

/** An approval is only honoured this long after it was decided (the runtime re-submits immediately). */
export const DEFAULT_MAX_APPROVAL_AGE_MS = 15 * 60_000;

const STRING_FIELDS = [
  "request_id",
  "tenant_id",
  "run_id",
  "tool",
  "args_hash",
  "outcome",
  "decision",
  "decided_by",
  "decided_at",
  "reason",
  "audit_event_id",
  "audit_hash",
  "key_id",
  "signature",
] as const;

/** Shape check for an untrusted wire record. It only guards the types; the signature is what makes it trustworthy. */
export function isDecisionRecord(v: unknown): v is DecisionRecord {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  return STRING_FIELDS.every((k) => typeof o[k] === "string") && Number.isInteger(o["level"]);
}

/**
 * Adapter from the approvals service to the kernel's ports. `verify` is `isApprovalValidFor`: a verified APPROVED record for exactly
 * the expected tenant, run, tool and arguments hash, and nothing else (denied, expired, forged, malformed, other tenant).
 */
export function kernelApprovalPorts(
  service: ApprovalService,
  signer: DecisionSigner,
  opts: { maxAgeMs?: number } = {},
): KernelApprovalPorts {
  const maxAgeMs = opts.maxAgeMs ?? DEFAULT_MAX_APPROVAL_AGE_MS;
  if (!Number.isFinite(maxAgeMs) || maxAgeMs <= 0) throw new Error("maxAgeMs must be positive");
  return {
    requester: {
      async create(input) {
        const r = await service.create(input);
        return { id: r.id };
      },
    },
    verifier: {
      async verify(record, expected) {
        return (
          isDecisionRecord(record) &&
          (await isApprovalValidFor(record, expected, signer, { nowMs: service.now(), maxAgeMs }))
        );
      },
    },
  };
}
