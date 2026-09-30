import { randomUUID } from "node:crypto";
import {
  canonicalize,
  sealEvent,
  validateAuditEvent,
  type AuditEvent,
  type UnsealedEvent,
} from "@axis/contracts";
import { AuditValidationError } from "./errors.js";
import type { AuditInput } from "./types.js";

const CHAIN_FIELDS = ["seq", "prev_hash", "hash"] as const;

export interface Prepared {
  event: UnsealedEvent;
  /** When the caller did not supply `ts`, idempotent replays ignore it (it is assigned, not content). */
  tsSupplied: boolean;
}

/** Seal against `prev` and validate the sealed event against the audit JSON schema. Throws AuditValidationError. */
export function sealValidated(event: UnsealedEvent, prev: AuditEvent | undefined): AuditEvent {
  let sealed: AuditEvent;
  try {
    sealed = sealEvent(event, prev);
  } catch (err) {
    // canonicalize rejects floats / undefined / non-JSON values
    throw new AuditValidationError(`audit event is not canonicalizable: ${(err as Error).message}`);
  }
  if (!validateAuditEvent(sealed)) {
    throw new AuditValidationError(
      "audit event failed schema validation",
      validateAuditEvent.errors,
    );
  }
  return sealed;
}

/**
 * Assign id/ts when absent and validate everything BEFORE any storage is touched. The event is sealed against
 * genesis purely to validate the shape; storage seals again against the real head.
 */
export function prepare(input: AuditInput, now: () => Date): Prepared {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new AuditValidationError("audit event must be an object");
  }
  for (const f of CHAIN_FIELDS) {
    if (f in input) throw new AuditValidationError(`audit event must not supply ${f}`);
  }
  const event: UnsealedEvent = {
    ...input,
    id: input.id ?? randomUUID(),
    ts: input.ts ?? now().toISOString(),
  };
  sealValidated(event, undefined);
  return { event, tsSupplied: input.ts !== undefined };
}

/** Canonical form of everything the caller controls (excludes chain fields, and ts when it was assigned). */
export function contentKey(e: AuditEvent | UnsealedEvent, includeTs: boolean): string {
  const copy: Record<string, unknown> = { ...e };
  for (const k of ["seq", "prev_hash", "hash"]) delete copy[k];
  if (!includeTs) delete copy["ts"];
  return canonicalize(copy);
}
