export type BillingErrorCode =
  | "INVALID"
  | "TENANT_MISMATCH"
  | "PERIOD_NOT_CLOSABLE"
  | "PERIOD_ALREADY_CLOSED"
  | "PERIOD_NOT_SEALED"
  | "LIVE_KEY_REFUSED"
  | "PROVIDER_ERROR"
  | "AUDIT_FAILED"
  | "SIGNATURE_INVALID"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "NOT_FOUND";

/** Every refusal in this package is a BillingError with a stable code; messages never contain keys or secrets. */
export class BillingError extends Error {
  constructor(
    readonly code: BillingErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "BillingError";
  }
}
