export type ComplianceErrorCode =
  "unauthenticated" | "forbidden" | "not_found" | "conflict" | "invalid" | "unavailable";

export const HTTP_STATUS: Record<ComplianceErrorCode, number> = {
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  invalid: 422,
  unavailable: 503,
};

/** Every refusal of the service. `message` is safe to return to a caller (no secrets, no other tenants' data). */
export class ComplianceError extends Error {
  constructor(
    readonly code: ComplianceErrorCode,
    message: string,
    /** Machine-readable failed checks (validation paths). */
    readonly checks: readonly string[] = [],
  ) {
    super(message);
  }
  get status(): number {
    return HTTP_STATUS[this.code];
  }
}

export const forbidden = (m = "forbidden"): ComplianceError => new ComplianceError("forbidden", m);
export const notFound = (m = "not found"): ComplianceError => new ComplianceError("not_found", m);
export const invalid = (m: string, checks: readonly string[] = []): ComplianceError =>
  new ComplianceError("invalid", m, checks);
export const conflict = (m: string): ComplianceError => new ComplianceError("conflict", m);
export const unavailable = (m: string): ComplianceError => new ComplianceError("unavailable", m);
