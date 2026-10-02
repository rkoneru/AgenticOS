export type CpErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "invalid"
  | "region_mismatch"
  | "unavailable";

export const HTTP_STATUS: Record<CpErrorCode, number> = {
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  invalid: 422,
  region_mismatch: 421,
  unavailable: 503,
};

/** Every refusal of the control plane. `message` is safe to return to the caller (never contains secrets or other tenants' data). */
export class CpError extends Error {
  constructor(
    readonly code: CpErrorCode,
    message: string,
  ) {
    super(message);
  }
  get status(): number {
    return HTTP_STATUS[this.code];
  }
}

export const forbidden = (m = "forbidden"): CpError => new CpError("forbidden", m);
export const notFound = (m = "not found"): CpError => new CpError("not_found", m);
export const invalid = (m: string): CpError => new CpError("invalid", m);
export const conflict = (m: string): CpError => new CpError("conflict", m);
export const unauthenticated = (m = "authentication required"): CpError =>
  new CpError("unauthenticated", m);
