export type RegistryErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "invalid"
  | "verification_failed"
  | "rate_limited"
  | "unavailable";

export const HTTP_STATUS: Record<RegistryErrorCode, number> = {
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  invalid: 422,
  verification_failed: 422,
  rate_limited: 429,
  unavailable: 503,
};

/** Every refusal of the registry. `message` is safe to return to a caller (no secrets, no other tenants' data). */
export class RegistryError extends Error {
  constructor(
    readonly code: RegistryErrorCode,
    message: string,
    /** Machine-readable failed checks, for `verification_failed`. */
    readonly checks: readonly string[] = [],
  ) {
    super(message);
  }
  get status(): number {
    return HTTP_STATUS[this.code];
  }
}

export const forbidden = (m = "forbidden"): RegistryError => new RegistryError("forbidden", m);
export const notFound = (m = "not found"): RegistryError => new RegistryError("not_found", m);
export const invalid = (m: string): RegistryError => new RegistryError("invalid", m);
export const conflict = (m: string): RegistryError => new RegistryError("conflict", m);
export const unavailable = (m: string): RegistryError => new RegistryError("unavailable", m);
