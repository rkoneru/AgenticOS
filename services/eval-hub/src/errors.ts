export type HubErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "invalid"
  | "integrity_failed"
  | "rate_limited"
  | "unavailable";

export const HTTP_STATUS: Record<HubErrorCode, number> = {
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  invalid: 422,
  integrity_failed: 422,
  rate_limited: 429,
  unavailable: 503,
};

/** Every refusal of the hub. `message` is safe to return to a caller (no secrets, no other tenants' data). */
export class HubError extends Error {
  constructor(
    readonly code: HubErrorCode,
    message: string,
    /** Machine-readable failed checks (integrity failures, validation paths). */
    readonly checks: readonly string[] = [],
  ) {
    super(message);
  }
  get status(): number {
    return HTTP_STATUS[this.code];
  }
}

export const forbidden = (m = "forbidden"): HubError => new HubError("forbidden", m);
export const notFound = (m = "not found"): HubError => new HubError("not_found", m);
export const invalid = (m: string, checks: readonly string[] = []): HubError =>
  new HubError("invalid", m, checks);
export const conflict = (m: string): HubError => new HubError("conflict", m);
export const unavailable = (m: string): HubError => new HubError("unavailable", m);
export const integrityFailed = (m: string, checks: readonly string[]): HubError =>
  new HubError("integrity_failed", m, checks);
