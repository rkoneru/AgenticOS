/** RFC 9457 `application/problem+json` as the OpenAPI `Problem` schema defines it (`code` is a closed set). */
export type ProblemCode =
  | "unauthenticated"
  | "forbidden"
  | "policy_denied"
  | "not_found"
  | "conflict"
  | "validation_failed"
  | "rate_limited"
  | "budget_exceeded"
  | "internal";

export interface ValidationIssue {
  path: string;
  keyword?: string;
  message: string;
}

export const PROBLEM_BASE = "https://axis.example/problems/";

export interface Problem {
  type: string;
  title: string;
  status: number;
  code?: ProblemCode;
  detail?: string;
  trace_id?: string;
  errors?: ValidationIssue[];
}

/** Every refusal of the gateway. `detail` is safe to return to the caller (never a secret, an exception text or another tenant's data). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    /** Slug in the problem `type` URI. */
    readonly slug: string,
    readonly title: string,
    readonly code?: ProblemCode,
    readonly detail?: string,
    readonly errors?: ValidationIssue[],
    readonly headers: Record<string, string> = {},
  ) {
    super(detail ?? title);
  }
}

export const unauthenticated = (detail = "authentication required"): ApiError =>
  new ApiError(
    401,
    "unauthenticated",
    "Authentication required",
    "unauthenticated",
    detail,
    undefined,
    {
      "www-authenticate": 'Bearer realm="axis"',
    },
  );
export const forbidden = (detail = "not permitted"): ApiError =>
  new ApiError(403, "forbidden", "Forbidden", "forbidden", detail);
export const policyDenied = (detail = "the policy gate could not allow this request"): ApiError =>
  new ApiError(403, "policy_denied", "Denied by policy", "policy_denied", detail);
export const notFound = (detail = "not found"): ApiError =>
  new ApiError(404, "not_found", "Not found", "not_found", detail);
export const conflict = (detail: string): ApiError =>
  new ApiError(409, "conflict", "Conflict", "conflict", detail);
export const validation = (detail: string, errors: ValidationIssue[] = []): ApiError =>
  new ApiError(422, "validation_failed", "Validation failed", "validation_failed", detail, errors);
export const badRequest = (detail: string, slug = "bad_request"): ApiError =>
  new ApiError(400, slug, "Bad request", "validation_failed", detail);
export const tooLarge = (max: number): ApiError =>
  new ApiError(
    413,
    "payload_too_large",
    "Payload too large",
    "validation_failed",
    `request body exceeds ${max} bytes`,
  );
export const unsupportedMedia = (): ApiError =>
  new ApiError(
    415,
    "unsupported_media_type",
    "Unsupported media type",
    "validation_failed",
    "send application/json",
  );
export const methodNotAllowed = (allow: string[]): ApiError =>
  new ApiError(405, "method_not_allowed", "Method not allowed", undefined, undefined, undefined, {
    allow: allow.join(", "),
  });
export const rateLimited = (retryAfterSec: number): ApiError =>
  new ApiError(
    429,
    "rate_limited",
    "Too many requests",
    "rate_limited",
    "rate limit exceeded",
    undefined,
    {
      "retry-after": String(Math.max(1, Math.ceil(retryAfterSec))),
    },
  );
export const unavailable = (detail = "a dependency is unavailable; retry"): ApiError =>
  new ApiError(503, "unavailable", "Service unavailable", "internal", detail, undefined, {
    "retry-after": "1",
  });
export const timeout = (): ApiError =>
  new ApiError(
    504,
    "timeout",
    "Gateway timeout",
    "internal",
    "the request exceeded its time budget",
  );
export const notImplemented = (detail: string): ApiError =>
  new ApiError(501, "not_implemented", "Not implemented", undefined, detail);
export const internal = (): ApiError =>
  new ApiError(500, "internal", "Internal error", "internal", "internal error");

export function toProblem(err: ApiError, traceId: string): Problem {
  return {
    type: PROBLEM_BASE + err.slug,
    title: err.title,
    status: err.status,
    ...(err.code ? { code: err.code } : {}),
    ...(err.detail ? { detail: err.detail } : {}),
    trace_id: traceId,
    ...(err.errors ? { errors: err.errors } : {}),
  };
}
