import { redactText } from "./redact.js";

/** Identifiers that tie a failure to server-side logs. */
export interface ResponseMeta {
  operationId: string;
  status: number;
  requestId: string | undefined;
  traceId: string | undefined;
  /** Number of HTTP attempts made (1 means no retry). */
  attempts: number;
  durationMs: number;
}

/** RFC 9457 problem document (axis-v1 `Problem`, plus the validation `errors` extension). */
export interface ProblemDetails {
  type?: string;
  title?: string;
  status?: number;
  code?: string;
  detail?: string;
  trace_id?: string;
  errors?: Array<{ path: string; keyword?: string; message: string }>;
  [extension: string]: unknown;
}

export interface ErrorInit {
  status?: number;
  problem?: ProblemDetails;
  requestId?: string | undefined;
  traceId?: string | undefined;
  cause?: unknown;
  retryAfterSeconds?: number | undefined;
}

/** Base class of every error thrown by the SDK. Messages never contain credentials. */
export class AxisError extends Error {
  readonly status: number | undefined;
  readonly problem: ProblemDetails | undefined;
  readonly requestId: string | undefined;
  readonly traceId: string | undefined;
  /** Stable machine-readable slug (problem `code`, else the last segment of problem `type`). */
  readonly code: string | undefined;

  constructor(message: string, init: ErrorInit = {}) {
    super(redactText(message), init.cause === undefined ? undefined : { cause: init.cause });
    this.name = new.target.name;
    this.status = init.status;
    this.problem = init.problem;
    this.requestId = init.requestId;
    this.traceId = init.traceId ?? init.problem?.trace_id;
    this.code = problemSlug(init.problem);
  }
}

/** Transport failure: DNS, TLS, reset, refused redirect. The request may or may not have been processed. */
export class AxisConnectionError extends AxisError {}
/** The per-request timeout elapsed. */
export class AxisTimeoutError extends AxisError {}
/** The caller's AbortSignal fired. */
export class AxisAbortError extends AxisError {}
/** `runs.wait` ran out of time (the run is still going). */
export class AxisWaitTimeoutError extends AxisTimeoutError {}
/** The server answered with a non-2xx problem response. */
export class AxisApiError extends AxisError {}
export class AuthenticationError extends AxisApiError {}
export class PermissionError extends AxisApiError {}
/** The Risk Kernel / policy gate denied the request (fail closed; also when it could not be evaluated). */
export class PolicyDeniedError extends AxisApiError {}
/** The action needs a human decision first. `approvalId` is set when the problem carries one. */
export class ApprovalRequiredError extends AxisApiError {
  readonly approvalId: string | undefined;
  constructor(message: string, init: ErrorInit = {}) {
    super(message, init);
    const id = init.problem?.["approval_id"];
    this.approvalId = typeof id === "string" ? id : undefined;
  }
}
export class NotFoundError extends AxisApiError {}
export class ConflictError extends AxisApiError {}
export class ValidationError extends AxisApiError {
  get errors(): NonNullable<ProblemDetails["errors"]> {
    return this.problem?.errors ?? [];
  }
}
export class RateLimitError extends AxisApiError {
  /** Parsed `Retry-After`, in seconds. */
  readonly retryAfterSeconds: number | undefined;
  constructor(message: string, init: ErrorInit = {}) {
    super(message, init);
    this.retryAfterSeconds = init.retryAfterSeconds;
  }
}
export class BudgetExceededError extends AxisApiError {}
export class InternalServerError extends AxisApiError {}

export function problemSlug(p: ProblemDetails | undefined): string | undefined {
  if (!p) return undefined;
  if (typeof p.code === "string" && p.code) return p.code;
  if (typeof p.type === "string") {
    const seg = p.type.split("/").filter(Boolean).pop();
    if (seg && !seg.includes(":")) return seg;
  }
  return undefined;
}

/** Parse `Retry-After` (delta-seconds or HTTP-date) to seconds, or undefined. */
export function parseRetryAfter(
  value: string | null,
  now: number = Date.now(),
): number | undefined {
  if (value === null) return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v);
  const at = Date.parse(v);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now) / 1000));
}

/** Map a problem response to the typed hierarchy. */
export function errorFromProblem(
  status: number,
  problem: ProblemDetails | undefined,
  ids: {
    requestId?: string | undefined;
    traceId?: string | undefined;
    retryAfterSeconds?: number | undefined;
  },
): AxisApiError {
  const init: ErrorInit = {
    status,
    requestId: ids.requestId,
    traceId: ids.traceId,
    retryAfterSeconds: ids.retryAfterSeconds,
  };
  if (problem) init.problem = problem;
  const slug = problemSlug(problem);
  const title = problem?.title ?? `HTTP ${status}`;
  const message = `${title}${problem?.detail ? `: ${problem.detail}` : ""} (HTTP ${status}${slug ? `, ${slug}` : ""})`;
  switch (slug) {
    case "policy_denied":
      return new PolicyDeniedError(message, init);
    case "approval_required":
      return new ApprovalRequiredError(message, init);
    case "rate_limited":
      return new RateLimitError(message, init);
    case "budget_exceeded":
      return new BudgetExceededError(message, init);
    case "validation_failed":
      return new ValidationError(message, init);
    case "unauthenticated":
      return new AuthenticationError(message, init);
    case "forbidden":
      return new PermissionError(message, init);
    case "not_found":
      return new NotFoundError(message, init);
    case "conflict":
      return new ConflictError(message, init);
    case "internal":
      return new InternalServerError(message, init);
    default:
  }
  if (status === 401) return new AuthenticationError(message, init);
  if (status === 403) return new PermissionError(message, init);
  if (status === 404) return new NotFoundError(message, init);
  if (status === 409) return new ConflictError(message, init);
  if (status === 422) return new ValidationError(message, init);
  if (status === 429) return new RateLimitError(message, init);
  if (status >= 500) return new InternalServerError(message, init);
  return new AxisApiError(message, init);
}
