"""Typed error hierarchy mapped from RFC 9457 problem+json."""

from __future__ import annotations

import email.utils
import time
from dataclasses import dataclass
from typing import Any

from .redact import redact_text


@dataclass(frozen=True, slots=True)
class ResponseMeta:
    """Identifiers that tie a call to server-side logs."""

    operation_id: str
    status: int
    request_id: str | None
    trace_id: str | None
    attempts: int
    duration_s: float


class AxisError(Exception):
    """Base class of every SDK error. Messages never contain credentials."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        problem: dict[str, Any] | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(redact_text(message))
        self.status = status
        self.problem = problem
        self.request_id = request_id
        self.trace_id = trace_id or (problem.get("trace_id") if problem else None)
        self.retry_after = retry_after
        self.code = problem_slug(problem)

    @property
    def message(self) -> str:
        return str(self.args[0])


class AxisConnectionError(AxisError):
    """DNS/TLS/reset/refused redirect; the request may or may not have been processed."""


class AxisTimeoutError(AxisError):
    """The per-request timeout elapsed."""


class AxisWaitTimeoutError(AxisTimeoutError):
    """``runs.wait`` ran out of time (the run is still going)."""


class AxisApiError(AxisError):
    """The server answered with a non-2xx problem response."""


class AuthenticationError(AxisApiError): ...


class ForbiddenError(AxisApiError):
    """403 forbidden."""


class PolicyDeniedError(AxisApiError):
    """The Risk Kernel / policy gate denied the request (fail closed)."""


class ApprovalRequiredError(AxisApiError):
    """The action needs a human decision first."""

    @property
    def approval_id(self) -> str | None:
        v = (self.problem or {}).get("approval_id")
        return v if isinstance(v, str) else None


class NotFoundError(AxisApiError): ...


class ConflictError(AxisApiError): ...


class ValidationError(AxisApiError):
    @property
    def errors(self) -> list[dict[str, Any]]:
        v = (self.problem or {}).get("errors")
        return v if isinstance(v, list) else []


class RateLimitError(AxisApiError):
    """429; ``retry_after`` holds the parsed Retry-After in seconds."""


class BudgetExceededError(AxisApiError): ...


class InternalServerError(AxisApiError): ...


def problem_slug(p: dict[str, Any] | None) -> str | None:
    if not p:
        return None
    code = p.get("code")
    if isinstance(code, str) and code:
        return code
    t = p.get("type")
    if isinstance(t, str):
        seg = [s for s in t.split("/") if s][-1:]
        if seg and ":" not in seg[0]:
            return seg[0]
    return None


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Retry-After as seconds (delta-seconds or HTTP-date)."""
    if value is None:
        return None
    v = value.strip()
    if v.isdigit():
        return float(v)
    try:
        when = email.utils.parsedate_to_datetime(v).timestamp()
    except (TypeError, ValueError):
        return None
    return max(0.0, when - (time.time() if now is None else now))


_BY_SLUG: dict[str, type[AxisApiError]] = {
    "policy_denied": PolicyDeniedError,
    "approval_required": ApprovalRequiredError,
    "rate_limited": RateLimitError,
    "budget_exceeded": BudgetExceededError,
    "validation_failed": ValidationError,
    "unauthenticated": AuthenticationError,
    "forbidden": ForbiddenError,
    "not_found": NotFoundError,
    "conflict": ConflictError,
    "internal": InternalServerError,
}
_BY_STATUS: dict[int, type[AxisApiError]] = {
    401: AuthenticationError,
    403: ForbiddenError,
    404: NotFoundError,
    409: ConflictError,
    422: ValidationError,
    429: RateLimitError,
}


def error_from_problem(
    status: int,
    problem: dict[str, Any] | None,
    *,
    request_id: str | None = None,
    trace_id: str | None = None,
    retry_after: float | None = None,
) -> AxisApiError:
    slug = problem_slug(problem)
    title = (problem or {}).get("title") or f"HTTP {status}"
    detail = (problem or {}).get("detail")
    tail = f"HTTP {status}{', ' + slug if slug else ''}"
    message = f"{title}{': ' + str(detail) if detail else ''} ({tail})"
    cls = _BY_SLUG.get(slug or "")
    if cls is None:
        cls = _BY_STATUS.get(status) or (InternalServerError if status >= 500 else AxisApiError)
    return cls(
        message,
        status=status,
        problem=problem,
        request_id=request_id,
        trace_id=trace_id,
        retry_after=retry_after,
    )
