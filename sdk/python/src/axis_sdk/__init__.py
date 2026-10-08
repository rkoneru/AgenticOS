"""AXIS Python SDK: a generated typed layer plus an ergonomic client on top."""

from __future__ import annotations

from ._generated.models import *  # noqa: F403 - re-export the wire types
from ._generated.operations import API_VERSION, DEFAULT_BASE_URL, OPERATIONS, OperationSpec
from .client import AsyncAxis, Axis, parse_blueprint_ref, parse_eval_blueprint
from .errors import (
    ApprovalRequiredError,
    AuthenticationError,
    AxisApiError,
    AxisConnectionError,
    AxisError,
    AxisTimeoutError,
    AxisWaitTimeoutError,
    BudgetExceededError,
    ConflictError,
    ForbiddenError,
    InternalServerError,
    NotFoundError,
    PolicyDeniedError,
    RateLimitError,
    ResponseMeta,
    ValidationError,
    error_from_problem,
)
from .pagination import apaginate, paginate
from .redact import REDACTED, Secret, redact_text
from .sse import SseEvent, SseParser
from .transport import AsyncHttpTransport, HttpTransport, TransportConfig, normalize_base_url
from .transport_types import RequestOptions

__version__ = "0.1.0"

__all__ = [
    "API_VERSION",
    "DEFAULT_BASE_URL",
    "OPERATIONS",
    "REDACTED",
    "ApprovalRequiredError",
    "AsyncAxis",
    "AsyncHttpTransport",
    "AuthenticationError",
    "Axis",
    "AxisApiError",
    "AxisConnectionError",
    "AxisError",
    "AxisTimeoutError",
    "AxisWaitTimeoutError",
    "BudgetExceededError",
    "ConflictError",
    "ForbiddenError",
    "HttpTransport",
    "InternalServerError",
    "NotFoundError",
    "OperationSpec",
    "PolicyDeniedError",
    "RateLimitError",
    "RequestOptions",
    "ResponseMeta",
    "Secret",
    "SseEvent",
    "SseParser",
    "TransportConfig",
    "ValidationError",
    "apaginate",
    "error_from_problem",
    "normalize_base_url",
    "paginate",
    "parse_blueprint_ref",
    "parse_eval_blueprint",
    "redact_text",
]
