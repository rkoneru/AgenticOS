from __future__ import annotations

import copy
import pickle  # noqa: S403 - proves pickling does not carry the secret
from typing import Any

import httpx
import pytest
from axis_mock_server import MockServer
from axis_sdk import (
    ApprovalRequiredError,
    AuthenticationError,
    Axis,
    AxisApiError,
    AxisConnectionError,
    AxisError,
    BudgetExceededError,
    ConflictError,
    ForbiddenError,
    InternalServerError,
    NotFoundError,
    PolicyDeniedError,
    RateLimitError,
    Secret,
    ValidationError,
    error_from_problem,
    redact_text,
)
from axis_sdk.errors import parse_retry_after

KEY = "axk_live_SUPERSECRET0123456789"


def test_secret_never_reveals() -> None:
    s = Secret(KEY)
    for out in (
        repr(s),
        str(s),
        f"{s}",
        repr({"s": s}),
        repr([s]),
        str(pickle.dumps(s)),
        repr(copy.deepcopy(s)),
    ):  # noqa: S301
        assert "SUPERSECRET" not in out
    assert s.reveal() == KEY
    assert s == Secret(KEY)
    assert s != Secret("other")
    assert hash(s) == hash(Secret("other"))
    assert pickle.loads(pickle.dumps(s)).reveal() == "[REDACTED]"  # noqa: S301


def test_redact_text() -> None:
    t = redact_text(f"boom {KEY} Bearer abc.def-ghi x-axis-api-key: zzz999", [KEY])
    assert "SUPERSECRET" not in t and "abc.def" not in t and "zzz999" not in t
    assert redact_text("short", ["ab"]) == "short"


def test_client_transport_and_errors_never_expose_the_key() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"fail with {KEY}", request=request)

    ax = Axis(
        KEY,
        base_url="https://api.x.test/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(boom)),
    )
    for out in (repr(ax), str(ax), repr(ax._transport), repr(ax._transport._core.config)):
        assert "SUPERSECRET" not in out
    with pytest.raises(AxisConnectionError) as ei:
        ax.runs.get("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f")
    blob = (
        repr(ei.value)
        + str(ei.value)
        + repr(ei.value.__cause__)
        + repr(ei.value.__context__ and ei.value.__context__.args)
    )
    assert "SUPERSECRET" not in str(ei.value) and "SUPERSECRET" not in repr(ei.value)
    assert ei.value.__cause__ is None
    assert isinstance(blob, str)


def test_error_message_scrubs_credential_shaped_text() -> None:
    assert "top.secret" not in AxisError("auth failed: Bearer top.secret.token").message


def _p(code: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": f"https://axis.example/problems/{code}",
        "title": "T",
        "status": 400,
        "code": code,
        **extra,
    }


@pytest.mark.parametrize(
    ("status", "code", "cls"),
    [
        (403, "policy_denied", PolicyDeniedError),
        (403, "approval_required", ApprovalRequiredError),
        (429, "rate_limited", RateLimitError),
        (402, "budget_exceeded", BudgetExceededError),
        (422, "validation_failed", ValidationError),
        (401, "unauthenticated", AuthenticationError),
        (403, "forbidden", ForbiddenError),
        (404, "not_found", NotFoundError),
        (409, "conflict", ConflictError),
        (500, "internal", InternalServerError),
    ],
)
def test_problem_mapping(status: int, code: str, cls: type[AxisApiError]) -> None:
    e = error_from_problem(status, _p(code), request_id="r1", trace_id="t1")
    assert type(e) is cls
    assert isinstance(e, AxisApiError)
    assert (e.code, e.request_id, e.trace_id, e.status) == (code, "r1", "t1", status)


def test_status_fallbacks_and_type_uri_slug() -> None:
    for status, cls in [
        (401, AuthenticationError),
        (403, ForbiddenError),
        (404, NotFoundError),
        (409, ConflictError),
        (422, ValidationError),
        (429, RateLimitError),
        (503, InternalServerError),
        (418, AxisApiError),
    ]:
        assert type(error_from_problem(status, None)) is cls
    assert (
        type(
            error_from_problem(
                403,
                {
                    "type": "https://axis.example/problems/policy_denied",
                    "title": "x",
                    "status": 403,
                },
            )
        )
        is PolicyDeniedError
    )
    assert (
        error_from_problem(400, {"type": "about:blank", "title": "x", "status": 400}).code is None
    )


def test_problem_extensions() -> None:
    v = error_from_problem(
        422, _p("validation_failed", errors=[{"path": "/abl", "message": "bad"}])
    )
    assert isinstance(v, ValidationError) and v.errors == [{"path": "/abl", "message": "bad"}]
    assert error_from_problem(422, _p("validation_failed")).errors == []  # type: ignore[attr-defined]
    a = error_from_problem(403, _p("approval_required", approval_id="ap-1"))
    assert isinstance(a, ApprovalRequiredError) and a.approval_id == "ap-1"
    assert error_from_problem(403, _p("approval_required")).approval_id is None  # type: ignore[attr-defined]
    r = error_from_problem(429, _p("rate_limited", trace_id="tb"), retry_after=7)
    assert r.retry_after == 7 and r.trace_id == "tb" and "HTTP 429" in r.message


def test_retry_after_parsing() -> None:
    assert parse_retry_after(None) is None
    assert parse_retry_after("5") == 5
    assert parse_retry_after("garbage") is None
    assert parse_retry_after("Thu, 01 Jan 1970 00:00:10 GMT", now=4) == 6
    assert parse_retry_after("Thu, 01 Jan 1970 00:00:01 GMT", now=4) == 0


def test_401_maps_to_authentication_error() -> None:
    server = MockServer(overrides={"getRun": lambda c, n: None})
    ax = Axis(
        "",
        base_url=server.base_url,
        token="tok_abc_123456",
        http_client=httpx.Client(transport=server.transport()),
    )
    ax.runs.get("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f")
    assert server.calls[0].headers["authorization"] == "Bearer tok_abc_123456"
    assert "x-axis-api-key" not in server.calls[0].headers
