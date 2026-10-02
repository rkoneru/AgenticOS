from __future__ import annotations

from typing import Any

import httpx
import pytest
from axis_sdk import (
    OPERATIONS,
    AsyncAxis,
    AsyncHttpTransport,
    Axis,
    AxisConnectionError,
    AxisError,
    AxisTimeoutError,
    HttpTransport,
    RateLimitError,
    RequestOptions,
    ResponseMeta,
    TransportConfig,
    normalize_base_url,
)
from axis_sdk.transport import is_retriable
from mock_server import MockServer, problem

KEY = "axk_test_key_123456"
RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"
BASE = "https://api.test.axis.example/v1"


def make(server: MockServer, **kw: Any) -> tuple[Axis, list[float]]:
    sleeps: list[float] = []
    ax = Axis(
        KEY,
        base_url=server.base_url,
        http_client=httpx.Client(transport=server.transport()),
        sleep=sleeps.append,
        random=lambda: 0.5,
        **kw,
    )
    return ax, sleeps


def fail_first(n: int, status: int = 503, headers: dict[str, str] | None = None) -> Any:
    return lambda c, k: problem(status, "internal", headers) if k <= n else None


def test_idempotent_get_retries_with_exponential_jittered_backoff() -> None:
    server = MockServer(overrides={"getRun": fail_first(2)})
    ax, sleeps = make(server)
    ax.runs.get(RUN)
    assert len(server.calls) == 3
    assert sleeps == [0.25, 0.5]


def test_gives_up_after_max_retries() -> None:
    server = MockServer(overrides={"getRun": fail_first(99)})
    ax, _ = make(server, max_retries=1)
    with pytest.raises(AxisError) as ei:
        ax.runs.get(RUN)
    assert ei.value.status == 503
    assert len(server.calls) == 2


def test_retry_after_is_honoured_and_surfaced() -> None:
    server = MockServer(
        overrides={
            "getRun": lambda c, k: (
                problem(429, "rate_limited", {"retry-after": "3"}) if k == 1 else None
            )
        }
    )
    ax, sleeps = make(server)
    ax.runs.get(RUN)
    assert sleeps == [3.0]
    server2 = MockServer(
        overrides={"getRun": lambda c, k: problem(429, "rate_limited", {"retry-after": "9"})}
    )
    ax2, _ = make(server2, max_retries=0)
    with pytest.raises(RateLimitError) as ei:
        ax2.runs.get(RUN)
    assert ei.value.retry_after == 9


def test_post_without_idempotency_capability_is_never_retried() -> None:
    server = MockServer(overrides={"publishPolicyPack": fail_first(5)})
    ax, _ = make(server)
    with pytest.raises(AxisError):
        ax.policies.publish({})
    assert len(server.calls) == 1


def test_non_idempotent_post_is_not_retried_on_network_error() -> None:
    n = 0

    def boom(request: httpx.Request) -> httpx.Response:
        nonlocal n
        n += 1
        raise httpx.ReadError("reset", request=request)

    ax = Axis(
        KEY,
        base_url=BASE,
        sleep=lambda _s: None,
        http_client=httpx.Client(transport=httpx.MockTransport(boom)),
    )
    with pytest.raises(AxisConnectionError):
        ax.policies.publish({})
    assert n == 1


def test_keyed_post_retries_and_reuses_one_key() -> None:
    server = MockServer(overrides={"startRun": fail_first(2, 502)})
    ax, _ = make(server)
    ax.runs.start("agent-one@1.0.0")
    assert len(server.calls) == 3
    keys = {c.headers["idempotency-key"] for c in server.calls}
    assert len(keys) == 1 and next(iter(keys))


def test_each_logical_call_gets_a_fresh_key() -> None:
    server = MockServer()
    ax, _ = make(server)
    ax.runs.start("agent-one@1.0.0")
    ax.runs.start("agent-one@1.0.0")
    assert server.calls[0].headers["idempotency-key"] != server.calls[1].headers["idempotency-key"]


def test_read_only_posts_and_put_are_retried() -> None:
    s1 = MockServer(overrides={"testPolicy": fail_first(1)})
    make(s1)[0].policies.test({}, {"enforcement_point": "tool_call", "context": {}})
    assert len(s1.calls) == 2
    s2 = MockServer(overrides={"setKillSwitch": fail_first(1)})
    make(s2)[0].kill_switches.engage("tenant")
    assert len(s2.calls) == 2


def test_4xx_is_never_retried() -> None:
    server = MockServer(overrides={"getRun": lambda c, k: problem(403, "policy_denied")})
    ax, _ = make(server)
    with pytest.raises(AxisError):
        ax.runs.get(RUN)
    assert len(server.calls) == 1


def test_network_errors_retry_for_idempotent_calls_and_per_call_override() -> None:
    server = MockServer()
    n = 0

    def flaky(request: httpx.Request) -> httpx.Response:
        nonlocal n
        n += 1
        if n < 2:
            raise httpx.ConnectError("down", request=request)
        return server.handle(request)

    ax = Axis(
        KEY,
        base_url=server.base_url,
        sleep=lambda _s: None,
        http_client=httpx.Client(transport=httpx.MockTransport(flaky)),
    )
    ax.runs.get(RUN)
    assert n == 2
    s2 = MockServer(overrides={"getRun": fail_first(9)})
    ax2, _ = make(s2)
    with pytest.raises(AxisError):
        ax2.runs.get(RUN, options=RequestOptions(max_retries=0))
    assert len(s2.calls) == 1


def test_timeout_maps_to_timeout_error() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    ax = Axis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(slow)),
    )
    with pytest.raises(AxisTimeoutError):
        ax.runs.get(RUN)


def test_request_and_trace_ids_surface_on_errors_and_callbacks() -> None:
    metas: list[ResponseMeta] = []
    server = MockServer(
        overrides={
            "getRun": lambda c, k: problem(
                404, "not_found", {"x-request-id": "req-9"}, trace_id="a" * 32
            )
        }
    )
    ax, _ = make(server, on_response=metas.append)
    with pytest.raises(AxisError) as ei:
        ax.runs.get(RUN)
    assert (ei.value.request_id, ei.value.trace_id) == ("req-9", "a" * 32)
    assert metas[0].operation_id == "getRun" and metas[0].status == 404 and metas[0].attempts == 1


def test_trace_from_traceparent_and_header_and_attempts() -> None:
    seen: list[ResponseMeta] = []
    run = {
        "id": RUN,
        "blueprint": {"name": "a", "version": "1"},
        "state": "running",
        "created_at": "2026-01-01T00:00:00Z",
    }

    def ov(c: Any, k: int) -> httpx.Response:
        h = (
            {"traceparent": f"00-{'c' * 32}-{'d' * 16}-01"}
            if k == 1
            else {"x-trace-id": "tt"}
            if k == 2
            else {}
        )
        return httpx.Response(200, json=run, headers=h)

    server = MockServer(overrides={"getRun": ov})
    ax, _ = make(server, on_response=seen.append)
    ax.runs.get(RUN)
    ax.runs.get(RUN)
    assert [m.trace_id for m in seen] == ["c" * 32, "tt"]
    server2 = MockServer(
        overrides={"getRun": lambda c, k: problem(503, "internal") if k < 2 else None}
    )
    seen2: list[ResponseMeta] = []
    make(server2, on_response=seen2.append)[0].runs.get(RUN)
    assert seen2[0].attempts == 2


def test_bad_bodies() -> None:
    t = HttpTransport(
        TransportConfig(BASE),
        httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<html>"))),
    )
    with pytest.raises(AxisError, match="not valid JSON"):
        t.call(
            OPERATIONS["getRun"],
            path={"runId": RUN},
            query={},
            body=None,
            idempotency_key=None,
            options=None,
        )
    t2 = HttpTransport(
        TransportConfig(BASE),
        httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(204))),
    )
    assert (
        t2.call(
            OPERATIONS["getRun"],
            path={"runId": RUN},
            query={},
            body=None,
            idempotency_key=None,
            options=None,
        )
        is None
    )
    t3 = HttpTransport(
        TransportConfig(BASE, max_retries=0),
        httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(502, text="gateway down"))
        ),
    )
    with pytest.raises(AxisError) as ei:
        t3.call(
            OPERATIONS["getRun"],
            path={"runId": RUN},
            query={},
            body=None,
            idempotency_key=None,
            options=None,
        )
    assert ei.value.status == 502


# ------------------------------------------------------------------------------ credential safety


def test_api_key_goes_only_to_the_base_origin_and_never_in_the_url() -> None:
    server = MockServer()
    ax, _ = make(server)
    ax.runs.get(RUN)
    c = server.calls[0]
    assert c.headers["x-axis-api-key"] == KEY
    assert "authorization" not in c.headers
    assert c.url.host == "api.test.axis.example"
    assert KEY not in str(c.url)


def test_cross_origin_redirect_is_refused_without_leaking_credentials() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers.get("x-axis-api-key", "")))
        return httpx.Response(307, headers={"location": "https://evil.example/steal"})

    ax = Axis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(AxisConnectionError, match="another origin"):
        ax.runs.get(RUN)
    assert [h for h, _ in seen] == ["api.test.axis.example"]
    # a downgrade to http on the same host is another origin too
    ax2 = Axis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.Client(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(
                    302, headers={"location": "http://api.test.axis.example/v1/x"}
                )
            )
        ),
    )
    with pytest.raises(AxisConnectionError, match="another origin"):
        ax2.runs.get(RUN)


def test_same_origin_redirects_are_followed_303_becomes_get_and_loops_are_capped() -> None:
    seen: list[str] = []
    run = {
        "id": RUN,
        "blueprint": {"name": "a", "version": "1"},
        "state": "ready",
        "created_at": "x",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/runs"):
            return httpx.Response(303, headers={"location": f"{BASE}/runs/{RUN}"})
        return httpx.Response(200, json=run)

    ax = Axis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    ax.runs.start("a-b@1")
    assert seen == ["POST /v1/runs", f"GET /v1/runs/{RUN}"]
    loop = Axis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.Client(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(307, headers={"location": f"{BASE}/runs"})
            )
        ),
    )
    with pytest.raises(AxisConnectionError, match="too many redirects"):
        loop.runs.get(RUN)
    no_loc = Axis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(307))),
    )
    with pytest.raises(AxisError):
        no_loc.runs.get(RUN)


def test_tenant_is_never_a_client_input() -> None:
    for k in ("tenant", "tenant_id", "tenantId"):
        with pytest.raises(TypeError, match="tenant"):
            Axis(KEY, base_url=BASE, **{k: "t-1"})
    ax, _ = make(MockServer())
    for h in (
        "X-Axis-Tenant",
        "x-axis-tenant-id",
        "X-Tenant-Id",
        "Authorization",
        "x-axis-api-key",
        "Cookie",
        "Host",
    ):
        with pytest.raises(TypeError, match="may not be set"):
            ax.runs.get(RUN, options=RequestOptions(headers={h: "evil"}))
    ax.runs.get(RUN, options=RequestOptions(headers={"x-custom": "ok"}))


def test_base_url_validation() -> None:
    with pytest.raises(ValueError, match="https"):
        normalize_base_url("http://api.example.com/v1")
    assert normalize_base_url("http://localhost:8080/v1") == "http://localhost:8080/v1/"
    assert normalize_base_url("http://127.0.0.1:1").startswith("http://")
    assert normalize_base_url("http://api.example.com/v1", True).startswith("http://")
    with pytest.raises(ValueError, match="credentials"):
        normalize_base_url("https://u:p@api.example.com")
    with pytest.raises(ValueError, match="query"):
        normalize_base_url("https://api.example.com?x=1")
    for bad in ("not a url", "https://", "https://[bad"):
        with pytest.raises(ValueError, match="invalid base URL"):
            normalize_base_url(bad)


def test_credentials_required_and_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AXIS_API_KEY", raising=False)
    monkeypatch.delenv("AXIS_BASE_URL", raising=False)
    with pytest.raises(TypeError, match="API key is required"):
        Axis(base_url=BASE)
    monkeypatch.setenv("AXIS_API_KEY", "axk_env_123456")
    monkeypatch.setenv("AXIS_BASE_URL", "https://env.example/v1")
    assert Axis().base_url == "https://env.example/v1"
    monkeypatch.delenv("AXIS_BASE_URL")
    assert "axis.example" in Axis().base_url


def test_path_params_required_encoded_and_body_required() -> None:
    server = MockServer()
    ax, _ = make(server)
    with pytest.raises(TypeError, match="missing path parameter"):
        ax.api.get_run(run_id="")
    ax.blueprints.get("a b/c", "1.0.0")
    assert "a%20b%2Fc" in server.calls[0].url.raw_path.decode()
    with pytest.raises(TypeError, match="body is required"):
        ax.api.start_run(body=None)  # type: ignore[arg-type]


def test_retriable_matrix() -> None:
    assert is_retriable(OPERATIONS["getRun"], None)
    assert not is_retriable(OPERATIONS["startRun"], None)
    assert is_retriable(OPERATIONS["startRun"], "k" * 8)
    assert not is_retriable(OPERATIONS["publishPolicyPack"], "k" * 8)
    assert is_retriable(OPERATIONS["testPolicy"], None)


def test_bool_query_and_close() -> None:
    server = MockServer()
    ax, _ = make(server)
    with ax:
        ax.runs.list(limit=2)
    assert server.calls[0].url.params["limit"] == "2"
    own = Axis(KEY, base_url=BASE)
    own.close()


async def test_async_retry_and_security() -> None:
    server = MockServer(overrides={"getRun": fail_first(1)})
    sleeps: list[float] = []

    async def sleep(s: float) -> None:
        sleeps.append(s)

    async with AsyncAxis(
        KEY,
        base_url=server.base_url,
        http_client=httpx.AsyncClient(transport=server.transport()),
        sleep=sleep,
        random=lambda: 0.5,
    ) as ax:
        await ax.runs.get(RUN)
        assert sleeps == [0.25]
        assert (
            "SUPERSECRET" not in repr(ax) and KEY not in repr(ax) and KEY not in repr(ax._transport)
        )
    s2 = MockServer(overrides={"publishPolicyPack": fail_first(5)})
    async with AsyncAxis(
        KEY,
        base_url=s2.base_url,
        http_client=httpx.AsyncClient(transport=s2.transport()),
        sleep=sleep,
    ) as ax2:
        with pytest.raises(AxisError):
            await ax2.policies.publish({})
    assert len(s2.calls) == 1

    async def evil(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://evil.example/x"})

    async with AsyncAxis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(evil)),
    ) as ax3:
        with pytest.raises(AxisConnectionError, match="another origin"):
            await ax3.runs.get(RUN)
    with pytest.raises(TypeError, match="tenant"):
        AsyncAxis(KEY, base_url=BASE, tenant_id="x")


async def test_async_errors_and_redirects() -> None:
    def net(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"down {KEY}", request=request)

    async def nosleep(_s: float) -> None:
        return None

    async with AsyncAxis(
        KEY,
        base_url=BASE,
        max_retries=1,
        sleep=nosleep,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(net)),
    ) as ax:
        with pytest.raises(AxisConnectionError) as ei:
            await ax.runs.get(RUN)
    assert KEY not in str(ei.value)
    seen: list[str] = []
    run = {
        "id": RUN,
        "blueprint": {"name": "a", "version": "1"},
        "state": "ready",
        "created_at": "x",
    }

    def h(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/runs"):
            return httpx.Response(303, headers={"location": f"{BASE}/runs/{RUN}"})
        return httpx.Response(200, json=run)

    async with AsyncAxis(
        KEY, base_url=BASE, http_client=httpx.AsyncClient(transport=httpx.MockTransport(h))
    ) as ax:
        await ax.runs.start("a-b@1")
    assert seen == ["POST /v1/runs", f"GET /v1/runs/{RUN}"]
    async with AsyncAxis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(502, text="x"))
        ),
    ) as ax:
        with pytest.raises(AxisError) as e2:
            await ax.runs.get(RUN)
    assert e2.value.status == 502

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    async with AsyncAxis(
        KEY,
        base_url=BASE,
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(timeout)),
    ) as ax:
        with pytest.raises(AxisTimeoutError):
            await ax.runs.get(RUN)
    t = AsyncHttpTransport(TransportConfig(BASE))
    await t.aclose()
    assert "AsyncHttpTransport" in repr(t)
