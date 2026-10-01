"""ModelGateway cross-cutting behaviour: retries, breaker, fallbacks, BYO keys, error mapping, secrecy."""

from __future__ import annotations

import logging
import pickle
import stat
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_runtime.models import (
    CircuitBreaker,
    CostTable,
    FileSecretStore,
    InMemorySecretStore,
    KmsSecretStore,
    ModelError,
    Price,
    RetryPolicy,
    Secret,
    SecretNotFoundError,
    TenantModelPolicy,
    Usage,
)
from axis_runtime.models.costs import COST_TABLE_VERSION
from axis_runtime.models.resilience import BreakerState, SystemModelClock, default_rng
from axis_runtime.models.secrets import PLATFORM_TENANT, SecretStoreError, scrub
from axis_runtime.models.types import ErrorKind, ModelTarget
from conftest import TENANT, FakeClock, FixedRng
from mhelpers import (
    ALL_SECRET_VALUES,
    KEYS,
    collect,
    free,
    gateway_for,
    json_response,
    request,
    store,
    stream_response,
)

OK_OPENAI = {
    "model": "gpt-4o",
    "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
}
OK_ANTHROPIC = {
    "model": "claude-sonnet-4-20250514",
    "content": [{"type": "text", "text": "from fallback"}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 1, "output_tokens": 1},
}


class Script:
    """Handler returning queued responses (last one repeats) and counting calls per host."""

    def __init__(self, *responses: httpx.Response | Exception | Any) -> None:
        self.responses = list(responses)
        self.hosts: list[str] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.hosts.append(req.url.host)
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if callable(item) and not isinstance(item, httpx.Response):
            item = item()
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[no-any-return]


def err(status: int, **headers: str) -> httpx.Response:
    return httpx.Response(
        status, json={"error": {"type": "some_error", "message": "free text"}}, headers=headers
    )


# ---- retries with jitter ----------------------------------------------------------------------------


async def test_retries_with_full_jitter_then_succeeds() -> None:
    script = Script(err(500), err(503), json_response(OK_OPENAI))
    gw, clock = gateway_for(script)
    resp = await free(gw).complete(request("openai", "gpt-4o"))
    assert resp.text == "ok" and len(script.hosts) == 3
    assert clock.slept == [1.0, 2.0]  # FixedRng returns the ceiling: base*2**(n-1)
    assert [a.outcome for a in resp.attempts] == ["server", "server", "ok"]


async def test_retry_delay_is_capped_and_honours_retry_after_as_a_floor() -> None:
    script = Script(
        err(429, **{"retry-after": "5"}),
        err(429, **{"retry-after": "999"}),
        json_response(OK_OPENAI),
    )
    gw, clock = gateway_for(script)
    await free(gw).complete(request("openai", "gpt-4o"))
    assert clock.slept == [5.0, 8.0]  # floor from the server, bounded by max_delay


async def test_bad_retry_after_header_is_ignored() -> None:
    gw, clock = gateway_for(Script(err(429, **{"retry-after": "soon"}), json_response(OK_OPENAI)))
    await free(gw).complete(request("openai", "gpt-4o"))
    assert clock.slept == [1.0]


def test_retry_policy_jitter_is_bounded_and_random() -> None:
    p = RetryPolicy(max_attempts=5, base_delay=0.5, max_delay=4.0)
    rng = default_rng()
    for attempt in range(1, 8):
        for _ in range(50):
            assert 0.0 <= p.delay(attempt, rng) <= min(4.0, 0.5 * 2 ** (attempt - 1))
    assert len({p.delay(3, rng) for _ in range(20)}) > 1  # actually jittered


async def test_retries_exhausted_raises_the_last_error_with_attempts() -> None:
    script = Script(err(500))
    gw, clock = gateway_for(script)
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o"))
    assert exc.value.kind is ErrorKind.SERVER and exc.value.status == 500 and exc.value.retryable
    assert len(script.hosts) == 3 and clock.slept == [1.0, 2.0]
    assert [a.outcome for a in exc.value.attempts] == ["server"] * 3


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (400, ErrorKind.INVALID_REQUEST),
        (401, ErrorKind.AUTH),
        (403, ErrorKind.AUTH),
        (404, ErrorKind.INVALID_REQUEST),
        (413, ErrorKind.INVALID_REQUEST),
        (422, ErrorKind.INVALID_REQUEST),
        (418, ErrorKind.UNKNOWN),
    ],
)
async def test_non_retryable_errors_are_not_retried(status: int, kind: ErrorKind) -> None:
    script = Script(err(status))
    gw, clock = gateway_for(script)
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o"))
    assert exc.value.kind is kind and len(script.hosts) == 1 and clock.slept == []
    assert "free text" not in str(
        exc.value
    )  # provider free text may echo user content: never surfaced


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (408, ErrorKind.TIMEOUT),
        (429, ErrorKind.RATE_LIMIT),
        (500, ErrorKind.SERVER),
        (502, ErrorKind.SERVER),
        (503, ErrorKind.SERVER),
        (529, ErrorKind.SERVER),
    ],
)
async def test_retryable_status_mapping(status: int, kind: ErrorKind) -> None:
    gw, _ = gateway_for(Script(err(status)), retry=RetryPolicy(max_attempts=1))
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o"))
    assert exc.value.kind is kind and exc.value.retryable


async def test_content_filter_error_code_is_mapped_and_final() -> None:
    body = {"error": {"code": "content_filter", "message": "x"}}
    script = Script(httpx.Response(400, json=body))
    gw, _ = gateway_for(script)
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("azure-openai", "d", endpoint="https://r.openai.azure.com"))
    assert (
        exc.value.kind is ErrorKind.CONTENT_FILTER
        and not exc.value.retryable
        and len(script.hosts) == 1
    )


async def test_transport_errors_are_mapped_and_retried() -> None:
    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions?key=URL-SECRET")
    script = Script(
        httpx.ConnectTimeout("timed out at URL-SECRET", request=req),
        httpx.ConnectError("refused URL-SECRET", request=req),
        json_response(OK_OPENAI),
    )
    gw, clock = gateway_for(script)
    resp = await free(gw).complete(request("openai", "gpt-4o"))
    assert [a.outcome for a in resp.attempts] == ["timeout", "network", "ok"] and len(
        clock.slept
    ) == 2
    gw, _ = gateway_for(
        Script(httpx.ReadTimeout("URL-SECRET", request=req)), retry=RetryPolicy(max_attempts=1)
    )
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o"))
    assert exc.value.kind is ErrorKind.TIMEOUT and "URL-SECRET" not in str(exc.value)
    assert exc.value.provider == "openai"  # re-labelled by the gateway


@pytest.mark.parametrize(
    "body",
    [
        b"<html>",
        b"[]",
        b'{"choices": []}',
        b'{"choices": [{"message": {"tool_calls": [{"id": 1}]}}]}',
    ],
)
async def test_malformed_provider_responses_become_server_errors(body: bytes) -> None:
    gw, _ = gateway_for(
        Script(httpx.Response(200, content=body)), retry=RetryPolicy(max_attempts=1)
    )
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o"))
    assert exc.value.kind is ErrorKind.SERVER


async def test_unknown_provider_is_invalid_request() -> None:
    gw, _ = gateway_for(Script(json_response(OK_OPENAI)))
    with pytest.raises(ModelError, match="unknown provider") as exc:
        await free(gw).complete(request("mystery", "m"))
    assert exc.value.kind is ErrorKind.INVALID_REQUEST


async def test_latency_is_measured_with_the_injected_clock() -> None:
    clock = FakeClock()

    def handler(req: httpx.Request) -> httpx.Response:
        clock.advance(0.25)
        return json_response(OK_OPENAI)

    gw, _ = gateway_for(handler, clock=clock)
    assert (await free(gw).complete(request("openai", "gpt-4o"))).latency_ms == 250


# ---- circuit breaker --------------------------------------------------------------------------------------


async def test_breaker_opens_then_rejects_without_calling_the_provider() -> None:
    script = Script(err(500))
    gw, clock = gateway_for(
        script, breaker_threshold=3, breaker_reset_seconds=30, retry=RetryPolicy(max_attempts=2)
    )
    for _ in range(2):  # 2 calls x 2 attempts = 4 failures >= threshold 3
        with pytest.raises(ModelError):
            await free(gw).complete(request("openai", "gpt-4o"))
    assert gw.breaker(TENANT, "openai").state is BreakerState.OPEN
    calls_before = len(script.hosts)
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o"))
    assert exc.value.kind is ErrorKind.CIRCUIT_OPEN and len(script.hosts) == calls_before


async def test_breaker_half_open_probe_closes_on_success_and_reopens_on_failure() -> None:
    script = Script(err(500), err(500), json_response(OK_OPENAI))
    gw, clock = gateway_for(
        script, breaker_threshold=2, breaker_reset_seconds=30, retry=RetryPolicy(max_attempts=2)
    )
    with pytest.raises(ModelError):
        await free(gw).complete(request("openai", "gpt-4o"))
    assert gw.breaker(TENANT, "openai").state is BreakerState.OPEN
    clock.advance(31)
    assert gw.breaker(TENANT, "openai").state is BreakerState.HALF_OPEN
    assert (await free(gw).complete(request("openai", "gpt-4o"))).text == "ok"  # the single probe
    assert gw.breaker(TENANT, "openai").state is BreakerState.CLOSED

    script2 = Script(err(500))
    gw2, clock2 = gateway_for(
        script2, breaker_threshold=1, breaker_reset_seconds=10, retry=RetryPolicy(max_attempts=1)
    )
    with pytest.raises(ModelError):
        await free(gw2).complete(request("openai", "gpt-4o"))
    clock2.advance(11)
    with pytest.raises(ModelError) as exc:
        await free(gw2).complete(request("openai", "gpt-4o"))  # probe fails
    assert (
        exc.value.kind is ErrorKind.SERVER
        and gw2.breaker(TENANT, "openai").state is BreakerState.OPEN
    )


def test_breaker_allows_only_one_half_open_probe() -> None:
    clock = FakeClock()
    b = CircuitBreaker(clock, failure_threshold=1, reset_timeout=5)
    assert b.allow()
    b.record_failure()
    assert not b.allow()
    clock.advance(6)
    assert b.allow() and not b.allow()  # second caller is rejected while the probe is in flight
    b.record_success()
    assert b.allow() and b.state is BreakerState.CLOSED


async def test_breaker_is_per_provider_and_ignores_client_errors() -> None:
    gw, _ = gateway_for(Script(err(500)), breaker_threshold=1, retry=RetryPolicy(max_attempts=1))
    with pytest.raises(ModelError):
        await free(gw).complete(request("openai", "gpt-4o"))
    assert gw.breaker(TENANT, "openai").state is BreakerState.OPEN
    assert gw.breaker(TENANT, "anthropic").state is BreakerState.CLOSED
    gw2, _ = gateway_for(Script(err(400)), breaker_threshold=1)
    for _ in range(3):
        with pytest.raises(ModelError):
            await free(gw2).complete(request("openai", "gpt-4o"))
    assert (
        gw2.breaker(TENANT, "openai").state is BreakerState.CLOSED
    )  # a bad request is not a provider outage


# ---- fallbacks -----------------------------------------------------------------------------------------------


def by_host(routes: dict[str, Any]) -> Any:
    def handler(req: httpx.Request) -> httpx.Response:
        r = routes[req.url.host]
        return r() if callable(r) else r

    return handler


async def test_fallback_used_when_primary_is_down() -> None:
    hits: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        hits.append(req.url.host)
        return err(503) if req.url.host == "api.openai.com" else json_response(OK_ANTHROPIC)

    gw, _ = gateway_for(handler)
    req = request(
        "openai", "gpt-4o", fallbacks=(ModelTarget("anthropic", "claude-sonnet-4-20250514"),)
    )
    resp = await free(gw).complete(req)
    assert resp.text == "from fallback" and resp.provider == "anthropic"
    assert hits == ["api.openai.com"] * 3 + ["api.anthropic.com"]
    assert [(a.provider, a.outcome) for a in resp.attempts] == [("openai", "server")] * 3 + [
        ("anthropic", "ok")
    ]


async def test_fallback_on_auth_error_but_not_on_invalid_request() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "api.openai.com":
            return err(401)
        return json_response(OK_ANTHROPIC)

    gw, _ = gateway_for(handler)
    fb = (ModelTarget("anthropic", "claude-sonnet-4-20250514"),)
    assert (
        await free(gw).complete(request("openai", "gpt-4o", fallbacks=fb))
    ).provider == "anthropic"

    calls: list[str] = []

    def bad_request(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.host)
        return err(400)

    gw2, _ = gateway_for(bad_request)
    with pytest.raises(ModelError) as exc:
        await free(gw2).complete(request("openai", "gpt-4o", fallbacks=fb))
    assert exc.value.kind is ErrorKind.INVALID_REQUEST and calls == [
        "api.openai.com"
    ]  # no pointless fallback


async def test_fallback_when_primary_circuit_is_open() -> None:
    hits: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        hits.append(req.url.host)
        return err(500) if req.url.host == "api.openai.com" else json_response(OK_ANTHROPIC)

    gw, _ = gateway_for(handler, breaker_threshold=1, retry=RetryPolicy(max_attempts=1))
    fb = (ModelTarget("anthropic", "claude-sonnet-4-20250514"),)
    await free(gw).complete(request("openai", "gpt-4o", fallbacks=fb))
    hits.clear()
    resp = await free(gw).complete(request("openai", "gpt-4o", fallbacks=fb))
    assert hits == ["api.anthropic.com"] and [a.outcome for a in resp.attempts] == [
        "circuit_open",
        "ok",
    ]


async def test_all_targets_failing_raises_the_last_error() -> None:
    gw, _ = gateway_for(Script(err(500)), retry=RetryPolicy(max_attempts=1))
    fb = (ModelTarget("anthropic", "m"),)
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o", fallbacks=fb))
    assert exc.value.provider == "anthropic" and len(exc.value.attempts) == 2


# ---- BYO keys, platform fallback -----------------------------------------------------------------------------------


async def test_tenant_key_is_used_and_isolated_from_other_tenants() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["authorization"])
        return json_response(OK_OPENAI)

    secrets = InMemorySecretStore(
        {("tenant-a", "openai", "default"): "key-A", ("tenant-b", "openai", "default"): "key-B"}
    )
    gw, _ = gateway_for(handler, secrets=secrets)
    await free(gw).complete(request("openai", "gpt-4o", tenant_id="tenant-a"))
    await free(gw).complete(request("openai", "gpt-4o", tenant_id="tenant-b"))
    assert seen == ["Bearer key-A", "Bearer key-B"]
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai", "gpt-4o", tenant_id="tenant-c"))
    assert (
        exc.value.kind is ErrorKind.NO_CREDENTIALS and len(seen) == 2
    )  # never borrowed another tenant's key


async def test_key_label_selects_between_a_tenants_keys() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["authorization"])
        return json_response(OK_OPENAI)

    secrets = InMemorySecretStore(
        {(TENANT, "openai", "default"): "k-default", (TENANT, "openai", "prod"): "k-prod"}
    )
    gw, _ = gateway_for(handler, secrets=secrets)
    await free(gw).complete(request("openai", "gpt-4o", key_label="prod"))
    assert seen == ["Bearer k-prod"]
    with pytest.raises(ModelError):
        await free(gw).complete(request("openai", "gpt-4o", key_label="missing"))


async def test_platform_keys_only_when_the_tenant_policy_allows() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["authorization"])
        return json_response(OK_OPENAI)

    platform = InMemorySecretStore({(PLATFORM_TENANT, "openai", "default"): "platform-key"})
    empty = InMemorySecretStore()
    # flag off (default): refuse
    gw, _ = gateway_for(handler, secrets=empty, platform_secrets=platform)
    with pytest.raises(ModelError, match="platform keys are not permitted") as exc:
        await free(gw).complete(request("openai", "gpt-4o"))
    assert exc.value.kind is ErrorKind.NO_CREDENTIALS and seen == []
    # flag on for this tenant only
    gw, _ = gateway_for(
        handler,
        secrets=empty,
        platform_secrets=platform,
        tenant_policy=lambda t: TenantModelPolicy(allow_platform_keys=t == TENANT),
    )
    await free(gw).complete(request("openai", "gpt-4o"))
    assert seen == ["Bearer platform-key"]
    with pytest.raises(ModelError):
        await free(gw).complete(request("anthropic", "claude-sonnet-4-20250514"))
    # allowed but no platform store configured / no platform key for the provider
    gw, _ = gateway_for(handler, secrets=empty, tenant_policy=lambda t: TenantModelPolicy(True))
    with pytest.raises(ModelError):
        await free(gw).complete(request("openai", "gpt-4o"))
    gw, _ = gateway_for(
        handler,
        secrets=empty,
        platform_secrets=InMemorySecretStore(),
        tenant_policy=lambda t: TenantModelPolicy(True),
    )
    with pytest.raises(ModelError):
        await free(gw).complete(request("openai", "gpt-4o"))


async def test_tenant_key_wins_over_platform_key_even_when_allowed() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["authorization"])
        return json_response(OK_OPENAI)

    gw, _ = gateway_for(
        handler,
        secrets=InMemorySecretStore({(TENANT, "openai", "default"): "mine"}),
        platform_secrets=InMemorySecretStore({(PLATFORM_TENANT, "openai", "default"): "theirs"}),
        tenant_policy=lambda t: TenantModelPolicy(True),
    )
    await free(gw).complete(request("openai", "gpt-4o"))
    assert seen == ["Bearer mine"]


async def test_missing_key_falls_through_to_a_fallback_target_with_a_key() -> None:
    secrets = InMemorySecretStore({(TENANT, "anthropic", "default"): "ak"})
    gw, _ = gateway_for(Script(json_response(OK_ANTHROPIC)), secrets=secrets)
    resp = await free(gw).complete(
        request("openai", "gpt-4o", fallbacks=(ModelTarget("anthropic", "m"),))
    )
    assert resp.provider == "anthropic"


# ---- streaming resilience -----------------------------------------------------------------------------------


OPENAI_STREAM_OK = (
    b'data: {"model":"gpt-4o","choices":[{"delta":{"content":"hi"}}]}\n\n'
    b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}\n\n'
    b"data: [DONE]\n\n"
)


async def test_stream_retries_before_the_first_event_and_honours_status_errors() -> None:
    script = Script(err(503), stream_response(OPENAI_STREAM_OK))
    gw, clock = gateway_for(lambda r: script(r))
    events = await collect(free(gw).stream(request("openai", "gpt-4o")))
    assert events[-1].response.text == "hi" and clock.slept == [1.0]  # type: ignore[union-attr]


async def test_stream_does_not_retry_after_bytes_reached_the_consumer() -> None:
    first = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: {oops\n\n'
    script = Script(stream_response(first), stream_response(OPENAI_STREAM_OK))
    gw, _ = gateway_for(lambda r: script(r))
    got: list[Any] = []
    with pytest.raises(ModelError, match="malformed stream event") as exc:
        async for ev in free(gw).stream(request("openai", "gpt-4o")):
            got.append(ev)
    assert [e.text for e in got] == ["hi"] and len(
        script.hosts
    ) == 1  # no silent restart mid-answer
    assert exc.value.attempts[-1].outcome == "server"


async def test_stream_falls_back_and_fails_on_fatal_errors() -> None:
    fb_stream = (
        b'event: message_start\ndata: {"type":"message_start","message":{"model":"m","usage":{"input_tokens":1}}}\n\n'
        b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"fb"}}\n\n'
    )

    def handler(req: httpx.Request) -> httpx.Response:
        return err(500) if req.url.host == "api.openai.com" else stream_response(fb_stream)()

    gw, _ = gateway_for(handler, retry=RetryPolicy(max_attempts=1))
    events = await collect(
        free(gw).stream(request("openai", "gpt-4o", fallbacks=(ModelTarget("anthropic", "m"),)))
    )
    assert events[-1].response.text == "fb" and events[-1].response.provider == "anthropic"  # type: ignore[union-attr]
    gw2, _ = gateway_for(Script(err(400)))
    with pytest.raises(ModelError) as exc:
        await collect(
            free(gw2).stream(
                request("openai", "gpt-4o", fallbacks=(ModelTarget("anthropic", "m"),))
            )
        )
    assert exc.value.kind is ErrorKind.INVALID_REQUEST


async def test_stream_circuit_open_and_transport_error() -> None:
    req = httpx.Request("POST", "https://x")
    gw, _ = gateway_for(
        Script(httpx.ConnectError("boom", request=req)),
        breaker_threshold=1,
        retry=RetryPolicy(max_attempts=1),
    )
    with pytest.raises(ModelError) as e1:
        await collect(free(gw).stream(request("openai", "gpt-4o")))
    assert e1.value.kind is ErrorKind.NETWORK and e1.value.provider == "openai"
    with pytest.raises(ModelError) as e2:
        await collect(free(gw).stream(request("openai", "gpt-4o")))
    assert e2.value.kind is ErrorKind.CIRCUIT_OPEN


# ---- secrets never leak ----------------------------------------------------------------------------------------------


async def test_secrets_never_appear_in_exceptions_logs_or_reprs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    failures: list[BaseException] = []
    providers = [
        ("openai", "gpt-4o", None),
        ("google", "gemini-2.0-flash", None),
        ("anthropic", "claude-sonnet-4", None),
        ("azure-openai", "d", "https://r.openai.azure.com"),
        ("openai-compatible", "m", "https://c.internal/v1"),
    ]
    for provider, model, endpoint in providers:
        own = KEYS[provider]  # a misbehaving provider that echoes the caller's own key back
        for body in [
            httpx.Response(401, json={"error": {"type": own, "message": f"bad key {own}"}}),
            httpx.Response(500, json={"error": {"code": own}}),
            httpx.Response(400, content=f"{own} echoed".encode()),
        ]:
            gw, _ = gateway_for(Script(body), retry=RetryPolicy(max_attempts=2))
            try:
                await free(gw).complete(request(provider, model, endpoint=endpoint))
            except ModelError as e:
                failures.append(e)
    req = httpx.Request("POST", "https://api.openai.com/?key=sk-openai-SECRET-222")
    gw, _ = gateway_for(
        Script(httpx.ConnectError("sk-openai-SECRET-222", request=req)),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        await free(gw).complete(request("openai", "gpt-4o"))
    except ModelError as e:
        failures.append(e)
    gw, _ = gateway_for(Script(json_response({})), secrets=store(bedrock="sk-openai-SECRET-222"))
    try:
        await free(gw).complete(request("bedrock", "m"))
    except ModelError as e:
        failures.append(e)
    assert len(failures) >= 10
    for e in failures:
        blob = " ".join(
            [
                str(e),
                repr(e),
                *map(repr, e.args),
                repr(e.attempts),
                repr(e.__cause__),
                repr(e.__context__),
            ]
        )
        assert not any(s in blob for s in ALL_SECRET_VALUES), blob
        assert e.__cause__ is None  # the raw httpx exception (which can hold URLs) is never chained
    logged = " ".join(r.getMessage() + str(r.args) + str(r.exc_text) for r in caplog.records)
    assert caplog.records and not any(s in logged for s in ALL_SECRET_VALUES)
    assert "SECRET" not in caplog.text


def test_secret_wrapper_never_reveals_itself() -> None:
    s = Secret("sk-very-secret")
    assert (
        "sk-very-secret" not in repr(s)
        and "sk-very-secret" not in str(s)
        and f"{s}" == "Secret(***)"
    )
    assert "sk-very-secret" not in repr([s]) and "sk-very-secret" not in repr({"k": s})
    assert (
        s.reveal() == "sk-very-secret"
        and s == Secret("sk-very-secret")
        and s != Secret("x")
        and s != "sk-very-secret"
    )
    assert hash(s) == hash(Secret("sk-very-secret"))
    with pytest.raises(TypeError):
        pickle.dumps(s)
    assert scrub("a sk-very-secret b", s, None, Secret("")) == "a *** b"


# ---- stores ---------------------------------------------------------------------------------------------------------


async def test_in_memory_store() -> None:
    s = InMemorySecretStore()
    with pytest.raises(SecretNotFoundError):
        await s.get("t", "openai")
    await s.put("t", "openai", "default", "v")
    assert (await s.get("t", "openai")).reveal() == "v"
    with pytest.raises(SecretNotFoundError):
        await s.get("t2", "openai")  # tenant scoped


async def test_file_store_is_encrypted_scoped_and_key_checked(tmp_path: Path) -> None:
    path = tmp_path / "secrets.enc"
    key = FileSecretStore.generate_key()
    fs = FileSecretStore(path, key)
    with pytest.raises(SecretNotFoundError):
        await fs.get("t", "openai")
    await fs.put("t", "openai", "default", "sk-plaintext-marker")
    await fs.put("t", "anthropic", "prod", "ak-2")
    await fs.put("t", "openai", "default", "sk-rotated")  # overwrite
    raw = path.read_bytes()
    assert b"sk-plaintext-marker" not in raw and b"sk-rotated" not in raw and b"openai" not in raw
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert (await FileSecretStore(path, key).get("t", "openai")).reveal() == "sk-rotated"
    assert (await fs.get("t", "anthropic", "prod")).reveal() == "ak-2"
    with pytest.raises(SecretNotFoundError):
        await fs.get("other-tenant", "openai")
    with pytest.raises(SecretStoreError, match="cannot be decrypted") as exc:
        await FileSecretStore(path, FileSecretStore.generate_key()).get("t", "openai")
    assert "sk-" not in str(exc.value)
    path.write_bytes(b"garbage")
    with pytest.raises(SecretStoreError):
        await fs.get("t", "openai")
    assert not path.with_name(path.name + ".tmp").exists()


async def test_kms_store_is_an_honest_unbuilt_interface() -> None:
    kms = KmsSecretStore("arn:aws:kms:eu-west-1:000000000000:key/example")
    with pytest.raises(NotImplementedError, match="not built"):
        await kms.get("t", "openai")
    with pytest.raises(NotImplementedError, match="not built"):
        await kms.put("t", "openai", "default", "v")


# ---- costs ------------------------------------------------------------------------------------------------------------


def test_cost_lookup_longest_prefix_region_prefix_and_unknowns() -> None:
    t = CostTable()
    assert (
        t.lookup("openai", "gpt-4o-mini-2024-07-18")
        == t.lookup("openai", "gpt-4o-mini")
        != t.lookup("openai", "gpt-4o")
    )
    assert t.lookup("openai", "gpt-4.1-mini") != t.lookup("openai", "gpt-4.1")
    assert t.lookup("bedrock", "us.anthropic.claude-3-5-sonnet-20241022-v2:0") is not None
    assert t.lookup("azure-openai", "gpt-4o") == t.lookup("openai", "gpt-4o")
    assert (
        t.lookup("openai", "brand-new-model") is None
        and t.lookup("openai-compatible", "llama") is None
    )
    assert t.cost("openai", "brand-new-model", Usage(10, 10)) is None
    assert COST_TABLE_VERSION and t.version == COST_TABLE_VERSION


def test_cost_computation_with_cache_tiers_and_custom_tables() -> None:
    t = CostTable()
    c = t.cost(
        "anthropic",
        "claude-sonnet-4-20250514",
        Usage(
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            cached_tokens=400_000,
            cache_write_tokens=100_000,
        ),
    )
    # 500k*3 + 400k*0.30 + 100k*3.75 + 1M*15 = 1.5 + 0.12 + 0.375 + 15 = 16.995
    assert c == Decimal("16.995000")
    # cache tiers default to the plain input price when a table has none
    custom = CostTable({"x": {"m": Price(Decimal(2), Decimal(4))}}, version="acme-1")
    assert custom.version == "acme-1"
    assert custom.cost("x", "m", Usage(1_000_000, 500_000, 200_000, 100_000)) == Decimal(
        "4.000000"
    )  # 1M*2 + 0.5M*4
    # inconsistent usage (cached > input) never yields a negative cost
    assert custom.cost("x", "m", Usage(10, 0, 50, 0)) is not None


def test_system_clock_and_default_rng_are_usable() -> None:
    c = SystemModelClock()
    assert (
        c.monotonic() <= c.monotonic() and c.now().tzinfo is UTC and isinstance(c.now(), datetime)
    )
    assert 0 <= default_rng().uniform(0, 1) <= 1


async def test_system_clock_sleep_and_default_transport() -> None:
    await SystemModelClock().sleep(0)
    from axis_runtime.models import InMemorySecretStore as S
    from axis_runtime.models.gateway import ModelGateway

    gw = ModelGateway(S())  # default httpx transport is constructed lazily and never used here
    assert gw.cost_table.version == COST_TABLE_VERSION and FixedRng().uniform(1, 2) == 2


# ---- breaker map is bounded ---------------------------------------------------------------------------------


def _trip(gw: Any, tenant: str) -> None:
    b = gw.breaker(tenant, "openai")
    for _ in range(b.failure_threshold):
        b.record_failure()
    assert b.state is BreakerState.OPEN


def test_breaker_map_is_a_bounded_lru_evicting_closed_breakers_first() -> None:
    gw, _ = gateway_for(Script(err(500)), max_breakers=3, breaker_threshold=1)
    _trip(gw, "t-open")  # oldest, but OPEN: must survive
    closed_a = gw.breaker("t-a", "openai")
    gw.breaker("t-b", "openai")
    assert len(gw._breakers) == 3  # noqa: SLF001
    gw.breaker("t-a", "openai")  # touch: t-b is now the least recently used CLOSED one
    gw.breaker("t-c", "openai")  # full: evicts t-b, not the older OPEN t-open
    keys = {k[0] for k in gw._breakers}  # noqa: SLF001
    assert keys == {"t-open", "t-a", "t-c"}
    assert gw.breaker("t-a", "openai") is closed_a
    assert gw.breaker("t-open", "openai").state is BreakerState.OPEN  # eviction never reset it
    for i in range(50):
        gw.breaker(f"churn-{i}", "openai")
    assert len(gw._breakers) == 3  # noqa: SLF001
    assert gw.breaker("t-open", "openai").state is BreakerState.OPEN


def test_breaker_map_refuses_new_keys_when_every_breaker_is_tripped() -> None:
    gw, clock = gateway_for(Script(err(500)), max_breakers=2, breaker_threshold=1)
    _trip(gw, "t1")
    _trip(gw, "t2")
    with pytest.raises(ModelError) as exc:
        gw.breaker("t3", "openai")
    assert exc.value.kind is ErrorKind.CONFIGURATION and not exc.value.retryable
    assert {k[0] for k in gw._breakers} == {"t1", "t2"}  # noqa: SLF001
    clock.advance(31)  # half-open is still not closed: still refused
    with pytest.raises(ModelError):
        gw.breaker("t3", "openai")
    gw.breaker("t1", "openai").record_success()  # one recovers: room appears
    assert gw.breaker("t3", "openai").state is BreakerState.CLOSED


async def test_a_refused_breaker_is_a_non_retryable_configuration_error_end_to_end() -> None:
    script = Script(json_response(OK_OPENAI))
    gw, _ = gateway_for(script, max_breakers=1, breaker_threshold=1)
    _trip(gw, TENANT)
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("anthropic", "claude-sonnet-4-20250514"))
    assert exc.value.kind is ErrorKind.CONFIGURATION and script.hosts == []


def test_recording_an_outcome_never_raises_when_the_map_is_full_of_tripped_breakers() -> None:
    gw, _ = gateway_for(Script(err(500)), max_breakers=1, breaker_threshold=1)
    _trip(gw, "t1")
    req = request("openai", "gpt-4o", tenant_id="t2")
    breaker = gw._recording_breaker(req, req.target)  # noqa: SLF001
    breaker.record_failure()
    assert len(gw._breakers) == 1  # noqa: SLF001  (the throwaway was not stored)


def test_max_breakers_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_breakers"):
        gateway_for(Script(err(500)), max_breakers=0)
