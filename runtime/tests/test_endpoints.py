"""SSRF / platform-key exfiltration defences for ABL endpoint overrides, and per-tenant breakers."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from axis_runtime.models import (
    ErrorKind,
    InMemorySecretStore,
    ModelError,
    RetryPolicy,
    TenantModelPolicy,
)
from axis_runtime.models.adapters.base import default_resolver
from axis_runtime.models.endpoints import (
    EndpointError,
    check_host_literal,
    check_resolved,
    validate_endpoint,
)
from axis_runtime.models.resilience import BreakerState
from axis_runtime.models.secrets import PLATFORM_TENANT
from conftest import TENANT
from mhelpers import free, gateway_for, json_response, request

OK = {
    "model": "m",
    "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
}
PUBLIC = "93.184.216.34"


class FakeResolver:
    def __init__(self, table: dict[str, list[str]] | None = None, default: list[str] | None = None):
        self.table = table or {}
        self.default = default if default is not None else [PUBLIC]
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append((host, port))
        return self.table.get(host, self.default)


async def _validate(
    endpoint: str,
    resolver: FakeResolver | None = None,
    *,
    allow_http: bool = False,
    allow_private: bool = False,
    ports: frozenset[int] = frozenset(),
) -> None:
    await validate_endpoint(
        endpoint,
        allow_http=allow_http,
        allow_private=allow_private,
        extra_ports=ports,
        resolver=resolver or FakeResolver(),
    )


# ---- static rejections ---------------------------------------------------------------------------------

BAD_ENDPOINTS = [
    "http://api.example.com",  # not https
    "ftp://api.example.com",
    "https://user:pw@api.example.com",  # userinfo
    "https://user@api.example.com",
    "https://api.example.com@evil.example.org",
    "https://api.example.com:8443",  # odd port
    "https://api.example.com:80",
    "https://api.example.com:notaport",
    "https://",
    "https://[fe80::1%25eth0]/",
    "https://localhost",
    "https://LOCALHOST.",
    "https://foo.localhost",
    "https://llm.internal",
    "https://metadata.google.internal",
    "https://printer.local",
    "https://host.localdomain",
    "https://169.254.169.254",
    "https://169.254.169.254/latest/meta-data",
    "https://127.0.0.1",
    "https://10.1.2.3",
    "https://172.16.0.1",
    "https://192.168.1.1",
    "https://100.64.0.1",  # CGNAT
    "https://0.0.0.0",
    "https://224.0.0.1",  # multicast
    "https://240.0.0.1",  # reserved
    "https://[::1]",
    "https://[::]",
    "https://[fe80::1]",
    "https://[fc00::1]",
    "https://[ff02::1]",
    "https://[::ffff:127.0.0.1]",  # IPv4-mapped loopback
    "https://[::ffff:169.254.169.254]",
    "https://[::ffff:a9fe:a9fe]",
    "https://[2002:7f00:1::]",  # 6to4 embedding 127.0.0.1
    "https://[64:ff9b::7f00:1]",  # NAT64 embedding 127.0.0.1
    "https://2130706433",  # decimal 127.0.0.1
    "https://0x7f000001",  # hex
    "https://0x7f.0.0.1",
    "https://0177.0.0.1",  # octal
    "https://127.1",  # short form
    "https://017700000001",
]


@pytest.mark.parametrize("endpoint", BAD_ENDPOINTS)
async def test_bad_endpoints_are_rejected(endpoint: str) -> None:
    with pytest.raises(EndpointError) as exc:
        await _validate(endpoint)
    assert "pw" not in str(exc.value)  # never echo userinfo


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://api.example.com",
        "https://api.example.com/v1/",
        "https://api.example.com:443/v1",
        "https://93.184.216.34",
        "https://[2606:2800:220:1:248:1893:25c8:1946]",
        "https://localhost.example.com",  # only exact/suffix names are blocked
        "https://internal.example.com",
    ],
)
async def test_good_endpoints_are_accepted(endpoint: str) -> None:
    await _validate(endpoint)


async def test_http_and_extra_ports_are_opt_in() -> None:
    await _validate("http://api.example.com", allow_http=True)
    await _validate("http://api.example.com:80", allow_http=True)
    with pytest.raises(EndpointError):
        await _validate("http://api.example.com:443", allow_http=True)
    await _validate("https://api.example.com:8443", ports=frozenset({8443}))
    with pytest.raises(EndpointError):
        await _validate("https://api.example.com:9443", ports=frozenset({8443}))


# ---- DNS resolution ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],
        ["93.184.216.34", "10.0.0.5"],  # ANY non-public address rejects
        ["169.254.169.254"],
        ["::1"],
        ["::ffff:10.0.0.1"],
        ["fe80::1%eth0"],
        ["not-an-ip"],
        [],
    ],
)
async def test_hostnames_resolving_to_non_public_addresses_are_rejected(answers: list[str]) -> None:
    with pytest.raises(EndpointError):
        await _validate("https://rebind.example.com", FakeResolver(default=answers))


async def test_resolution_uses_the_injected_resolver_and_port_and_skips_ip_literals() -> None:
    r = FakeResolver()
    await _validate("https://api.example.com", r)
    assert r.calls == [("api.example.com", 443)]
    r2 = FakeResolver()
    await _validate("https://93.184.216.34", r2)
    assert r2.calls == []  # literals are judged directly, no DNS


async def test_resolver_failure_fails_closed() -> None:
    async def boom(host: str, port: int) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(EndpointError, match="could not be resolved"):
        await validate_endpoint(
            "https://api.example.com",
            allow_http=False,
            allow_private=False,
            extra_ports=frozenset(),
            resolver=boom,
        )


async def test_allow_private_skips_host_checks_but_not_scheme_or_userinfo() -> None:
    r = FakeResolver(default=["10.0.0.5"])
    for ok in ("https://llm.internal", "https://127.0.0.1", "https://10.0.0.5"):
        await _validate(ok, r, allow_private=True)
    assert r.calls == []
    for bad in ("http://llm.internal", "https://u:p@llm.internal"):
        with pytest.raises(EndpointError):
            await _validate(bad, r, allow_private=True)


def test_host_literal_checker_directly() -> None:
    check_host_literal("api.example.com")
    with pytest.raises(EndpointError):
        check_host_literal("10.0.0.1")


async def test_default_resolver_is_lazy_and_resolves_via_the_event_loop() -> None:
    resolver = default_resolver()  # building it performs no DNS
    addrs = list(await resolver("127.0.0.1", 443))
    assert addrs == ["127.0.0.1"]
    with pytest.raises(EndpointError):
        await check_resolved("localhost.example.invalid", 443, _raising)


async def _raising(host: str, port: int) -> list[str]:
    raise OSError


# ---- gateway integration -------------------------------------------------------------------------------


def _seen_gateway(**kw: Any) -> tuple[Any, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return json_response(OK)

    gw, _ = gateway_for(handler, **kw)
    return gw, seen


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://169.254.169.254",
        "https://evil.example.org@api.example.com",
        "https://localhost",
        "https://[::ffff:7f00:1]",
        "https://2130706433",
    ],
)
async def test_gateway_never_sends_to_a_bad_endpoint(endpoint: str) -> None:
    gw, seen = _seen_gateway()
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai-compatible", endpoint=endpoint))
    assert exc.value.kind is ErrorKind.INVALID_REQUEST and not exc.value.retryable
    assert seen == []


async def test_gateway_rejects_a_hostname_that_resolves_to_a_private_address() -> None:
    gw, seen = _seen_gateway(resolver=FakeResolver({"rebind.example.com": ["10.0.0.9"]}))
    with pytest.raises(ModelError, match="non-public"):
        await free(gw).complete(request("openai-compatible", endpoint="https://rebind.example.com"))
    assert seen == []
    await free(gw).complete(request("openai-compatible", endpoint="https://fine.example.com"))
    assert len(seen) == 1


async def test_tenant_policy_allow_private_endpoints_is_per_tenant() -> None:
    gw, seen = _seen_gateway(
        tenant_policy=lambda t: TenantModelPolicy(allow_private_endpoints=t == TENANT),
    )
    await free(gw).complete(request("openai-compatible", endpoint="https://llm.internal"))
    assert len(seen) == 1
    other = request("openai-compatible", endpoint="https://llm.internal", tenant_id="other")
    with pytest.raises(ModelError):
        await free(gw).complete(other)
    assert len(seen) == 1


async def test_gateway_validates_endpoints_for_streams_too() -> None:
    gw, seen = _seen_gateway()
    with pytest.raises(ModelError):
        async for _ in free(gw).stream(request("openai-compatible", endpoint="https://10.0.0.1")):
            pass
    assert seen == []


async def test_default_resolver_is_not_built_until_an_endpoint_is_used() -> None:
    gw, _ = gateway_for(lambda r: json_response(OK))
    gw._resolver = None  # noqa: SLF001
    await free(gw).complete(request("openai"))  # no endpoint override: no DNS at all


PLATFORM = InMemorySecretStore({(PLATFORM_TENANT, "openai-compatible", "default"): "platform-key"})


async def test_platform_key_is_never_sent_to_a_custom_endpoint() -> None:
    gw, seen = _seen_gateway(
        secrets=InMemorySecretStore(),
        platform_secrets=PLATFORM,
        tenant_policy=lambda t: TenantModelPolicy(allow_platform_keys=True),
    )
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai-compatible", endpoint="https://api.example.com"))
    assert exc.value.kind is ErrorKind.CONFIGURATION and not exc.value.retryable
    assert "platform-key" not in str(exc.value) and seen == []


async def test_platform_key_without_endpoint_override_still_works() -> None:
    platform = InMemorySecretStore({(PLATFORM_TENANT, "openai", "default"): "platform-key"})
    gw, seen = _seen_gateway(
        secrets=InMemorySecretStore(),
        platform_secrets=platform,
        tenant_policy=lambda t: TenantModelPolicy(allow_platform_keys=True),
    )
    await free(gw).complete(request("openai"))
    assert seen[0].headers["authorization"] == "Bearer platform-key"


async def test_tenant_own_key_may_be_combined_with_an_endpoint() -> None:
    gw, seen = _seen_gateway(
        secrets=InMemorySecretStore({(TENANT, "openai-compatible", "default"): "mine"}),
        platform_secrets=PLATFORM,
        tenant_policy=lambda t: TenantModelPolicy(allow_platform_keys=True),
    )
    await free(gw).complete(request("openai-compatible", endpoint="https://api.example.com"))
    assert seen[0].headers["authorization"] == "Bearer mine"


# ---- circuit breaker isolation -------------------------------------------------------------------------


async def test_breaker_is_isolated_per_tenant_and_per_endpoint() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500) if req.url.host == "bad.example.com" else json_response(OK)

    secrets = InMemorySecretStore(
        {
            (TENANT, "openai-compatible", "default"): "a",
            ("tenant-b", "openai-compatible", "default"): "b",
        }
    )
    gw, _ = gateway_for(
        handler, secrets=secrets, breaker_threshold=2, retry=RetryPolicy(max_attempts=2)
    )
    bad = "https://bad.example.com/v1"
    good = "https://good.example.com/v1"
    with pytest.raises(ModelError):
        await free(gw).complete(request("openai-compatible", endpoint=bad))
    assert gw.breaker(TENANT, "openai-compatible", bad).state is BreakerState.OPEN
    # tenant A is now short-circuited on that endpoint...
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("openai-compatible", endpoint=bad))
    assert exc.value.kind is ErrorKind.CIRCUIT_OPEN
    # ...but tenant B, same provider and same endpoint, is unaffected (it reaches the provider: 500)
    with pytest.raises(ModelError) as exc_b:
        await free(gw).complete(request("openai-compatible", endpoint=bad, tenant_id="tenant-b"))
    assert exc_b.value.kind is ErrorKind.SERVER
    assert gw.breaker("tenant-b", "openai-compatible", bad) is not gw.breaker(
        TENANT, "openai-compatible", bad
    )
    # ...and tenant A's other endpoint is independent
    assert (await free(gw).complete(request("openai-compatible", endpoint=good))).text == "ok"
    assert gw.breaker(TENANT, "openai-compatible", good).state is BreakerState.CLOSED
    assert gw.breaker(TENANT, "openai-compatible", good + "/") is gw.breaker(
        TENANT, "openai-compatible", good
    )
