"""Data residency at the ModelGateway: a tenant's prompts only go to provider endpoints in its allowed regions (fail-closed)."""

from __future__ import annotations

import dataclasses

import httpx
import pytest
from axis_runtime.models import ModelError, TenantModelPolicy
from axis_runtime.models.types import ErrorKind, ModelTarget
from conftest import TENANT
from mhelpers import collect, free, gateway_for, json_response, request

OK = {
    "model": "gpt-4o",
    "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
}


class Calls:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.n += 1
        return json_response(OK)


def with_region(region: str | None, **kw: object):  # type: ignore[no-untyped-def]
    r = request("openai", "gpt-4o", **kw)
    return dataclasses.replace(r, target=ModelTarget("openai", "gpt-4o", None, {}, region))


def gw(calls: Calls, allowed: frozenset[str] | None):  # type: ignore[no-untyped-def]
    g, _ = gateway_for(calls, tenant_policy=lambda _t: TenantModelPolicy(allowed_regions=allowed))
    return free(g)


async def test_unrestricted_tenant_is_unchanged() -> None:
    calls = Calls()
    resp = await gw(calls, None).complete(with_region(None))
    assert resp.text == "ok" and calls.n == 1


async def test_allowed_region_passes_and_case_is_ignored() -> None:
    calls = Calls()
    resp = await gw(calls, frozenset({"EU-West-1"})).complete(with_region("eu-west-1"))
    assert resp.text == "ok" and calls.n == 1


@pytest.mark.parametrize("region", ["us-east-1", None, "", "  "])
async def test_other_missing_or_blank_region_is_refused_before_any_network_call(
    region: str | None,
) -> None:
    calls = Calls()
    with pytest.raises(ModelError) as e:
        await gw(calls, frozenset({"eu-west-1"})).complete(with_region(region))
    assert e.value.kind is ErrorKind.CONFIGURATION and calls.n == 0


async def test_empty_allow_list_denies_everything() -> None:
    calls = Calls()
    with pytest.raises(ModelError):
        await gw(calls, frozenset()).complete(with_region("eu-west-1"))
    assert calls.n == 0


async def test_fallback_in_an_allowed_region_is_used_when_the_primary_is_not() -> None:
    calls = Calls()
    r = with_region("us-east-1")
    r = dataclasses.replace(r, fallbacks=(ModelTarget("openai", "gpt-4o", None, {}, "eu-west-1"),))
    resp = await gw(calls, frozenset({"eu-west-1"})).complete(r)
    assert resp.text == "ok" and calls.n == 1


async def test_streaming_obeys_the_same_rule() -> None:
    calls = Calls()
    with pytest.raises(ModelError):
        await collect(gw(calls, frozenset({"eu-west-1"})).stream(with_region("us-east-1")))
    assert calls.n == 0


async def test_policy_lookup_is_by_the_requests_tenant() -> None:
    seen: list[str] = []

    def policy(t: str) -> TenantModelPolicy:
        seen.append(t)
        return TenantModelPolicy(allowed_regions=frozenset({"eu-west-1"}))

    g, _ = gateway_for(Calls(), tenant_policy=policy)
    await free(g).complete(with_region("eu-west-1"))
    assert seen and set(seen) == {TENANT}
