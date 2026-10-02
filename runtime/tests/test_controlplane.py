"""Control-plane runtime bridge client, HttpSecretStore and the budget config the control plane produces."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from axis_runtime.controlplane import ControlPlaneBridge, ControlPlaneUnavailable, KeyNotFound
from axis_runtime.models import SecretNotFoundError
from axis_runtime.models.secrets import SecretStoreError
from axis_runtime.models.secrets_http import HttpSecretStore
from axis_runtime.tenant_budgets import (
    BudgetConfigError,
    TenantBudgets,
    tighter,
)
from axis_runtime.tki import InMemoryLedger, ListSink
from axis_runtime.tki.budget import (
    AccountKey,
    BudgetExceededError,
    Limit,
    Resource,
    ScopeKind,
)

T = "11111111-1111-4111-8111-111111111111"


def bridge(handler: Any, tenant: str = T) -> ControlPlaneBridge:
    return ControlPlaneBridge(
        "http://cp.test/",
        tenant_id=tenant,
        token="rt-secret",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


async def test_reveal_sends_only_provider_and_label_with_the_bearer_and_returns_an_opaque_secret() -> (
    None
):
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"value": "sk-byo-123"})

    store = HttpSecretStore(bridge(handler))
    secret = await store.get(T, "openai", "default")
    assert secret.reveal() == "sk-byo-123"
    assert "sk-byo-123" not in repr(secret) and "sk-byo-123" not in str(secret)
    (req,) = seen
    assert (req.method, str(req.url)) == ("POST", "http://cp.test/internal/v1/model-keys/reveal")
    assert req.headers["authorization"] == "Bearer rt-secret"
    assert json.loads(req.content) == {
        "provider": "openai",
        "label": "default",
    }  # no tenant in the body


async def test_a_client_never_asks_on_behalf_of_another_tenant() -> None:
    called = False

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"value": "x"})

    with pytest.raises(SecretNotFoundError):
        await HttpSecretStore(bridge(handler)).get("22222222-2222-4222-8222-222222222222", "openai")
    assert called is False


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx.Response(404, json={}), SecretNotFoundError),
        (httpx.Response(401, json={}), SecretStoreError),
        (httpx.Response(500, text="boom sk-leak"), SecretStoreError),
        (httpx.Response(200, text="not json"), SecretStoreError),
        (httpx.Response(200, json={"value": ""}), SecretStoreError),
        (httpx.Response(200, json={"nope": 1}), SecretStoreError),
    ],
)
async def test_failures_are_fail_closed_and_never_leak_the_body(
    response: httpx.Response, expected: type[Exception]
) -> None:
    with pytest.raises(expected) as info:
        await HttpSecretStore(bridge(lambda _r: response)).get(T, "openai")
    assert "sk-leak" not in str(info.value)


async def test_transport_errors_and_put_are_refused() -> None:
    def boom(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    store = HttpSecretStore(bridge(boom))
    with pytest.raises(SecretStoreError, match="transport"):
        await store.get(T, "openai")
    with pytest.raises(SecretStoreError, match="admin API"):
        await store.put(T, "openai", "default", "sk-x")


async def test_budget_config_fetch_and_aclose() -> None:
    b = bridge(lambda _r: httpx.Response(200, json={"tenant": [], "run": [], "agents": {}}))
    assert await b.budget_config() == {"tenant": [], "run": [], "agents": {}}
    for resp in (httpx.Response(503), httpx.Response(200, text="x"), httpx.Response(200, json=[1])):
        with pytest.raises(ControlPlaneUnavailable):
            await bridge(lambda _r, r=resp: r).budget_config()
    await b.aclose()
    with pytest.raises(KeyNotFound):
        await bridge(lambda _r: httpx.Response(200)).reveal_model_key("x", "p", "l")


async def test_default_client_is_created() -> None:
    b = ControlPlaneBridge("http://127.0.0.1:1", tenant_id=T, token="t")
    with pytest.raises(ControlPlaneUnavailable, match="transport"):
        await b.budget_config()
    await b.aclose()


DOC = {
    "tenant": [
        {"metric": "tokens", "period": "day", "soft": 80, "hard": 100},
        {"metric": "tokens", "period": "month", "hard": 60},
        {"metric": "cost_usd", "period": "day", "soft": 0.5, "hard": 1},
        {"metric": "runtime_seconds", "period": "day", "hard": 2},
        {"metric": "tool_calls", "period": "day"},
    ],
    "run": [{"metric": "tokens", "period": "run", "soft": 10, "hard": 50}],
    "agents": {},
}


def test_budget_document_maps_to_ledger_limits_with_the_tightest_period_winning() -> None:
    tb = TenantBudgets.from_json(DOC)
    lim = tb.tenant_limits()
    assert lim[Resource.TOKENS] == Limit(60, 60)  # soft clamped to the tighter hard
    assert lim[Resource.COST_MICRO_USD] == Limit(500_000, 1_000_000)
    assert lim[Resource.RUNTIME_MS] == Limit(None, 2000)
    assert Resource.TOOL_CALLS not in lim  # an entry with no cap sets no limit
    assert tb.run_limits() == {Resource.TOKENS: Limit(10, 50)}


def test_a_tenant_can_lower_but_never_raise_what_the_blueprint_declares() -> None:
    tb = TenantBudgets.from_json(DOC)
    merged = tb.spawn_limits({Resource.TOKENS: Limit(5, 500), Resource.TOOL_CALLS: Limit(None, 7)})
    assert merged[Resource.TOKENS] == Limit(5, 50)
    assert merged[Resource.TOOL_CALLS] == Limit(None, 7)
    assert tighter({Resource.TOKENS: Limit(None, 10)}, {Resource.TOKENS: Limit(None, 99)})[
        Resource.TOKENS
    ] == Limit(None, 10)


@pytest.mark.parametrize(
    "bad",
    [
        {"tenant": "x"},
        {"tenant": [5]},
        {"tenant": [{"metric": "gpu_hours", "period": "day", "hard": 1}]},
        {"tenant": [{"metric": "tokens", "period": "day", "hard": -1}]},
        {"tenant": [{"metric": "tokens", "period": "day", "hard": True}]},
        {"tenant": [{"metric": "tokens", "period": "day", "soft": "5"}]},
        {"tenant": [{"metric": "tokens", "period": "day", "hard": float("nan")}]},
        {"tenant": [{"metric": "tokens", "period": "day", "hard": float("inf")}]},
        {"tenant": [{"metric": "cost_usd", "period": "day", "hard": 1e308}]},
    ],
)
def test_an_unintelligible_budget_stops_the_run_instead_of_being_dropped(bad: Any) -> None:
    with pytest.raises(BudgetConfigError):
        TenantBudgets.from_json(bad)


def test_the_tenant_limits_are_enforced_by_the_tki_ledger_for_every_run_of_the_tenant() -> None:
    ledger = InMemoryLedger(ListSink())
    TenantBudgets.from_json(
        {"tenant": [{"metric": "tokens", "period": "day", "hard": 100}]}
    ).apply_to_ledger(ledger, T)
    tenant = AccountKey(T, ScopeKind.TENANT, T)
    run = AccountKey(T, ScopeKind.RUN, "r1")
    ledger.ensure_account(AccountKey(T, ScopeKind.AGENT, "a"), tenant)
    ledger.ensure_account(run, AccountKey(T, ScopeKind.AGENT, "a"))
    ledger.charge(run, {Resource.TOKENS: 60})
    with pytest.raises(BudgetExceededError):
        ledger.reserve(
            run, {Resource.TOKENS: 50}
        )  # the tenant has 40 left, whatever the run thinks
    # a refreshed config replaces the limits; the scheduler's own ensure_account finds the account
    TenantBudgets.from_json(
        {"tenant": [{"metric": "tokens", "period": "day", "hard": 1000}]}
    ).apply_to_ledger(ledger, T)
    ledger.reserve(run, {Resource.TOKENS: 50})


def test_malformed_lists_and_empty_documents() -> None:
    assert TenantBudgets.from_json({}) == TenantBudgets()
    assert TenantBudgets().tenant_limits() == {}
    with pytest.raises(BudgetConfigError):
        TenantBudgets.from_json({"run": {}})
