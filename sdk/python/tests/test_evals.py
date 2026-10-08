from __future__ import annotations

from typing import Any

import httpx
import pytest
from axis_mock_server import MockServer
from axis_sdk import AsyncAxis, Axis, AxisWaitTimeoutError, parse_eval_blueprint
from test_resources import aclient, client

RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"


def erun(status: str, run_id: str = RUN) -> dict[str, Any]:
    return {"id": run_id, "suite": "smoke@1.0.0", "status": status, "case_results": []}


def test_parse_eval_blueprint() -> None:
    assert parse_eval_blueprint("agent@1.0.0") == {"name": "agent", "version": "1.0.0"}
    assert parse_eval_blueprint("acme/agent@1.0.0") == {
        "namespace": "acme",
        "name": "agent",
        "version": "1.0.0",
    }
    assert parse_eval_blueprint({"name": "agent", "version": "1"}) == {
        "name": "agent",
        "version": "1",
    }
    assert parse_eval_blueprint({"namespace": "acme", "name": "agent", "version": "1"}) == {
        "namespace": "acme",
        "name": "agent",
        "version": "1",
    }
    with pytest.raises(ValueError, match="name@version"):
        parse_eval_blueprint("agent")


def test_start_sends_mode_and_namespaced_blueprint_with_an_idempotency_key() -> None:
    ax, server, _ = client()
    ax.evals.start("smoke@1.0.0", "acme/agent@1.0.0", mode="manual")
    call = server.calls[0]
    assert call.body == {
        "suite": "smoke@1.0.0",
        "mode": "manual",
        "blueprint": {"namespace": "acme", "name": "agent", "version": "1.0.0"},
    }
    assert call.headers.get("idempotency-key")


def test_wait_polls_until_final_and_times_out() -> None:
    n = 0

    def get(c: Any, i: int) -> httpx.Response:
        nonlocal n
        n += 1
        return httpx.Response(200, json=erun("running" if n < 3 else "failed"))

    ax, _, sleeps = client(getEvalRun=get)
    assert ax.evals.wait(RUN, poll_interval=0.5)["status"] == "failed"
    assert sleeps == [0.5, 0.5]
    slow, _, _ = client(getEvalRun=lambda c, i: httpx.Response(200, json=erun("queued")))
    with pytest.raises(AxisWaitTimeoutError):
        slow.evals.wait(RUN, timeout=0)


def test_iterate_follows_the_cursor_and_stops_at_max_items() -> None:
    pages = [
        {"items": [erun("passed", "a"), erun("failed", "b")], "next_cursor": "c1"},
        {"items": [erun("errored", "c")], "next_cursor": None},
    ]
    i = 0

    def listing(c: Any, n: int) -> httpx.Response:
        nonlocal i
        page = pages[i]
        i += 1
        return httpx.Response(200, json=page)

    ax, server, _ = client(listEvalRuns=listing)
    assert [r["id"] for r in ax.evals.iterate(suite="smoke@1.0.0")] == ["a", "b", "c"]
    assert "cursor=c1" in str(server.calls[1].url)
    i = 0
    assert [r["id"] for r in ax.evals.iterate(max_items=1)] == ["a"]


def test_comparison_is_none_without_a_baseline() -> None:
    ax, _, _ = client(getEvalRunComparison=lambda c, i: httpx.Response(200, json={}))
    assert ax.evals.comparison(RUN) is None
    ax2, _, _ = client(
        getEvalRunComparison=lambda c, i: httpx.Response(
            200, json={"comparison": {"comparable": True}}
        )
    )
    assert ax2.evals.comparison(RUN) == {"comparable": True}


def test_gate_dataset_and_runner_requests() -> None:
    ax, server, _ = client()
    bp = {"name": "agent", "version": "1", "content_hash": "a" * 64}
    ax.evals.gate(bp, [{"ref": "s@^1.0.0", "threshold": 0.9}])
    assert server.calls[0].body == {
        "blueprint": bp,
        "suites": [{"ref": "s@^1.0.0", "threshold": 0.9}],
    }
    ax.evals.datasets.get("qa")
    ax.evals.datasets.get("qa", 3)
    assert str(server.calls[1].url).endswith("/evals/datasets/qa/versions/latest")
    assert str(server.calls[2].url).endswith("/evals/datasets/qa/versions/3")
    ax.evals.runners.register("ci-1")
    assert server.calls[3].body is None


@pytest.mark.asyncio
async def test_async_variants() -> None:
    n = 0

    def get(c: Any, i: int) -> httpx.Response:
        nonlocal n
        n += 1
        return httpx.Response(200, json=erun("running" if n < 2 else "passed"))

    pages = [
        {"items": [erun("passed", "a")], "next_cursor": "c1"},
        {"items": [erun("failed", "b")], "next_cursor": None},
    ]
    i = 0

    def listing(c: Any, k: int) -> httpx.Response:
        nonlocal i
        page = pages[i]
        i += 1
        return httpx.Response(200, json=page)

    ax, server, sleeps = await aclient(
        getEvalRun=get,
        listEvalRuns=listing,
        getEvalRunComparison=lambda c, k: httpx.Response(200, json={}),
    )
    assert (await ax.evals.wait(RUN, poll_interval=0.25))["status"] == "passed"
    assert sleeps == [0.25]
    got = [r["id"] async for r in ax.evals.iterate()]
    assert got == ["a", "b"]
    assert await ax.evals.comparison(RUN) is None
    slow, _, _ = await aclient(getEvalRun=lambda c, k: httpx.Response(200, json=erun("queued")))
    with pytest.raises(AxisWaitTimeoutError):
        await slow.evals.wait(RUN, timeout=0)
    await ax.evals.start("smoke@1.0.0", "acme/agent@1.0.0")
    assert server.calls[-1].body["blueprint"]["namespace"] == "acme"
    _ = (AsyncAxis, Axis, MockServer)
