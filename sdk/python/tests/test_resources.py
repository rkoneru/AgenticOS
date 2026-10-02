from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest
from axis_mock_server import MockServer, problem
from axis_sdk import (
    AsyncAxis,
    Axis,
    AxisConnectionError,
    AxisError,
    AxisWaitTimeoutError,
    apaginate,
    paginate,
    parse_blueprint_ref,
)

RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"
PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def run(state: str) -> dict[str, Any]:
    return {
        "id": RUN,
        "blueprint": {"name": "a", "version": "1"},
        "state": state,
        "created_at": "2026-01-01T00:00:00Z",
    }


def ev(seq: int) -> dict[str, Any]:
    return {"sequence": seq, "type": "message", "pid": PID, "at": "2026-01-01T00:00:00Z"}


def sse(*events: dict[str, Any]) -> str:
    return "".join(f"id: {e['sequence']}\ndata: {json.dumps(e)}\n\n" for e in events)


def sse_response(text: str) -> httpx.Response:
    return httpx.Response(200, text=text, headers={"content-type": "text/event-stream"})


def client(**overrides: Any) -> tuple[Axis, MockServer, list[float]]:
    server = MockServer(overrides=overrides)
    sleeps: list[float] = []
    ax = Axis(
        "axk_test_key_123456",
        base_url=server.base_url,
        http_client=httpx.Client(transport=server.transport()),
        sleep=sleeps.append,
    )
    return ax, server, sleeps


def test_stream_yields_typed_events_and_ends_when_terminated() -> None:
    ax, _, _ = client(
        listRunEvents=lambda c, n: sse_response(sse(ev(1), ev(2))),
        getRun=lambda c, n: httpx.Response(200, json=run("terminated")),
    )
    assert [e["sequence"] for e in ax.runs.stream(RUN)] == [1, 2]


def test_stream_reconnects_with_last_event_id_dedupes_and_honours_retry() -> None:
    conn = 0

    def events(c: Any, n: int) -> httpx.Response:
        nonlocal conn
        conn += 1
        return (
            sse_response("retry: 250\n" + sse(ev(1), ev(2)))
            if conn == 1
            else sse_response(sse(ev(2), ev(3)))
        )

    ax, server, sleeps = client(
        listRunEvents=events,
        getRun=lambda c, n: httpx.Response(200, json=run("running" if n == 1 else "terminated")),
    )
    assert [e["sequence"] for e in ax.runs.stream(RUN)] == [1, 2, 3]
    calls = [c for c in server.calls if c.operation_id == "listRunEvents"]
    assert [c.headers["last-event-id"] for c in calls] == ["0", "2"]
    assert calls[1].url.params["after_sequence"] == "2"
    assert calls[1].headers["accept"] == "text/event-stream"
    assert sleeps == [0.25]


def test_stream_after_sequence_and_unrelated_events() -> None:
    ax, server, _ = client(
        listRunEvents=lambda c, n: sse_response(
            'event: ping\ndata: {}\n\ndata: {"x":1}\n\n' + sse(ev(6))
        ),
        getRun=lambda c, n: httpx.Response(200, json=run("terminated")),
    )
    assert [e["sequence"] for e in ax.runs.stream(RUN, after_sequence=5)] == [6]
    assert server.calls[0].url.params["after_sequence"] == "5"


def test_stream_gives_up_after_max_reconnects() -> None:
    ax, _, _ = client(
        listRunEvents=lambda c, n: sse_response(": nothing\n\n"),
        getRun=lambda c, n: httpx.Response(200, json=run("running")),
    )
    with pytest.raises(AxisError, match="failed 3 times"):
        list(ax.runs.stream(RUN, max_reconnects=2))


def test_stream_does_not_reconnect_on_4xx_but_does_on_5xx() -> None:
    ax, server, _ = client(listRunEvents=lambda c, n: problem(404, "not_found"))
    with pytest.raises(AxisError) as ei:
        list(ax.runs.stream(RUN))
    assert ei.value.status == 404 and len(server.calls) == 1
    ax2, _, _ = client(
        listRunEvents=lambda c, n: problem(503, "internal") if n == 1 else sse_response(sse(ev(1))),
        getRun=lambda c, n: httpx.Response(200, json=run("terminated")),
    )
    assert [e["sequence"] for e in ax2.runs.stream(RUN)] == [1]


def test_stream_malformed_json_is_an_error() -> None:
    ax, _, _ = client(listRunEvents=lambda c, n: sse_response("data: {not json\n\n"))
    with pytest.raises(AxisError, match="malformed JSON"):
        list(ax.runs.stream(RUN))
    ax2, _, _ = client(listRunEvents=lambda c, n: sse_response("data: [1]\n\n"))
    with pytest.raises(AxisError, match="non-object"):
        list(ax2.runs.stream(RUN))


class _Dropping(httpx.SyncByteStream):
    def __init__(self, first: str) -> None:
        self.first = first

    def __iter__(self) -> Iterator[bytes]:
        yield self.first.encode()
        raise httpx.ReadError("connection reset")


def test_stream_reconnects_after_a_mid_stream_disconnect() -> None:
    def events(c: Any, n: int) -> httpx.Response:
        if n == 1:
            return httpx.Response(
                200, stream=_Dropping(sse(ev(1))), headers={"content-type": "text/event-stream"}
            )
        return sse_response(sse(ev(2)))

    ax, _, _ = client(
        listRunEvents=events, getRun=lambda c, n: httpx.Response(200, json=run("terminated"))
    )
    assert [e["sequence"] for e in ax.runs.stream(RUN)] == [1, 2]


def test_stream_connection_failure_before_response_is_retried() -> None:
    server = MockServer(
        overrides={"getRun": lambda c, n: httpx.Response(200, json=run("terminated"))}
    )
    n = 0

    def flaky(request: httpx.Request) -> httpx.Response:
        nonlocal n
        n += 1
        if n == 1:
            raise httpx.ConnectError("down", request=request)
        return sse_response(sse(ev(1))) if "events" in request.url.path else server.handle(request)

    ax = Axis(
        "axk_test_key_123456",
        base_url=server.base_url,
        http_client=httpx.Client(transport=httpx.MockTransport(flaky)),
        sleep=lambda _s: None,
    )
    assert [e["sequence"] for e in ax.runs.stream(RUN)] == [1]
    # the failing connect surfaced as a connection error internally; exhausting the budget re-raises as AxisError
    always = Axis(
        "axk_test_key_123456",
        base_url=server.base_url,
        http_client=httpx.Client(
            transport=httpx.MockTransport(
                lambda r: (_ for _ in ()).throw(httpx.ConnectError("x", request=r))
            )
        ),
        sleep=lambda _s: None,
    )
    with pytest.raises(AxisError, match="failed"):
        list(always.runs.stream(RUN, max_reconnects=1))
    assert AxisConnectionError


def test_wait_polls_until_terminated_and_times_out() -> None:
    ax, _, sleeps = client(
        getRun=lambda c, n: httpx.Response(200, json=run("running" if n < 3 else "terminated"))
    )
    assert ax.runs.wait(RUN, poll_interval=10)["state"] == "terminated"
    assert sleeps == [10, 10]
    ax2, _, _ = client(getRun=lambda c, n: httpx.Response(200, json=run("running")))
    with pytest.raises(AxisWaitTimeoutError):
        ax2.runs.wait(RUN, timeout=0)


def test_cancel_signal_and_events() -> None:
    ax, server, _ = client()
    ax.runs.cancel(RUN, reason="stop")
    ax.runs.cancel(RUN, force=True)
    ax.runs.signal(RUN, "PAUSE", pid=PID, reason="r")
    assert [c.body for c in server.calls] == [
        {"signal": "TERM", "reason": "stop"},
        {"signal": "KILL"},
        {"signal": "PAUSE", "pid": PID, "reason": "r"},
    ]
    assert server.violations == []


def test_all_events_follows_pages() -> None:
    ax, server, _ = client(
        listRunEvents=lambda c, n: httpx.Response(
            200,
            json={"items": [ev(1), ev(2)], "next_cursor": "c"}
            if c.url.params["after_sequence"] == "0"
            else {"items": [ev(3)], "next_cursor": None},
        )
    )
    assert [e["sequence"] for e in ax.runs.all_events(RUN)] == [1, 2, 3]
    assert len(server.calls) == 2
    ax2, _, _ = client(
        listRunEvents=lambda c, n: httpx.Response(200, json={"items": [], "next_cursor": "c"})
    )
    assert list(ax2.runs.all_events(RUN)) == []


def test_pagination() -> None:
    pages = {
        None: {"items": [run("running"), run("ready")], "next_cursor": "p2"},
        "p2": {"items": [run("waiting")], "next_cursor": None},
    }
    ax, server, _ = client(
        listRuns=lambda c, n: httpx.Response(200, json=pages[c.url.params.get("cursor")])
    )
    assert len(list(ax.runs.iterate(limit=2))) == 3
    assert [c.url.params.get("cursor") for c in server.calls] == [None, "p2"]
    assert len(list(ax.runs.iterate(max_items=1))) == 1
    assert list(paginate(lambda c: {"items": [], "next_cursor": "x"})) == []
    calls = 0

    def two(c: str | None) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"items": [1], "next_cursor": "a"} if calls < 2 else {"items": [2]}

    assert list(paginate(two)) == [1, 2]


def test_blueprint_refs_and_guards() -> None:
    assert parse_blueprint_ref("my-agent@1.2.3") == {"name": "my-agent", "version": "1.2.3"}
    assert parse_blueprint_ref({"name": "a", "version": "2"}) == {"name": "a", "version": "2"}
    for bad in ("noversion", "@1", "a@"):
        with pytest.raises(ValueError, match=r"name@version"):
            parse_blueprint_ref(bad)
    ax, server, _ = client()
    with pytest.raises(ValueError, match="needs a target"):
        ax.kill_switches.engage("agent")
    with pytest.raises(ValueError, match="scope"):
        ax.kill_switches.set("galaxy", True)
    with pytest.raises(ValueError, match="decision"):
        ax.approvals.decide(RUN, "maybe")
    assert server.calls == []


def test_other_iterators_and_shortcuts() -> None:
    ax, server, _ = client()
    assert len(list(ax.blueprints.iterate(max_items=1))) == 1
    assert len(list(ax.approvals.iterate(status="pending", max_items=1))) == 1
    assert len(list(ax.policies.iterate(max_items=1))) == 1
    assert len(list(ax.audit.iterate(max_items=1, from_seq=1))) == 1
    ax.approvals.reject(RUN, "no")
    ax.kill_switches.release("tenant")
    ax.audit.verify()
    assert server.violations == []
    assert server.calls[-1].body is None


# ------------------------------------------------------------------------------------------- async


async def aclient(**overrides: Any) -> tuple[AsyncAxis, MockServer, list[float]]:
    server = MockServer(overrides=overrides)
    sleeps: list[float] = []

    async def sleep(s: float) -> None:
        sleeps.append(s)

    ax = AsyncAxis(
        "axk_test_key_123456",
        base_url=server.base_url,
        http_client=httpx.AsyncClient(transport=server.transport()),
        sleep=sleep,
    )
    return ax, server, sleeps


async def collect(it: AsyncIterator[Any]) -> list[Any]:
    return [x async for x in it]


class _ADropping(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield sse(ev(1)).encode()
        raise httpx.ReadError("reset")


async def test_async_stream_reconnect_dedupe_retry_and_errors() -> None:
    conn = 0

    def events(c: Any, n: int) -> httpx.Response:
        nonlocal conn
        conn += 1
        if conn == 1:
            return httpx.Response(
                200, stream=_ADropping(), headers={"content-type": "text/event-stream"}
            )
        if conn == 2:
            return sse_response("retry: 100\n" + sse(ev(1), ev(2)))
        return sse_response(sse(ev(2), ev(3)))

    ax, server, sleeps = await aclient(
        listRunEvents=events,
        getRun=lambda c, n: httpx.Response(200, json=run("running" if n == 1 else "terminated")),
    )
    async with ax:
        assert [e["sequence"] for e in await collect(ax.runs.stream(RUN))] == [1, 2, 3]
    calls = [c for c in server.calls if c.operation_id == "listRunEvents"]
    assert [c.headers["last-event-id"] for c in calls] == ["0", "1", "2"]
    assert 0.1 in sleeps
    ax2, _, _ = await aclient(listRunEvents=lambda c, n: problem(404, "not_found"))
    async with ax2:
        with pytest.raises(AxisError) as ei:
            await collect(ax2.runs.stream(RUN))
    assert ei.value.status == 404
    ax3, _, _ = await aclient(
        listRunEvents=lambda c, n: sse_response(": nothing\n\n"),
        getRun=lambda c, n: httpx.Response(200, json=run("running")),
    )
    async with ax3:
        with pytest.raises(AxisError, match="failed 2 times"):
            await collect(ax3.runs.stream(RUN, max_reconnects=1))
    ax4, _, _ = await aclient(
        listRunEvents=lambda c, n: (
            problem(503, "internal") if n == 1 else sse_response('data: {"x":1}\n\n' + sse(ev(4)))
        ),
        getRun=lambda c, n: httpx.Response(200, json=run("terminated")),
    )
    async with ax4:
        assert [e["sequence"] for e in await collect(ax4.runs.stream(RUN))] == [4]


async def test_async_wait_cancel_events_and_pagination() -> None:
    pages = {
        None: {"items": [run("running")], "next_cursor": "p2"},
        "p2": {"items": [run("ready")], "next_cursor": None},
    }
    ax, server, sleeps = await aclient(
        getRun=lambda c, n: httpx.Response(200, json=run("running" if n < 3 else "terminated")),
        listRuns=lambda c, n: httpx.Response(200, json=pages[c.url.params.get("cursor")]),
        listRunEvents=lambda c, n: httpx.Response(
            200,
            json={"items": [ev(1)], "next_cursor": "c"}
            if c.url.params["after_sequence"] == "0"
            else {"items": [], "next_cursor": None},
        ),
    )
    async with ax:
        assert (await ax.runs.wait(RUN, poll_interval=5))["state"] == "terminated"
        assert sleeps == [5, 5]
        assert len(await collect(ax.runs.iterate(limit=1))) == 2
        assert len(await collect(ax.runs.iterate(max_items=1))) == 1
        assert [e["sequence"] for e in await collect(ax.runs.all_events(RUN))] == [1]
        await ax.runs.cancel(RUN, force=True)
        await ax.runs.cancel(RUN)
        assert server.calls[-1].body == {"signal": "TERM"}
        assert await collect(apaginate(lambda c: _aempty())) == []


async def _aempty() -> dict[str, Any]:
    return {"items": [], "next_cursor": "x"}


async def test_async_other_resources() -> None:
    ax, server, _ = await aclient()
    async with ax:
        assert len(await collect(ax.blueprints.iterate(max_items=1))) == 1
        assert len(await collect(ax.approvals.iterate(max_items=1))) == 1
        assert len(await collect(ax.policies.iterate(max_items=1))) == 1
        assert len(await collect(ax.audit.iterate(max_items=1))) == 1
        await ax.approvals.reject(RUN, "no")
        await ax.kill_switches.release("tenant")
        await ax.audit.verify()
        with pytest.raises(ValueError, match="needs a target"):
            await ax.kill_switches.engage("agent")
        with pytest.raises(ValueError, match="scope"):
            await ax.kill_switches.set("x", True)
        with pytest.raises(ValueError, match="decision"):
            await ax.approvals.decide(RUN, "maybe")
    assert server.violations == []


async def test_async_wait_times_out() -> None:
    ax, _, _ = await aclient(getRun=lambda c, n: httpx.Response(200, json=run("running")))
    async with ax:
        with pytest.raises(AxisWaitTimeoutError):
            await ax.runs.wait(RUN, timeout=0)
