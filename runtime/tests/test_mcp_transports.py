"""stdio (real subprocess) and streamable-HTTP (httpx MockTransport) client transports."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_runtime.mcp import (
    McpLimits,
    McpProtocolError,
    McpResponseTooLarge,
    McpSession,
    McpSessionExpired,
    McpTransportError,
    StdioCommand,
)
from axis_runtime.mcp.config import ServerConfig
from axis_runtime.mcp.http import StreamableHttpTransport
from axis_runtime.mcp.stdio import StdioTransport, scrubbed_env

FAKE = str(Path(__file__).with_name("fake_mcp_stdio.py"))


def stdio(mode: str = "normal", **limits: Any) -> StdioTransport:
    cmd = StdioCommand((sys.executable, "-S", FAKE, mode), env={"ONLY_THIS": "1"})
    return StdioTransport(cmd, McpLimits(**limits))


# ---- stdio -------------------------------------------------------------------------------------


async def test_stdio_round_trip_and_scrubbed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AXIS_SECRET_KEY", "hunter2")
    t = stdio()
    s = McpSession("loc", t)
    await s.initialize()
    names = [x.name for x in (await s.list_tools()).tools]
    assert names == ["env", "echo"]
    env = json.loads((await s.invoke_tool("env", {}))["content"][0]["text"])
    assert "AXIS_SECRET_KEY" not in env and "ONLY_THIS" in env
    assert "PATH" not in env and "HOME" not in env  # nothing inherited
    echoed = await s.invoke_tool("echo", {"a": [1, 2]})
    assert json.loads(echoed["content"][0]["text"]) == {"a": [1, 2]}
    await s.close()
    await s.close()  # idempotent


def test_scrubbed_env_is_exactly_the_operator_env() -> None:
    assert scrubbed_env(StdioCommand(("/x",), env={"A": "1"})) == {"A": "1"}
    assert scrubbed_env(StdioCommand(("/x",))) == {}


async def test_stdio_server_request_gets_method_not_found() -> None:
    s = McpSession("loc", stdio("sampling"))
    await s.initialize()
    out = await s.invoke_tool("echo", {})
    assert out["content"][0]["text"] == str(-32601)
    await s.close()


@pytest.mark.parametrize(
    ("mode", "exc"),
    [
        ("garbage", McpProtocolError),
        ("oversize", McpResponseTooLarge),
        ("exit", McpTransportError),
    ],
)
async def test_stdio_failures_are_typed_and_kill_the_child(mode: str, exc: type[Exception]) -> None:
    t = stdio(mode, max_message_bytes=1000)
    s = McpSession("loc", t)
    await s.initialize()
    with pytest.raises(exc):
        await s.invoke_tool("echo", {})
    assert t._proc is None  # closed after the failure


async def test_stdio_timeout_kills_the_child() -> None:
    t = stdio("hang", call_timeout_seconds=0.5)
    s = McpSession("loc", t)
    await s.initialize()
    with pytest.raises(McpTransportError):
        await s.invoke_tool("echo", {})
    assert t._proc is None


async def test_stdio_missing_binary_is_a_transport_error() -> None:
    t = StdioTransport(StdioCommand(("/nonexistent/axis-mcp",)), McpLimits())
    with pytest.raises(McpTransportError) as e:
        await McpSession("x", t).initialize()
    assert "/nonexistent" not in str(e.value)


async def test_stdio_never_respawns_mid_session() -> None:
    t = stdio()
    s = McpSession("loc", t)
    await s.initialize()
    proc = t._proc
    proc.kill()
    await proc.wait()
    with pytest.raises(McpTransportError):
        await s.invoke_tool("echo", {})
    with pytest.raises(McpTransportError):  # and after close the transport stays closed
        await s.invoke_tool("echo", {})


# ---- streamable HTTP ---------------------------------------------------------------------------

URL = "https://mcp.example.com/mcp"
Handler = Callable[[httpx.Request], httpx.Response]


async def public(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def http(
    handler: Handler, *, headers: dict[str, str] | None = None, **limits: Any
) -> StreamableHttpTransport:
    cfg = ServerConfig("t", "kb", "http", url=URL, headers=headers or {})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return StreamableHttpTransport(cfg, McpLimits(**limits), resolver=public, client=client)


def rpc(req: httpx.Request) -> dict[str, Any]:
    return json.loads(req.content)  # type: ignore[no-any-return]


def ok_json(obj: Any, **headers: str) -> httpx.Response:
    return httpx.Response(200, json=obj, headers=headers)


def standard(req: httpx.Request, seen: list[httpx.Request] | None = None) -> httpx.Response:
    if seen is not None:
        seen.append(req)
    if req.method == "DELETE":
        return httpx.Response(204)
    m = rpc(req)
    if "id" not in m:
        return httpx.Response(202)
    method = m["method"]
    if method == "initialize":
        return ok_json(
            {"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": "2025-03-26"}},
            **{"Mcp-Session-Id": "sess-1"},
        )
    if method == "tools/list":
        return ok_json({"jsonrpc": "2.0", "id": m["id"], "result": {"tools": [{"name": "t"}]}})
    return ok_json(
        {"jsonrpc": "2.0", "id": m["id"], "result": {"content": [{"type": "text", "text": "hi"}]}}
    )


async def test_http_session_headers_and_close() -> None:
    seen: list[httpx.Request] = []
    t = http(lambda r: standard(r, seen), headers={"Authorization": "Bearer k"})
    s = McpSession("kb", t)
    await s.initialize()
    assert (await s.list_tools()).tools[0].name == "t"
    await s.invoke_tool("t", {"a": 1})
    first, *_, last_post = [r for r in seen if r.method == "POST"]
    assert "Mcp-Session-Id" not in first.headers and first.headers["authorization"] == "Bearer k"
    assert first.headers["accept"] == "application/json, text/event-stream"
    assert last_post.headers["mcp-session-id"] == "sess-1"
    assert last_post.headers["mcp-protocol-version"] == "2025-03-26"
    await s.close()
    assert seen[-1].method == "DELETE" and seen[-1].headers["mcp-session-id"] == "sess-1"


def sse(*events: Any, raw: str | None = None) -> httpx.Response:
    body = raw if raw is not None else "".join(f"data: {json.dumps(e)}\n\n" for e in events)
    return httpx.Response(200, content=body.encode(), headers={"content-type": "text/event-stream"})


async def test_http_sse_with_interleaved_server_messages() -> None:
    posted: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        m = rpc(req)
        if m.get("method") == "tools/call":
            return sse(
                {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
                {"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage"},
                {"jsonrpc": "2.0", "id": 999, "result": {}},  # someone else's id
                {"jsonrpc": "2.0", "id": m["id"], "result": {"content": []}},
            )
        if "error" in m:
            posted.append(m)
            return httpx.Response(202)
        return standard(req)

    s = McpSession("kb", http(handler))
    await s.initialize()
    out = await s.invoke_tool("t", {})
    assert out["content"] == []
    assert posted[0]["id"] == "srv-1" and posted[0]["error"]["code"] == -32601


async def test_http_sse_framing_edge_cases() -> None:
    def make(response: Callable[[dict[str, Any]], httpx.Response]) -> McpSession:
        def handler(req: httpx.Request) -> httpx.Response:
            m = rpc(req)
            return response(m) if m.get("method") == "tools/call" else standard(req)

        return McpSession("kb", http(handler))

    ok = {"jsonrpc": "2.0", "id": 3, "result": {"content": []}}
    # CRLF framing, keep-alive comment, multi-line data
    s = make(
        lambda m: sse(raw=": ping\r\n\r\ndata: " + json.dumps({**ok, "id": m["id"]}) + "\r\n\r\n")
    )
    await s.initialize()
    await s.invoke_tool("t", {})
    s = make(
        lambda m: sse(
            raw=f'data: {{"jsonrpc":"2.0",\ndata: "id": {m["id"]}, "result": {{"content": []}}}}\n\n'
        )
    )
    await s.initialize()
    await s.invoke_tool("t", {})
    # stream ends without our response
    s = make(lambda m: sse({"jsonrpc": "2.0", "method": "x"}))
    await s.initialize()
    with pytest.raises(McpTransportError):
        await s.invoke_tool("t", {})
    # malformed event
    s = make(lambda m: sse(raw="data: {nope\n\n"))
    await s.initialize()
    with pytest.raises(McpProtocolError):
        await s.invoke_tool("t", {})


async def test_http_size_caps() -> None:
    def big(req: httpx.Request) -> httpx.Response:
        m = rpc(req)
        if m.get("method") != "tools/call":
            return standard(req)
        return ok_json(
            {
                "jsonrpc": "2.0",
                "id": m["id"],
                "result": {"content": [{"type": "text", "text": "x" * 5000}]},
            }
        )

    s = McpSession("kb", http(big, max_message_bytes=1000))
    await s.initialize()
    with pytest.raises(McpResponseTooLarge):
        await s.invoke_tool("t", {})

    def endless(req: httpx.Request) -> httpx.Response:
        if rpc(req).get("method") != "tools/call":
            return standard(req)
        return sse(raw="data: " + "y" * 9000)  # one never-terminated event

    s = McpSession("kb", http(endless, max_message_bytes=1000))
    await s.initialize()
    with pytest.raises(McpResponseTooLarge):
        await s.invoke_tool("t", {})

    def many(req: httpx.Request) -> httpx.Response:
        if rpc(req).get("method") != "tools/call":
            return standard(req)
        return sse(*[{"jsonrpc": "2.0", "method": "n", "params": {"p": "z" * 500}}] * 20)

    s = McpSession("kb", http(many, max_message_bytes=1000))
    await s.initialize()
    with pytest.raises(McpResponseTooLarge):
        await s.invoke_tool("t", {})


@pytest.mark.parametrize(
    ("response", "exc"),
    [
        (httpx.Response(302, headers={"location": "http://169.254.169.254/"}), McpTransportError),
        (httpx.Response(500), McpTransportError),
        (httpx.Response(401), McpTransportError),
        (
            httpx.Response(200, content=b"<html>", headers={"content-type": "text/html"}),
            McpProtocolError,
        ),
        (
            httpx.Response(200, content=b"{", headers={"content-type": "application/json"}),
            McpProtocolError,
        ),
        (httpx.Response(202), McpTransportError),  # a request answered 202 is not an answer
        (ok_json({"jsonrpc": "2.0", "id": 424242, "result": {}}), McpProtocolError),  # id confusion
        (ok_json({"jsonrpc": "2.0", "id": "1", "result": {}}), McpProtocolError),
    ],
)
async def test_http_bad_responses(response: httpx.Response, exc: type[Exception]) -> None:
    t = http(lambda r: response)
    with pytest.raises(exc):
        await McpSession("kb", t).initialize()


async def test_http_session_expiry_and_bad_session_id() -> None:
    state = {"expired": False}

    def handler(req: httpx.Request) -> httpx.Response:
        if state["expired"] and rpc(req).get("method") == "tools/call":
            return httpx.Response(404)
        return standard(req)

    s = McpSession("kb", http(handler))
    await s.initialize()
    state["expired"] = True
    with pytest.raises(McpSessionExpired):
        await s.invoke_tool("t", {})

    def bad_sid(req: httpx.Request) -> httpx.Response:
        return ok_json(
            {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18"}},
            **{"Mcp-Session-Id": "bad id"},
        )

    with pytest.raises(McpProtocolError):
        await McpSession("kb", http(bad_sid)).initialize()


async def test_http_timeout_and_network_errors_hide_urls() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("cannot reach https://mcp.example.com/mcp?key=SECRET")

    with pytest.raises(McpTransportError) as e:
        await McpSession("kb", http(boom)).initialize()
    assert "SECRET" not in str(e.value)

    import asyncio

    def slow(req: httpx.Request) -> httpx.Response:
        return standard(req)

    t = http(slow, call_timeout_seconds=0.05)

    async def never(*_a: Any, **_k: Any) -> Any:
        await asyncio.sleep(5)

    t._client.send = never  # type: ignore[method-assign]
    with pytest.raises(McpTransportError):
        await McpSession("kb", t).initialize()


@pytest.mark.parametrize(
    "url",
    [
        "http://mcp.example.com/mcp",  # plain http
        "https://127.0.0.1/mcp",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/mcp",
        "https://user:pw@mcp.example.com/mcp",
        "https://[::1]/mcp",
        "https://mcp.example.com:8443/mcp",
        "https://2130706433/mcp",
    ],
)
async def test_http_ssrf_guard_applies_to_every_request(url: str) -> None:
    hits: list[httpx.Request] = []
    cfg = ServerConfig("t", "kb", "http", url=url)
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: standard(r, hits)))
    t = StreamableHttpTransport(cfg, McpLimits(), resolver=public, client=client)
    with pytest.raises(McpTransportError):
        await McpSession("kb", t).initialize()
    assert hits == []  # nothing was sent


async def test_http_ssrf_guard_catches_dns_to_private_and_allow_private_opt_in() -> None:
    async def private(host: str, port: int) -> list[str]:
        return ["10.0.0.5"]

    hits: list[httpx.Request] = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: standard(r, hits)))
    cfg = ServerConfig("t", "kb", "http", url=URL)
    with pytest.raises(McpTransportError):
        await McpSession(
            "kb", StreamableHttpTransport(cfg, McpLimits(), resolver=private, client=client)
        ).initialize()
    assert hits == []
    opt_in = ServerConfig("t", "kb", "http", url=URL, allow_private=True)
    await McpSession(
        "kb", StreamableHttpTransport(opt_in, McpLimits(), resolver=private, client=client)
    ).initialize()
    assert hits


async def test_http_config_without_url_and_owned_client() -> None:
    with pytest.raises(McpTransportError):
        StreamableHttpTransport(ServerConfig("t", "kb", "http"), McpLimits(), resolver=public)
    t = StreamableHttpTransport(
        ServerConfig("t", "kb", "http", url=URL), McpLimits(), resolver=public
    )
    await t.close()  # owns and closes its client; no session so no DELETE


async def test_http_body_reading_stops_at_the_cap_instead_of_buffering_an_endless_stream() -> None:
    import asyncio

    produced = [0]

    async def endless() -> Any:
        while True:
            produced[0] += 4096
            yield b"x" * 4096

    def handler(req: httpx.Request) -> httpx.Response:
        if rpc(req).get("method") != "tools/call":
            return standard(req)
        return httpx.Response(200, content=endless(), headers={"content-type": "application/json"})

    s = McpSession("kb", http(handler, max_message_bytes=10_000, call_timeout_seconds=5))
    await s.initialize()
    with pytest.raises(McpResponseTooLarge):
        await asyncio.wait_for(s.invoke_tool("t", {}), 2)  # the parser's own check never runs
    assert produced[0] <= 10_000 + 2 * 4096  # we stopped reading at the cap
