# ruff: noqa: S107
"""The stdlib asyncio HTTP front end, exercised over a real loopback socket."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from axis_runtime.mcp import McpHttpServer, McpServer, ServerLimits
from test_mcp_server import Harness


@pytest.fixture
async def srv() -> AsyncIterator[tuple[McpHttpServer, Harness]]:
    h = Harness(max_request_bytes=2000)
    s = McpHttpServer(
        h.server,
        allowed_origins=frozenset({"https://app.example.com"}),
        read_timeout_seconds=0.5,
        max_connections=4,
    )
    await s.start()
    yield s, h
    await s.stop()


async def raw_http(
    port: int, data: bytes, *, read: bool = True
) -> tuple[int, dict[str, str], bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    try:
        blob = await asyncio.wait_for(reader.read(-1), 3) if read else b""
    except ConnectionResetError:  # the server shed us before reading the request
        blob = b""
    writer.close()
    if not blob:
        return 0, {}, b""
    head, _, body = blob.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    headers = {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines[1:])}
    return int(lines[0].split()[1]), headers, body


def request(
    body: bytes | None = None,
    *,
    method: str = "POST",
    path: str = "/mcp",
    token: str | None = "tok-alice",
    extra: dict[str, str] | None = None,
    ctype: str | None = "application/json",
    length: str | None = None,
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", "Host: x"]
    if token:
        lines.append(f"Authorization: Bearer {token}")
    if ctype:
        lines.append(f"Content-Type: {ctype}")
    for k, v in (extra or {}).items():
        lines.append(f"{k}: {v}")
    body = body if body is not None else b""
    lines.append(f"Content-Length: {length if length is not None else len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def rpc_body(method: str, params: Any = None, rid: Any = 1) -> bytes:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


async def test_end_to_end_call_over_http(srv: tuple[McpHttpServer, Harness]) -> None:
    s, h = srv
    status, headers, body = await raw_http(s.port, request(rpc_body("tools/list")))
    assert status == 200 and headers["content-type"] == "application/json"
    assert headers["connection"] == "close" and int(headers["content-length"]) == len(body)
    assert {t["name"] for t in json.loads(body)["result"]["tools"]} >= {"lookup"}
    call = rpc_body("tools/call", {"name": "lookup", "arguments": {"q": "hi"}}, rid="r1")
    status, _, body = await raw_http(s.port, request(call))
    out = json.loads(body)
    assert status == 200 and out["id"] == "r1" and out["result"]["isError"] is False
    assert h.gate.requests[-1].actor_type.value == "mcp_client"


async def test_http_auth_and_notification_statuses(srv: tuple[McpHttpServer, Harness]) -> None:
    s, _ = srv
    status, headers, body = await raw_http(s.port, request(rpc_body("ping"), token=None))
    assert status == 401 and headers["www-authenticate"] == "Bearer"
    assert json.loads(body)["error"]["code"] == -32001
    status, _, body = await raw_http(s.port, request(rpc_body("ping"), token="wrong"))
    assert status == 401
    note = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    status, headers, body = await raw_http(s.port, request(note))
    assert status == 202 and body == b"" and "content-type" not in headers


@pytest.mark.parametrize(
    ("data", "status"),
    [
        (request(b"{}", method="GET"), 405),
        (request(b"{}", method="DELETE"), 405),
        (request(b"{}", path="/other"), 404),
        (request(b"{}", ctype="text/plain"), 415),
        (request(b"{}", ctype=None), 415),
        (request(b"{}", extra={"Origin": "https://evil.example.com"}), 403),
        (request(b"{}", extra={"Transfer-Encoding": "chunked"}), 400),
        (request(b"{}", length="abc"), 400),
        (request(b"{}", length="-1"), 400),
        (request(b"{}", length=""), 400),
        (request(b"x", length="999999"), 413),
        (request(b"{}", extra={"Authorization": "Bearer other"}), 400),  # duplicate header
        (b"GARBAGE\r\n\r\n", 400),
        (b"POST /mcp SPDY/3\r\n\r\n", 400),
        (b"POST /mcp HTTP/1.1\r\nbad header line\r\n\r\n", 400),
        (b"POST /mcp HTTP/1.1\r\n Leading: space\r\n\r\n", 400),
        (b"POST /mcp HTTP/1.1\r\n" + b"X: " + b"a" * 40000 + b"\r\n\r\n", 431),
    ],
)
async def test_http_rejections(
    srv: tuple[McpHttpServer, Harness], data: bytes, status: int
) -> None:
    s, h = srv
    got, headers, _ = await raw_http(s.port, data)
    assert got == status
    if status == 405:
        assert headers["allow"] == "POST"
    assert h.gate.requests == [] and h.performed == []


async def test_transfer_encoding_with_a_valid_body_is_still_refused(
    srv: tuple[McpHttpServer, Harness],
) -> None:
    s, h = srv
    data = request(rpc_body("ping"), extra={"Transfer-Encoding": "chunked"})
    status, _, _ = await raw_http(s.port, data)
    assert status == 400  # never guess framing when both are present (request smuggling)


async def test_http_allowed_origin_and_query_string_path(
    srv: tuple[McpHttpServer, Harness],
) -> None:
    s, _ = srv
    data = request(rpc_body("ping"), path="/mcp?x=1", extra={"Origin": "https://app.example.com"})
    status, _, _ = await raw_http(s.port, data)
    assert status == 200


async def test_http_slowloris_and_truncated_body_time_out(
    srv: tuple[McpHttpServer, Harness],
) -> None:
    s, _ = srv
    status, _, _ = await raw_http(s.port, b"POST /mcp HTTP/1.1\r\nHost: x\r\n")  # never finishes
    assert status == 408
    head = request(b"x" * 10, length="100")[:-10]  # promises 100 bytes, sends none
    status, _, _ = await raw_http(s.port, head)
    assert status == 408


async def test_http_client_disconnect_mid_body_is_harmless(
    srv: tuple[McpHttpServer, Harness],
) -> None:
    s, h = srv
    reader, writer = await asyncio.open_connection("127.0.0.1", s.port)
    writer.write(request(b"x" * 5, length="100")[:-5])
    await writer.drain()
    writer.close()
    await asyncio.sleep(0.1)
    status, _, _ = await raw_http(s.port, request(rpc_body("ping")))
    assert status == 200


async def test_http_connection_cap() -> None:
    h = Harness()
    s = McpHttpServer(h.server, max_connections=1, read_timeout_seconds=2.0)
    await s.start()
    try:
        r1, w1 = await asyncio.open_connection("127.0.0.1", s.port)  # holds the only slot
        w1.write(b"POST /mcp HTTP/1.1\r\n")
        await w1.drain()
        await asyncio.sleep(0.1)
        status, _, _ = await raw_http(s.port, request(rpc_body("ping")))
        assert status in (0, 503)  # shed: 503, or a reset if the close raced the reply
        assert h.gate.requests == []
        w1.close()
    finally:
        await s.stop()


async def test_http_internal_failure_is_a_generic_500() -> None:
    h = Harness()

    async def explode(raw: bytes, bearer: str | None) -> Any:
        raise RuntimeError("traceback with /srv/secret")

    h.server.handle = explode  # type: ignore[method-assign]
    s = McpHttpServer(h.server)
    await s.start()
    try:
        status, _, body = await raw_http(s.port, request(rpc_body("ping")))
        assert (
            status == 500
            and b"secret" not in body
            and json.loads(body)["error"]["message"] == "internal error"
        )
    finally:
        await s.stop()


async def test_http_port_requires_start_and_stop_is_idempotent() -> None:
    s = McpHttpServer(Harness().server)
    with pytest.raises(RuntimeError):
        _ = s.port
    await s.stop()
    await s.start()
    await s.stop()
    await s.stop()


def test_server_limits_defaults_are_sane() -> None:
    lim = ServerLimits()
    assert lim.max_request_bytes <= 1 << 20 and lim.burst >= 1
    assert McpServer.__name__ == "McpServer"
