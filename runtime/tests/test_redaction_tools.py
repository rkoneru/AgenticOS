"""Redaction paths and side-effect backends (tool registry, HTTP MCP client)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from axis_runtime.redaction import (
    REDACTED,
    RedactionPathError,
    parse_path,
    redact_paths,
    split_scope,
)
from axis_runtime.tools import (
    HttpMcpClient,
    McpError,
    ToolNotFoundError,
    ToolRegistry,
)

DOC = {
    "ssn": "1",
    "name": "Ada",
    "items": [{"email": "a@x", "n": 1}, {"email": "b@x", "n": 2}],
    "nested": {"deep": {"secret": "s"}},
}


def test_redacts_scalar_nested_indexed_and_wildcard_paths() -> None:
    out = redact_paths(DOC, ["ssn", "nested.deep.secret", "items.0.n", "items.*.email"])
    assert out["ssn"] == REDACTED and out["nested"]["deep"]["secret"] == REDACTED
    assert out["items"] == [{"email": REDACTED, "n": REDACTED}, {"email": REDACTED, "n": 2}]
    assert out["name"] == "Ada"
    assert DOC["ssn"] == "1" and DOC["items"][0]["email"] == "a@x"  # input untouched


def test_wildcard_over_dict_values_and_whole_nodes() -> None:
    assert redact_paths({"a": 1, "b": 2}, ["*"]) == {"a": REDACTED, "b": REDACTED}
    assert redact_paths(DOC, ["nested"])["nested"] == REDACTED


@pytest.mark.parametrize(
    "path", ["missing", "items.9", "items.x", "ssn.deeper", "nested.nope.secret"]
)
def test_missing_paths_are_noops(path: str) -> None:
    assert redact_paths(DOC, [path]) == DOC


@pytest.mark.parametrize("path", ["", ".", "a..b", ".a", "a."])
def test_malformed_paths_raise_before_any_change(path: str) -> None:
    with pytest.raises(RedactionPathError):
        parse_path(path)
    with pytest.raises(RedactionPathError):
        redact_paths(DOC, ["ssn", path])


def test_scope_splitting() -> None:
    assert split_scope(["args.a", "result.b", "c", "args", "result"]) == (
        ["a", "c", "*"],
        ["b", "c", "*"],
    )


# ---- ToolRegistry ---------------------------------------------------------------------------


async def test_registry_sync_async_and_unknown() -> None:
    reg = ToolRegistry()
    reg.register("add", lambda a: a["x"] + 1)

    async def aadd(a: Any) -> Any:
        return a["x"] + 2

    reg.register("aadd", aadd, description="d", input_schema={"type": "object", "properties": {}})
    assert await reg.call("add", {"x": 1}) == 2
    assert await reg.call("aadd", {"x": 1}) == 3
    assert reg.get("aadd") is not None and reg.get("aadd").description == "d"  # type: ignore[union-attr]
    assert reg.get("nope") is None
    with pytest.raises(ToolNotFoundError):
        await reg.call("nope", {})


# ---- HttpMcpClient ---------------------------------------------------------------------------


def _client(handler: Any) -> HttpMcpClient:
    return HttpMcpClient(
        {"kb": "https://mcp.example/rpc"},
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


async def test_mcp_call_tool_request_shape_and_result() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "result": {"content": [{"text": "hi"}]}}
        )

    c = _client(handler)
    assert await c.call_tool("kb", "search", {"q": "x"}) == {"content": [{"text": "hi"}]}
    body = json.loads(seen[0].content)
    assert body == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"q": "x"}},
    }
    assert str(seen[0].url) == "https://mcp.example/rpc"
    await c.aclose()


@pytest.mark.parametrize(
    ("handler", "msg"),
    [
        (
            lambda r: httpx.Response(
                200, json={"error": {"code": -32000, "message": "secret detail"}}
            ),
            "MCP error -32000",
        ),
        (lambda r: httpx.Response(200, json={"error": "weird"}), "MCP error"),
        (lambda r: httpx.Response(500, text="oops"), "transport error: HTTPStatusError"),
        (lambda r: httpx.Response(200, text="not json"), "invalid JSON from MCP"),
        (lambda r: httpx.Response(200, json=[1]), "invalid JSON-RPC"),
        (lambda r: httpx.Response(200, json={"jsonrpc": "2.0"}), "invalid JSON-RPC"),
    ],
)
async def test_mcp_errors_are_sanitised(handler: Any, msg: str) -> None:
    c = _client(handler)
    with pytest.raises(McpError, match=msg) as exc:
        await c.call_tool("kb", "search", {})
    assert "secret detail" not in str(exc.value)


async def test_mcp_unknown_server_and_default_client() -> None:
    c = _client(lambda r: httpx.Response(200, json={"result": 1}))
    with pytest.raises(McpError, match="unknown MCP server"):
        await c.call_tool("other", "t", {})
    default = HttpMcpClient({"kb": "https://mcp.example/rpc"})
    await default.aclose()
