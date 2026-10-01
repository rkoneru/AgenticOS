"""Fakes for MCP tests: an in-memory scripted server transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from axis_runtime.mcp import protocol


class FakeTransport:
    """Plays an MCP server in memory. ``tools`` is the tools/list payload; ``on_call`` builds the
    tools/call result. Every message the client sent is recorded in ``sent``."""

    def __init__(
        self,
        tools: list[Any] | None = None,
        on_call: Callable[[str, Mapping[str, Any]], Any] | None = None,
        *,
        version: str = "2025-06-18",
        extra_before_response: list[dict[str, Any]] | None = None,
    ) -> None:
        self.tools = tools if tools is not None else [tool("search")]
        self.on_call = on_call or (lambda n, a: {"content": [{"type": "text", "text": "ok"}]})
        self.version = version
        self.sent: list[dict[str, Any]] = []
        self.replies: list[dict[str, Any]] = []  # what route_incoming told us to say back
        self.extra = extra_before_response or []
        self.closed = False
        self.pages: list[dict[str, Any]] | None = None
        self.list_calls = 0

    def set_protocol_version(self, version: str) -> None:
        self.negotiated = version

    async def close(self) -> None:
        self.closed = True

    async def exchange(self, message: Mapping[str, Any], expect_id: Any) -> dict[str, Any] | None:
        self.sent.append(dict(message))
        if expect_id is None:
            return None
        for extra in self.extra:  # unsolicited server traffic arrives first
            _, reply = protocol.route_incoming(extra, expect_id)
            if reply is not None:
                self.replies.append(reply)
        method, params = message["method"], message.get("params") or {}
        if method == "initialize":
            result: Any = {"protocolVersion": self.version, "capabilities": {}}
        elif method == "tools/list":
            self.list_calls += 1
            if self.pages is not None:
                result = self.pages[min(self.list_calls - 1, len(self.pages) - 1)]
            else:
                result = {"tools": self.tools}
        elif method == "tools/call":
            result = self.on_call(params["name"], params["arguments"])
            if isinstance(result, Exception):
                raise result
        else:
            return protocol.error_response(expect_id, protocol.METHOD_NOT_FOUND, "nope")
        return protocol.result_response(expect_id, result)


def tool(name: str, description: str = "d", schema: Any = None, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": schema if schema is not None else {"type": "object"},
        **extra,
    }
