"""Side-effect backends used by Actions.  Network/process/file-IO primitives live HERE (and in
``axis_runtime.models.adapters``), never in the agent loop.

Only the function-tool registry and a minimal HTTP MCP client live here.  The code sandbox is
``axis_runtime.sandbox``; browser, memory and channel backends are interfaces only (Phase 4+);
see docs/NEEDS.md.
"""

from __future__ import annotations

import inspect
import itertools
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import httpx

if TYPE_CHECKING:
    from axis_runtime.manifest import RuntimeManifest
    from axis_runtime.models.types import ToolDefinition

ToolHandler = Callable[[Mapping[str, Any]], Any]


class ToolNotFoundError(KeyError):
    pass


class BackendUnavailableError(RuntimeError):
    """The Backends bundle has no implementation for the requested action kind."""


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    handler: ToolHandler
    description: str
    input_schema: Mapping[str, Any]


class ToolRegistry:
    """Function tools by name.  Handlers may be sync or async."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self,
        name: str,
        handler: ToolHandler,
        *,
        description: str = "",
        input_schema: Mapping[str, Any] | None = None,
    ) -> None:
        self._tools[name] = RegisteredTool(
            name, handler, description, input_schema or {"type": "object"}
        )

    def get(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name)

    async def call(self, name: str, args: Mapping[str, Any]) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFoundError(name)
        result = tool.handler(args)
        if inspect.isawaitable(result):
            result = await result
        return result


class McpClient(Protocol):
    async def call_tool(self, server: str, name: str, args: Mapping[str, Any]) -> Any: ...


class BrowserRunner(Protocol):
    async def run(self, args: Mapping[str, Any]) -> Any: ...


@runtime_checkable
class McpManifestSource(Protocol):
    """What the run needs of an MCP backend at SPAWN time (``mcp.backend.TenantMcpClient``): refuse
    a manifest naming servers or tools the tenant may not use, and the sanitised tool definitions
    the model is shown. A bare ``McpClient`` (e.g. ``HttpMcpClient``) offers neither."""

    def check_manifest(self, manifest: RuntimeManifest) -> None: ...

    async def definitions_for(self, manifest: RuntimeManifest) -> Mapping[str, ToolDefinition]: ...


class MemoryStore(Protocol):
    async def write(self, scope: str, args: Mapping[str, Any], *, agent: str | None = None) -> Any:
        """``agent``: the agent (manifest name) on whose behalf the write is made; it owns ``agent``
        scope memory. A child agent is not its root."""
        ...

    async def search(
        self,
        query: str,
        *,
        scopes: Sequence[str],
        limit: int,
        agent: str | None = None,
        kbs: Sequence[str] | None = None,
    ) -> Any: ...


class ChannelSender(Protocol):
    async def send(self, channel: str, args: Mapping[str, Any]) -> Any: ...


class SpawnHandler(Protocol):
    def __call__(self, ref: str, args: Mapping[str, Any]) -> Awaitable[Any]: ...


class McpError(RuntimeError):
    pass


class HttpMcpClient:
    """Minimal MCP-over-HTTP client (JSON-RPC 2.0 ``tools/call``, JSON responses only).

    No session negotiation, SSE responses or auth flows: Prototype.
    """

    def __init__(
        self,
        servers: Mapping[str, str],
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._servers = dict(servers)
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._ids = itertools.count(1)

    async def call_tool(self, server: str, name: str, args: Mapping[str, Any]) -> Any:
        url = self._servers.get(server)
        if url is None:
            raise McpError(f"unknown MCP server {server!r}")
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": "tools/call",
            "params": {"name": name, "arguments": dict(args)},
        }
        try:
            resp = await self._client.post(url, json=payload)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPError as exc:
            raise McpError(f"transport error: {type(exc).__name__}") from exc
        except ValueError as exc:
            raise McpError("invalid JSON from MCP server") from exc
        if not isinstance(body, dict):
            raise McpError("invalid JSON-RPC response")
        if "error" in body:
            err = body["error"]
            raise McpError(f"MCP error {err.get('code') if isinstance(err, dict) else ''}")
        if "result" not in body:
            raise McpError("invalid JSON-RPC response")
        return body["result"]

    async def aclose(self) -> None:
        await self._client.aclose()
