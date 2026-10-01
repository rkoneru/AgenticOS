"""``TenantMcpClient``: the ``McpClient`` backend the ActionExecutor hands to ``McpCall``.

One instance serves ONE tenant: ``call_tool(server, tool, args)`` resolves ``server`` through that
tenant's registry entries only, so a manifest that names another tenant's server (or a made-up one)
fails with the same ``McpServerNotAllowed``.  The tool must be one the server actually listed
(sanitised, namespaced ``server/tool``) and pass the entry's optional ``allow_tools``.  The
arguments are forwarded untouched.  This class is only reachable through ``McpCall._execute``
(bypass_scan.py ``call_tool`` restriction); it never decides policy and has no way to change it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from axis_runtime.mcp.client import McpSession, RemoteTool, Transport
from axis_runtime.mcp.config import (
    TOOL_NAME,
    McpLimits,
    McpServerRegistry,
    ServerConfig,
    qualify,
)
from axis_runtime.mcp.errors import McpToolNotAllowed, McpTransportError
from axis_runtime.mcp.http import StreamableHttpTransport
from axis_runtime.mcp.stdio import StdioTransport
from axis_runtime.models.adapters.base import default_resolver
from axis_runtime.models.endpoints import Resolver
from axis_runtime.models.types import ToolDefinition

if TYPE_CHECKING:
    from axis_runtime.manifest import RuntimeManifest

TransportFactory = Callable[[ServerConfig], Transport]


@dataclass
class _Conn:
    session: McpSession
    tools: dict[str, RemoteTool] = field(default_factory=dict)
    fetched_at: float | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class TenantMcpClient:
    def __init__(
        self,
        registry: McpServerRegistry,
        tenant_id: str,
        *,
        limits: McpLimits | None = None,
        resolver: Resolver | None = None,
        http_client: Any = None,
        allow_http: bool = False,
        extra_ports: frozenset[int] = frozenset(),
        transport_factory: TransportFactory | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._registry = registry
        self._tenant = tenant_id
        self._limits = limits or McpLimits()
        self._resolver = resolver
        self._http_client = http_client
        self._allow_http = allow_http
        self._extra_ports = extra_ports
        self._factory = transport_factory
        self._now = monotonic
        self._conns: dict[str, _Conn] = {}
        self._creating = asyncio.Lock()

    # ---- connections -------------------------------------------------------------------------
    def _transport(self, cfg: ServerConfig) -> Transport:
        if self._factory is not None:
            return self._factory(cfg)
        if cfg.transport == "stdio" and cfg.command is not None:
            return StdioTransport(cfg.command, self._limits)
        if cfg.transport == "http":
            return StreamableHttpTransport(
                cfg,
                self._limits,
                resolver=self._resolver or default_resolver(),
                client=self._http_client,
                allow_http=self._allow_http,
                extra_ports=self._extra_ports,
            )
        raise McpTransportError("unsupported transport")

    async def _connection(self, cfg: ServerConfig) -> _Conn:
        async with self._creating:
            conn = self._conns.get(cfg.name)
            if conn is not None:
                return conn
            session = McpSession(cfg.name, self._transport(cfg), self._limits)
            try:
                await asyncio.wait_for(session.initialize(), self._limits.connect_timeout_seconds)
            except BaseException:
                await session.close()
                raise
            conn = _Conn(session)
            self._conns[cfg.name] = conn
            return conn

    async def _drop(self, name: str) -> None:
        conn = self._conns.pop(name, None)
        if conn is not None:
            await conn.session.close()

    async def _tools(
        self, cfg: ServerConfig, conn: _Conn, *, refresh: bool
    ) -> dict[str, RemoteTool]:
        async with conn.lock:
            stale = (
                conn.fetched_at is None
                or self._now() - conn.fetched_at > self._limits.tool_list_ttl_seconds
            )
            if refresh or stale:
                listing = await conn.session.list_tools()
                conn.tools = {
                    t.name: t
                    for t in listing.tools
                    if cfg.allow_tools is None or t.name in cfg.allow_tools
                }
                conn.fetched_at = self._now()
            return conn.tools

    # ---- public ------------------------------------------------------------------------------
    async def list_tools(self, server: str) -> tuple[RemoteTool, ...]:
        cfg = self._registry.lookup(self._tenant, server)
        conn = await self._connection(cfg)
        try:
            return tuple((await self._tools(cfg, conn, refresh=False)).values())
        except McpTransportError:
            await self._drop(cfg.name)
            raise

    async def definitions_for(self, manifest: RuntimeManifest) -> dict[str, ToolDefinition]:
        """Model-facing definitions for the manifest's ``mcp`` tools, keyed by manifest tool name.
        Descriptions are sanitised, truncated data; they confer no capability."""
        out: dict[str, ToolDefinition] = {}
        for spec in manifest.tools:
            if spec.kind != "mcp":
                continue
            remote = spec.ref or spec.name
            tools = {t.name: t for t in await self.list_tools(spec.mcp_server or "")}
            tool = tools.get(remote)
            if tool is not None:
                out[spec.name] = ToolDefinition(spec.name, tool.description, tool.input_schema)
        return out

    async def call_tool(self, server: str, name: str, args: Mapping[str, Any]) -> Any:
        cfg = self._registry.lookup(self._tenant, server)
        if not TOOL_NAME.match(name):
            raise McpToolNotAllowed("invalid MCP tool name")
        if self._registry.reserved(qualify(server, name)):
            raise McpToolNotAllowed("MCP tool would shadow a built-in")
        try:
            conn = await self._connection(cfg)
            tools = await self._tools(cfg, conn, refresh=False)
            if name not in tools:  # may be new: one refresh, then fail closed
                tools = await self._tools(cfg, conn, refresh=True)
            if name not in tools:
                raise McpToolNotAllowed("tool is not offered by this server for this tenant")
            return await conn.session.invoke_tool(name, args)
        except McpToolNotAllowed:
            raise
        except McpTransportError:
            await self._drop(cfg.name)
            raise

    async def aclose(self) -> None:
        for name in list(self._conns):
            await self._drop(name)
