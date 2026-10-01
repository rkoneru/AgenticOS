"""MCP client configuration: limits, operator stdio catalog, tenant-scoped server registry.

Trust model (docs/spec/mcp.md):

* The OPERATOR owns ``StdioCommand`` entries (absolute argv, a fixed environment).  Tenants can
  only *select* one by id; they never supply a command, an argument, an environment variable or a
  working directory.  A tenant that tries to name an id the operator did not publish is refused.
* Tenants may register HTTP servers, but the URL must pass the endpoint SSRF guard
  (``models/endpoints.py``) every time it is used.
* A manifest ``mcp_server`` is only a *name*; it resolves through the calling tenant's own entries,
  so one tenant can never reach (or learn about) another tenant's servers.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from axis_runtime.mcp.errors import McpServerNotAllowed

if TYPE_CHECKING:
    from axis_runtime.manifest import RuntimeManifest

SERVER_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}\Z")
#: MCP tool names as the spec allows them. ``/`` is deliberately absent: it is the namespace
#: separator, so no server can mint a name that looks like another server's ``server/tool``.
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}\Z")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}\Z")
_FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "accept",
        "mcp-session-id",
        "mcp-protocol-version",
        "transfer-encoding",
        "connection",
        "cookie",
    }
)


def qualify(server: str, tool: str) -> str:
    """The namespaced name policies, audit events and models see: ``server/tool``."""
    return f"{server}/{tool}"


@dataclass(frozen=True)
class McpLimits:
    call_timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 10.0
    max_message_bytes: int = 1 << 20  # one JSON-RPC message from a server
    max_result_bytes: int = 256 << 10  # tool result after normalisation
    max_description_chars: int = 1024
    max_schema_bytes: int = 16 << 10
    max_tools_per_server: int = 256
    max_list_pages: int = 8
    max_content_items: int = 64
    tool_list_ttl_seconds: float = 300.0

    def __post_init__(self) -> None:
        values = (
            self.call_timeout_seconds,
            self.connect_timeout_seconds,
            self.max_message_bytes,
            self.max_result_bytes,
            self.max_description_chars,
            self.max_schema_bytes,
            self.max_tools_per_server,
            self.max_list_pages,
            self.max_content_items,
        )
        if any(v <= 0 for v in values):
            raise ValueError("limits must be positive")


@dataclass(frozen=True)
class StdioCommand:
    """An operator-approved subprocess. ``env`` is the ENTIRE environment (nothing is inherited)."""

    argv: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None

    def __post_init__(self) -> None:
        if not self.argv or not self.argv[0].startswith("/"):
            raise ValueError("argv[0] must be an absolute path")
        if any("\x00" in a for a in self.argv):
            raise ValueError("argv contains NUL")
        for k, v in self.env.items():
            if not k or "=" in k or "\x00" in k or "\x00" in v:
                raise ValueError("invalid environment entry")
        if self.cwd is not None and not self.cwd.startswith("/"):
            raise ValueError("cwd must be absolute")


@dataclass(frozen=True)
class ServerConfig:
    tenant_id: str
    name: str
    transport: str  # "http" | "stdio"
    url: str | None = None
    command: StdioCommand | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    #: Optional restriction to specific remote tool names (None = every well-formed listed tool).
    allow_tools: frozenset[str] | None = None
    allow_private: bool = False


class McpServerRegistry:
    """Tenant-scoped allowlist of MCP servers."""

    def __init__(
        self,
        *,
        stdio_catalog: Mapping[str, StdioCommand] | None = None,
        reserved_tool_names: Collection[str] = (),
    ) -> None:
        self._catalog = dict(stdio_catalog or {})
        self._reserved = frozenset(reserved_tool_names)
        self._servers: dict[tuple[str, str], ServerConfig] = {}

    # ---- registration ------------------------------------------------------------------------
    def _check_name(self, tenant_id: str, name: str) -> None:
        if not tenant_id:
            raise McpServerNotAllowed("tenant id required")
        if not SERVER_NAME.match(name):
            raise McpServerNotAllowed("invalid server name")

    def register_http(
        self,
        tenant_id: str,
        name: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        allow_tools: Collection[str] | None = None,
        allow_private: bool = False,
    ) -> ServerConfig:
        self._check_name(tenant_id, name)
        clean = dict(headers or {})
        for k, v in clean.items():
            if (
                not _HEADER_NAME.match(k)
                or k.lower() in _FORBIDDEN_HEADERS
                or any(c in v for c in "\r\n\x00")
            ):
                raise McpServerNotAllowed("invalid header")
        cfg = ServerConfig(
            tenant_id,
            name,
            "http",
            url=url,
            headers=clean,
            allow_tools=self._tools(name, allow_tools),
            allow_private=allow_private,
        )
        self._servers[(tenant_id, name)] = cfg
        return cfg

    def register_stdio(
        self,
        tenant_id: str,
        name: str,
        command_id: str,
        *,
        allow_tools: Collection[str] | None = None,
    ) -> ServerConfig:
        """Select an operator-published command by id. There is no way to pass a raw command."""
        self._check_name(tenant_id, name)
        command = self._catalog.get(command_id)
        if command is None:
            raise McpServerNotAllowed("stdio command is not in the operator allowlist")
        cfg = ServerConfig(
            tenant_id,
            name,
            "stdio",
            command=command,
            allow_tools=self._tools(name, allow_tools),
        )
        self._servers[(tenant_id, name)] = cfg
        return cfg

    def _tools(self, server: str, allow: Collection[str] | None) -> frozenset[str] | None:
        if allow is None:
            return None
        tools = frozenset(allow)
        for tool in tools:
            if not TOOL_NAME.match(tool):
                raise McpServerNotAllowed("invalid tool name in allowlist")
            if qualify(server, tool) in self._reserved:
                raise McpServerNotAllowed("tool would shadow a built-in")
        return tools

    # ---- lookup ------------------------------------------------------------------------------
    def lookup(self, tenant_id: str, name: str) -> ServerConfig:
        """The tenant's entry, else ``McpServerNotAllowed`` (same error for unknown / not yours)."""
        cfg = self._servers.get((tenant_id, name))
        if cfg is None:
            raise McpServerNotAllowed("MCP server is not allowed for this tenant")
        return cfg

    def servers(self, tenant_id: str) -> tuple[str, ...]:
        return tuple(sorted(n for (t, n) in self._servers if t == tenant_id))

    def reserved(self, qualified: str) -> bool:
        return qualified in self._reserved

    def check_manifest(self, tenant_id: str, manifest: RuntimeManifest) -> None:
        """Spawn-time validation: every ``mcp`` tool names an allowed server and none of the
        namespaced names collides with a non-MCP tool or a reserved built-in."""
        non_mcp = {t.name for t in manifest.tools if t.kind != "mcp"}
        for spec in manifest.tools:
            if spec.kind != "mcp":
                continue
            server = spec.mcp_server or ""
            self.lookup(tenant_id, server)
            remote = spec.ref or spec.name
            if not TOOL_NAME.match(remote):
                raise McpServerNotAllowed("invalid MCP tool name")
            q = qualify(server, remote)
            if q in non_mcp or self.reserved(q):
                raise McpServerNotAllowed("MCP tool would shadow a built-in tool")
