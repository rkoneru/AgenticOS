"""MCP (Model Context Protocol) client and server for the AXIS runtime. See docs/spec/mcp.md."""

from axis_runtime.mcp.backend import TenantMcpClient
from axis_runtime.mcp.client import McpSession, RemoteTool
from axis_runtime.mcp.config import (
    McpLimits,
    McpServerRegistry,
    ServerConfig,
    StdioCommand,
    qualify,
)
from axis_runtime.mcp.errors import (
    McpProtocolError,
    McpResponseTooLarge,
    McpServerNotAllowed,
    McpSessionExpired,
    McpToolNotAllowed,
    McpTransportError,
)
from axis_runtime.mcp.http_server import McpHttpServer
from axis_runtime.mcp.server import (
    Authenticator,
    ExposedTool,
    McpServer,
    Principal,
    ServerLimits,
    TenantToolCatalog,
    mcp_identity,
)

__all__ = [
    "Authenticator",
    "ExposedTool",
    "McpHttpServer",
    "McpLimits",
    "McpProtocolError",
    "McpResponseTooLarge",
    "McpServer",
    "McpServerNotAllowed",
    "McpServerRegistry",
    "McpSession",
    "McpSessionExpired",
    "McpToolNotAllowed",
    "McpTransportError",
    "Principal",
    "RemoteTool",
    "ServerConfig",
    "ServerLimits",
    "StdioCommand",
    "TenantMcpClient",
    "TenantToolCatalog",
    "mcp_identity",
    "qualify",
]
