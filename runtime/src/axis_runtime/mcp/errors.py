"""MCP errors. Messages are fixed strings or codes, NEVER server-controlled text (untrusted; it
would end up in audit events and, via the executor, in front of a model)."""

from __future__ import annotations

from axis_runtime.tools import McpError


class McpTransportError(McpError):
    """Connect, framing, timeout or HTTP-level failure."""


class McpResponseTooLarge(McpTransportError):
    """A message or result exceeded its byte cap."""


class McpProtocolError(McpError):
    """The peer violated JSON-RPC / MCP (or returned a JSON-RPC error; ``code`` is the peer's)."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class McpSessionExpired(McpTransportError):
    """The HTTP server forgot our session (404 with a session id)."""


class McpServerNotAllowed(McpError):
    """The server name is not in this tenant's allowlist (or the config is unacceptable)."""


class McpToolNotAllowed(McpError):
    """The tool is not offered by the server, or not allowed for this tenant's server entry."""
