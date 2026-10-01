"""Minimal HTTP/1.1 front for ``McpServer`` (stdlib asyncio streams, no extra dependencies).

Deliberately small and strict: ``POST`` to one path, ``Content-Length`` body (no chunked
encoding), bounded request line and headers, bounded body, per-connection read deadline, one
request per connection (``Connection: close``), JSON responses only (no SSE; the spec allows a
server to answer ``GET`` with 405).  ``Origin`` is checked against an allowlist when present
(DNS-rebinding defence, MCP transport spec).  Binds to loopback unless told otherwise; TLS is
the deployment's job (reverse proxy), see docs/NEEDS.md #102.
"""

from __future__ import annotations

import asyncio

from axis_runtime.mcp import protocol
from axis_runtime.mcp.server import McpServer, Reply, bearer_from_header

_STATUS = {
    200: "OK",
    202: "Accepted",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
_HEADER_LIMIT = 16 * 1024


class McpHttpServer:
    def __init__(
        self,
        server: McpServer,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        path: str = "/mcp",
        allowed_origins: frozenset[str] = frozenset(),
        read_timeout_seconds: float = 10.0,
        max_connections: int = 256,
    ) -> None:
        self._server = server
        self._host, self._port, self._path = host, port, path
        self._origins = allowed_origins
        self._timeout = read_timeout_seconds
        self._max_connections = max_connections
        self._active = 0
        self._srv: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._srv is None or not self._srv.sockets:
            raise RuntimeError("server not started")
        return int(self._srv.sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._srv = await asyncio.start_server(
            self._connection, self._host, self._port, limit=_HEADER_LIMIT * 2
        )

    async def stop(self) -> None:
        if self._srv is not None:
            self._srv.close()
            await self._srv.wait_closed()
            self._srv = None

    # ---- one connection ----------------------------------------------------------------------
    async def _connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active >= self._max_connections:
            await self._write(writer, Reply(503, None))
            return
        self._active += 1
        try:
            reply = await asyncio.wait_for(self._serve(reader), self._timeout)
        except TimeoutError:
            reply = Reply(408, None)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - never leak internals
            reply = Reply(500, _internal())
        finally:
            self._active -= 1
        await self._write(writer, reply)

    async def _serve(self, reader: asyncio.StreamReader) -> Reply:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            return Reply(431, None)
        if len(head) > _HEADER_LIMIT:
            return Reply(431, None)
        lines = head[:-4].decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            return Reply(400, None)
        method, target, _version = parts
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            key = name.strip().lower()
            if not sep or not key or name != name.strip():
                return Reply(400, None)
            if key in headers and key in {"content-length", "authorization", "origin", "host"}:
                return Reply(400, None)  # duplicates of these are request-smuggling material
            headers[key] = value.strip()
        if target.split("?", 1)[0] != self._path:
            return Reply(404, None)
        if method != "POST":
            return Reply(405, None, (("Allow", "POST"),))
        origin = headers.get("origin")
        if origin is not None and origin not in self._origins:
            return Reply(403, None)
        if "transfer-encoding" in headers:
            return Reply(400, None)
        if headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return Reply(415, None)
        length = headers.get("content-length", "")
        if not length.isascii() or not length.isdigit():
            return Reply(400, None)
        if int(length) > self._server.limits.max_request_bytes:
            return Reply(413, _too_large())
        body = await reader.readexactly(int(length))
        return await self._server.handle(body, bearer_from_header(headers.get("authorization")))

    async def _write(self, writer: asyncio.StreamWriter, reply: Reply) -> None:
        body = reply.body or b""
        head = [f"HTTP/1.1 {reply.status} {_STATUS.get(reply.status, 'Status')}"]
        head.append("Connection: close")
        if reply.body is not None:
            head.append("Content-Type: application/json")
        head.append(f"Content-Length: {len(body)}")
        head += [f"{k}: {_clean(v)}" for k, v in reply.headers]
        try:
            writer.write(("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body)
            await writer.drain()
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass


def _clean(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ")


def _internal() -> bytes:
    return protocol.dumps(
        protocol.error_response(None, protocol.INTERNAL_ERROR, "internal error")
    ).encode()


def _too_large() -> bytes:
    return protocol.dumps(
        protocol.error_response(None, protocol.REQUEST_TOO_LARGE, "request too large")
    ).encode()


__all__ = ["McpHttpServer"]
