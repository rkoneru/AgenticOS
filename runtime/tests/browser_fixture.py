"""A tiny local HTTP/WebSocket fixture server for browser tests (no internet).

Two instances are used: ``main`` (the allowlisted site) and ``evil`` (a different PORT on the same
loopback IP, so allowlist-by-port is exercised too). Both log every request and every raw connection,
so a test can assert that a blocked request NEVER reached the server.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass
class Req:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes = b""


@dataclass
class Resp:
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | str = b""


Handler = Callable[[Req], Resp]


class FixtureServer:
    def __init__(self, name: str) -> None:
        self.name = name
        self.routes: dict[str, Handler] = {}
        self.requests: list[Req] = []
        self.connections = 0
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    def paths(self) -> list[str]:
        return [r.path for r in self.requests]

    def hosts(self) -> list[str]:
        return [r.headers.get("host", "") for r in self.requests]

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = b""
        if (n := int(headers.get("content-length", "0"))) > 0:
            body = await reader.readexactly(n)
        req = Req(method, path, headers, body)
        self.requests.append(req)
        try:
            if headers.get("upgrade", "").lower() == "websocket":
                await self._websocket(req, writer)
                return
            handler = self.routes.get(path.split("?")[0])
            resp = handler(req) if handler else Resp(404, body=b"not found")
            payload = resp.body.encode() if isinstance(resp.body, str) else resp.body
            hdrs = {"content-type": "text/html; charset=utf-8", **resp.headers}
            hdrs["content-length"] = str(len(payload))
            hdrs["connection"] = "close"
            out = f"HTTP/1.1 {resp.status} X\r\n" + "".join(
                f"{k}: {v}\r\n" for k, v in hdrs.items()
            )
            writer.write(out.encode() + b"\r\n" + payload)
            await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def _websocket(self, req: Req, writer: asyncio.StreamWriter) -> None:
        key = req.headers["sec-websocket-key"]
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()  # noqa: S324
        writer.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        writer.write(b"\x81\x0bws-hello-ok")  # one unmasked text frame
        await writer.drain()
        await asyncio.sleep(0.3)


def page(body: str, title: str = "Fixture") -> str:
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"
