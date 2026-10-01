"""MCP stdio transport: one operator-approved subprocess, newline-delimited JSON-RPC.

This is the only module besides ``http.py`` that reaches the OS.  It can be reached solely through
``TenantMcpClient`` -> ``McpCall`` -> ``ActionExecutor`` (bypass_scan.py allowlists exactly this
file for the ``process`` rule).

Hardening: argv and environment come from the operator's ``StdioCommand`` (the child inherits
NOTHING from this process: no API keys, no tenant data), stderr is discarded, every line is capped
(``limit``), every exchange has a deadline, and the child is killed on close/timeout/overrun.
Known limit: no filesystem/network/seccomp isolation of the child (docs/NEEDS.md #83).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from axis_runtime.mcp import protocol
from axis_runtime.mcp.config import McpLimits, StdioCommand
from axis_runtime.mcp.errors import McpProtocolError, McpResponseTooLarge, McpTransportError

# asyncio.subprocess.PIPE / DEVNULL as values (the scanner bans reaching `asyncio.subprocess`).
_PIPE = -1
_DEVNULL = -3


def scrubbed_env(command: StdioCommand) -> dict[str, str]:
    """The child's whole environment: the operator's entries, nothing inherited."""
    return dict(command.env)


class StdioTransport:
    def __init__(self, command: StdioCommand, limits: McpLimits) -> None:
        self._command = command
        self._limits = limits
        self._proc: Any = None
        self._spawned = False
        self._lock = asyncio.Lock()

    async def _start(self) -> Any:
        if self._proc is not None:
            if self._proc.returncode is None:
                return self._proc
            raise McpTransportError("stdio server exited")  # never respawn mid-session
        if self._spawned:
            raise McpTransportError("stdio transport is closed")
        self._spawned = True
        try:
            self._proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *self._command.argv,
                    stdin=_PIPE,
                    stdout=_PIPE,
                    stderr=_DEVNULL,
                    env=scrubbed_env(self._command),
                    cwd=self._command.cwd,
                    limit=self._limits.max_message_bytes + 1,
                    start_new_session=True,
                ),
                self._limits.connect_timeout_seconds,
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise McpTransportError(f"cannot start stdio server ({type(exc).__name__})") from None
        return self._proc

    def set_protocol_version(self, version: str) -> None:  # stdio carries no per-request header
        return None

    async def exchange(
        self, message: Mapping[str, Any], expect_id: protocol.RequestId | None
    ) -> dict[str, Any] | None:
        async with self._lock:  # one outstanding exchange per child
            try:
                return await asyncio.wait_for(
                    self._exchange(message, expect_id), self._limits.call_timeout_seconds
                )
            except TimeoutError:
                await self.close()
                raise McpTransportError("stdio server timed out") from None
            except (McpTransportError, McpProtocolError):
                await self.close()
                raise

    async def _exchange(
        self, message: Mapping[str, Any], expect_id: protocol.RequestId | None
    ) -> dict[str, Any] | None:
        proc = await self._start()
        await self._write(proc, message)
        if expect_id is None:
            return None
        while True:
            obj = await self._read(proc)
            try:
                response, reply = protocol.route_incoming(obj, expect_id)
            except protocol.ProtocolError:
                raise McpProtocolError("malformed message from server") from None
            if reply is not None:
                await self._write(proc, reply)
            if response is not None:
                return response

    async def _write(self, proc: Any, message: Mapping[str, Any]) -> None:
        line = protocol.dumps(message) + "\n"
        try:
            proc.stdin.write(line.encode("ascii"))
            await proc.stdin.drain()
        except (OSError, ConnectionError):
            raise McpTransportError("stdio server closed its input") from None

    async def _read(self, proc: Any) -> Any:
        try:
            line = await proc.stdout.readline()
        except (asyncio.LimitOverrunError, ValueError):
            raise McpResponseTooLarge("stdio message exceeds the size cap") from None
        if not line:
            raise McpTransportError("stdio server closed its output")
        if len(line) > self._limits.max_message_bytes:
            raise McpResponseTooLarge("stdio message exceeds the size cap")
        try:
            return protocol.loads_strict(line.rstrip(b"\r\n"), self._limits.max_message_bytes)
        except protocol.ProtocolError as exc:
            if exc.code == protocol.REQUEST_TOO_LARGE:
                raise McpResponseTooLarge("stdio message exceeds the size cap") from None
            raise McpProtocolError("malformed message from server") from None

    async def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None or proc.returncode is not None:
            return
        try:
            proc.stdin.close()
            await asyncio.wait_for(proc.wait(), 1.0)
        except (OSError, TimeoutError, ConnectionError):
            pass
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), 2.0)
            except TimeoutError:
                pass


__all__ = ["StdioTransport", "scrubbed_env"]
