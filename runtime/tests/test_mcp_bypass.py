"""Bypass guard for the MCP path: IO grants are file-scoped, nothing may skip the gate."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import bypass_scan as bs
import pytest
from axis_runtime.actions import Backends, McpCall
from axis_runtime.executor import Completed, Denied
from axis_runtime.gate import ActorType, EnforcementPoint, EvaluateRequest, to_proto_request
from axis_runtime.mcp import McpServerRegistry, StdioCommand, TenantMcpClient
from conftest import TENANT, ScriptedGate, allow, deny
from helpers import PID, make_executor

FAKE = str(Path(__file__).with_name("fake_mcp_stdio.py"))


@pytest.mark.parametrize(
    ("rel", "source"),
    [
        ("mcp/backend.py", "import httpx"),  # only the transport module may import httpx
        ("mcp/client.py", "import httpx"),
        ("mcp/server.py", "import httpx"),
        ("mcp/http_server.py", "import httpx"),
        ("mcp/stdio.py", "import httpx"),
        ("mcp/http.py", "import subprocess"),
        ("mcp/http.py", "import socket"),
        ("mcp/stdio.py", "import subprocess"),
        ("mcp/stdio.py", "import socket"),
        ("mcp/http.py", "import asyncio\nasyncio.create_subprocess_exec('/bin/sh')"),  # no process
        ("mcp/http_server.py", "import asyncio\nasyncio.create_subprocess_exec('/bin/sh')"),
        ("mcp/server.py", "import asyncio\nasyncio.start_server(f, 'h', 1)"),  # no listener
        ("mcp/stdio.py", "import asyncio\nasyncio.start_server(f, 'h', 1)"),
        ("mcp/stdio.py", "import asyncio\nasyncio.open_connection('h', 1)"),
        ("mcp/http_server.py", "import asyncio\nasyncio.open_connection('h', 1)"),
        ("mcp/stdio.py", "import asyncio\nasyncio.subprocess.PIPE"),
        ("mcp/stdio.py", "import os\nos.system('id')"),
        ("mcp/stdio.py", "import os\nos.environ"),
        ("mcp/stdio.py", "eval('1')"),
        (
            "mcp/server.py",
            "await action.perform(token, backends)",
        ),  # the server must use the executor
        ("mcp/server.py", "await mcp.call_tool('s', 't', {})"),
        ("mcp/client.py", "await mcp.call_tool('s', 't', {})"),
        ("mcp/stdio.py", "await mcp.call_tool('s', 't', {})"),
        ("mcp/server.py", "x = action._execute(b)"),
        ("mcp/server.py", "from axis_runtime.executor import _TOKEN"),
        ("mcp/server.py", "from axis_runtime.guard import ExecutionToken"),
        ("mcp/backend.py", "import subprocess"),
        ("mcp/backend.py", "getattr(x, name)"),
    ],
)
def test_mcp_grants_do_not_leak_to_siblings_or_other_primitives(rel: str, source: str) -> None:
    assert bs.scan_source(rel, source) != [], f"{rel}: {source!r} must be flagged"


def test_mcp_grants_are_exactly_what_each_transport_needs() -> None:
    assert bs.scan_source("mcp/http.py", "import httpx") == []
    assert (
        bs.scan_source("mcp/stdio.py", "import asyncio\nasyncio.create_subprocess_exec('/x')") == []
    )
    assert (
        bs.scan_source("mcp/http_server.py", "import asyncio\nasyncio.start_server(f, 'h', 1)")
        == []
    )
    assert bs.scan_source("mcp/backend.py", "await mcp.call_tool('s', 't', {})") == []
    # and no other file got a process / net grant
    assert set(bs.EXEMPTIONS["process"]) == {"mcp/stdio.py"}
    assert set(bs.EXEMPTIONS["net"]) == {"mcp/http_server.py"}
    assert {f for f, g in bs.IO_IMPORTS.items() if "httpx" in g} >= {"mcp/http.py"}
    assert set(bs.RESTRICTED_NAMES["call_tool"]) == {"tools.py", "actions.py", "mcp/backend.py"}


def test_widening_member_allowlist_did_not_unban_the_primitives() -> None:
    for src in (
        "import asyncio\nasyncio.create_subprocess_exec('/x')",
        "import asyncio\nasyncio.start_server(f,'h',1)",
    ):
        assert bs.scan_source("run.py", src) != []
        assert bs.scan_source("tools.py", src) != []


def test_mcp_actor_type_has_a_wire_mapping() -> None:
    req = EvaluateRequest(
        tenant_id=TENANT,
        trace_id="c" * 32,
        span_id="d" * 16,
        actor_type=ActorType.MCP_CLIENT,
        actor_id="alice",
        pid=PID,
        blueprint_name="mcp-gateway",
        blueprint_version="1",
        enforcement_point=EnforcementPoint.MCP_CALL,
        action="kb/search",
        context={"actor": {"type": "mcp_client"}},
    )
    proto = to_proto_request(req)
    assert proto.actor.type == proto.actor.TYPE_SYSTEM and proto.actor.id == "alice"


def registry() -> McpServerRegistry:
    r = McpServerRegistry(
        stdio_catalog={"fake": StdioCommand((sys.executable, "-S", FAKE, "normal"))}
    )
    r.register_stdio(TENANT, "loc", "fake")
    return r


async def test_denied_mcp_call_never_spawns_a_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    spawned: list[Any] = []
    real = asyncio.create_subprocess_exec

    async def spy(*a: Any, **k: Any) -> Any:
        spawned.append(a)
        return await real(*a, **k)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    client = TenantMcpClient(registry(), TENANT)
    ex, _, _, _ = await make_executor(ScriptedGate(deny("no")))
    ex._backends = Backends(mcp=client)
    out = await ex.run(McpCall(name="echo", mcp_server="loc", args={"a": 1}), pid=PID)
    assert isinstance(out, Denied) and spawned == []


async def test_allowed_mcp_call_spawns_only_the_operator_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned: list[tuple[Any, ...]] = []
    real = asyncio.create_subprocess_exec

    async def spy(*a: Any, **k: Any) -> Any:
        spawned.append(a)
        return await real(*a, **k)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    client = TenantMcpClient(registry(), TENANT)
    ex, _, _, gate = await make_executor(ScriptedGate(allow()))
    ex._backends = Backends(mcp=client)
    try:
        out = await ex.run(McpCall(name="echo", mcp_server="loc", args={"a": 1}), pid=PID)
        assert isinstance(out, Completed)
        assert spawned == [(sys.executable, "-S", FAKE, "normal")]
        assert gate.requests[0].context["tool"]["name"] == "loc/echo"
    finally:
        await client.aclose()


async def test_unknown_server_in_manifest_is_a_failed_action_not_a_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from axis_runtime.executor import Failed

    monkeypatch.setattr(asyncio, "create_subprocess_exec", lambda *a, **k: pytest.fail("spawned"))
    client = TenantMcpClient(registry(), TENANT)
    ex, _, _, _ = await make_executor(ScriptedGate(allow()))
    ex._backends = Backends(mcp=client)
    out = await ex.run(McpCall(name="echo", mcp_server="/bin/sh -c id"), pid=PID)
    assert isinstance(out, Failed) and "McpServerNotAllowed" in out.error
