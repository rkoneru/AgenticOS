"""Dynamic bypass check (ADR-0009): interpreter audit events while gated scenarios run.

The static scan (``bypass_scan.py``) is an allowlist heuristic; this is its independent, behavioural
counterpart. A ``sys.addaudithook`` recorder (audit hooks can never be removed, so it is installed
ONCE and is inert unless ``recording()`` is active) captures network/process/native/file-write audit
events. Under a DENY (or approval-pending, or fail-closed outage) gate, and on the scripted/fake
transport allow path, the set of such events must be EMPTY. A non-vacuity test performs each
forbidden operation for real and proves the recorder sees it.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.gate import EvaluateRequest, GateDecision
from axis_runtime.run import run_agent
from conftest import ScriptedGate, allow, deny, make_deps, make_manifest
from helpers import PID, SAMPLES, make_executor
from test_run import deps_for, final, tool_turn

_ACTIVE = False  # module-level switch: the installed hook does nothing unless True
_EVENTS: list[tuple[str, str]] = []
_INSTALLED = False

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
_FORBIDDEN_EXACT = frozenset(
    {
        "socket.connect",
        "socket.bind",
        "socket.sendto",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "subprocess.Popen",
        "os.system",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "os.remove",
        "os.rename",
        "os.rmdir",
        "os.truncate",
        "os.mkdir",
        "os.chmod",
    }
)


def classify(event: str, args: tuple[Any, ...]) -> str | None:
    """Name of the forbidden category this audit event belongs to, else None."""
    if event in _FORBIDDEN_EXACT or event.startswith(("os.exec", "ctypes.", "shutil.")):
        return event
    if event == "open" and len(args) >= 3:
        mode, flags = args[1], args[2]
        if (isinstance(mode, str) and set(mode) & set("wax+")) or (
            isinstance(flags, int) and flags & _WRITE_FLAGS
        ):
            return "open-for-write"
    return None


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if not _ACTIVE:
        return
    kind = classify(event, args)
    if kind is not None:
        _EVENTS.append((kind, repr(args)[:120]))


def _install_once() -> None:
    global _INSTALLED
    if not _INSTALLED:
        sys.addaudithook(_hook)
        _INSTALLED = True


@contextmanager
def recording() -> Iterator[list[tuple[str, str]]]:
    global _ACTIVE
    _install_once()
    _EVENTS.clear()
    _ACTIVE = True
    try:
        yield _EVENTS
    finally:
        _ACTIVE = False


# ---- the recorder itself is sound ---------------------------------------------------------------------


def test_recorder_is_inert_outside_a_recording_window(tmp_path: Any) -> None:
    _install_once()
    _EVENTS.clear()
    (tmp_path / "f").write_text("x")  # an open-for-write while NOT recording
    assert _EVENTS == []


def test_recorder_sees_each_forbidden_operation_for_real(tmp_path: Any) -> None:
    """Non-vacuity: if these stop being recorded, the zero-events assertions below mean nothing."""
    with recording() as events:
        (tmp_path / "f").write_text("x")
        os.system("true")  # noqa: S605, S607
        subprocess.run(["true"], check=True)  # noqa: S607
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client = socket.socket()
        client.connect(server.getsockname())
        client.close()
        server.close()
        os.remove(tmp_path / "f")
        import ctypes

        ctypes.CDLL(None)
    kinds = {k for k, _ in events}
    assert {
        "open-for-write",
        "os.system",
        "subprocess.Popen",
        "socket.connect",
        "socket.bind",
        "os.remove",
    } <= kinds
    assert any(k.startswith("ctypes.") for k in kinds)


@pytest.mark.parametrize(
    ("event", "args", "expected"),
    [
        ("open", ("/x", "r", os.O_RDONLY), None),
        ("open", ("/x", "rb", 0), None),
        ("open", ("/x", "w", 0), "open-for-write"),
        ("open", ("/x", None, os.O_WRONLY), "open-for-write"),
        ("open", ("/x", "r", os.O_RDWR), "open-for-write"),
        ("open", ("/x", "a", 0), "open-for-write"),
        ("os.execve", (), "os.execve"),
        ("ctypes.dlopen", (), "ctypes.dlopen"),
        ("shutil.copyfile", (), "shutil.copyfile"),
        ("import", (), None),
    ],
)
def test_classifier(event: str, args: tuple[Any, ...], expected: str | None) -> None:
    assert classify(event, args) == expected


# ---- gated scenarios perform no forbidden operation ---------------------------------------------------


async def test_every_action_type_under_a_deny_gate_emits_no_forbidden_audit_events() -> None:
    with recording() as events:
        for make in SAMPLES.values():
            ex, _, effects, _ = await make_executor(ScriptedGate(deny("blocked by policy")))
            await ex.run(make(), pid=PID)
            assert effects.total() == 0
    assert events == []


async def test_approval_pending_emits_no_forbidden_audit_events() -> None:
    gate = ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="ap_1"))
    with recording() as events:
        for make in SAMPLES.values():
            ex, _, effects, _ = await make_executor(gate)
            await ex.run(make(), pid=PID)
            assert effects.total() == 0
    assert events == []


async def test_denied_agent_runs_emit_no_forbidden_audit_events() -> None:
    class Down:
        async def evaluate(self, r: EvaluateRequest) -> GateDecision:
            raise ConnectionError("down")

    def deny_tools(r: EvaluateRequest) -> GateDecision:
        return deny("tool blocked") if r.enforcement_point.value == "tool_call" else allow()

    with recording() as events:
        denied_model = deps_for(final(), gate=ScriptedGate(deny("egress blocked")))
        assert (await run_agent(make_manifest(), "secret", denied_model)).status == "policy_denied"
        assert denied_model.models._transport.calls == []  # type: ignore[attr-defined]  # noqa: SLF001
        outage = deps_for(final(), gate=Down())
        assert (await run_agent(make_manifest(), "x", outage)).status == "policy_denied"
        blocked_tool = deps_for(
            tool_turn(("lookup_claim", {"id": "x"})), final("sorry"), gate=ScriptedGate(deny_tools)
        )
        assert (await run_agent(make_manifest(), "x", blocked_tool)).output == "sorry"
    assert events == []


async def test_allowed_scripted_agent_run_touches_only_the_fake_transport() -> None:
    """Even with ALLOW, the scripted transport/tools mean no real socket, process or file write."""
    with recording() as events:
        deps = deps_for(tool_turn(("lookup_claim", {"id": "x"})), final("done"))
        result = await run_agent(make_manifest(), "x", deps)
        assert result.output == "done" and len(deps.models._transport.calls) == 2  # type: ignore[attr-defined]  # noqa: SLF001
        plain = make_deps(gate=ScriptedGate(allow()))
        assert (await run_agent(make_manifest(), "hi", plain)).output == "done"
    assert events == []
