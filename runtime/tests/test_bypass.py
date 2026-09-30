"""Bypass guard (Python half, ADR-0009): no action path may skip the Risk Kernel.

(a) Behavioural: for EVERY concrete Action type a DENY (or approval-pending) gate means zero side effects.
(b) Static: an AST scan fails if any module outside an explicit allowlist imports a network / process /
    file-write primitive, or reaches into the executor-only entry points.  The scanner is itself tested so
    that it demonstrably fails on violations.
"""

from __future__ import annotations

import ast
import gc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import axis_runtime
import pytest
from axis_runtime import Decision, all_action_types
from axis_runtime.actions import Action
from axis_runtime.executor import Denied, PendingApproval
from axis_runtime.gate import GateDecision
from conftest import ScriptedGate, deny
from helpers import PID, SAMPLES, make_executor

SRC = Path(axis_runtime.__file__).resolve().parent

# ---------------------------------------------------------------------------------------------------
# Allowlists. One constant, one reason per entry. Adding an entry is a security review decision.
# Paths are relative to src/axis_runtime. Every entry is verified to be still needed (no stale grants).
# ---------------------------------------------------------------------------------------------------
NETWORK_IMPORT_ALLOWLIST: dict[str, tuple[frozenset[str], str]] = {
    "models/adapters/base.py": (
        frozenset({"httpx"}),
        "HttpxTransport: the single place the ModelGateway touches the network; only reachable via ModelGateway, "
        "which only runs inside ActionExecutor (ModelCall).",
    ),
    "tools.py": (
        frozenset({"httpx"}),
        "HttpMcpClient: MCP-over-HTTP backend; only reachable through McpCall performed by ActionExecutor.",
    ),
    "gate.py": (
        frozenset({"grpc", "grpc.aio"}),
        "GrpcGateClient: the gate's own transport to the Risk Kernel (not an action).",
    ),
}
# Generated gRPC stubs import grpc; they are data, not call paths.
GENERATED_PREFIX = "_gen/"

FILE_WRITE_ALLOWLIST: dict[str, str] = {
    "models/secrets.py": "FileSecretStore (dev-only encrypted secret file); not reachable from any Action.",
}

BANNED_IMPORTS = frozenset(
    {
        "httpx",
        "subprocess",
        "socket",
        "requests",
        "urllib.request",
        "urllib3",
        "aiohttp",
        "http.client",
        "grpc",
    }
)

# Attribute/name references that only specific modules may make (the executor-only entry points).
RESTRICTED_NAMES: dict[str, dict[str, str]] = {
    "perform": {"executor.py": "the only caller of Action.perform", "actions.py": "defines it"},
    "_execute": {"actions.py": "defines and dispatches the guarded hook"},
    "bind_executor_token": {
        "executor.py": "binds the single token",
        "actions.py": "re-export",
        "guard.py": "defines it",
    },
    "ExecutionToken": {
        "executor.py": "issues the token",
        "actions.py": "re-export",
        "guard.py": "defines it",
    },
    "unguarded_for_tests": {"models/gateway.py": "defines the test-only seam"},
    "UnguardedModelGateway": {
        "models/gateway.py": "defines the test-only seam",
        "models/__init__.py": "re-export",
    },
    "_complete": {"models/gateway.py": "implementation behind the guard"},
    "_stream": {"models/gateway.py": "implementation behind the guard"},
}


def _imports(tree: ast.AST) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module
            for alias in node.names:
                yield f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Call):
            fn = node.func
            name = (
                fn.id
                if isinstance(fn, ast.Name)
                else fn.attr
                if isinstance(fn, ast.Attribute)
                else ""
            )
            if (
                name in {"__import__", "import_module"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                yield str(node.args[0].value)


def _banned_in(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for mod in _imports(tree):
        for banned in BANNED_IMPORTS:
            if mod == banned or mod.startswith(banned + "."):
                found.add(banned)
    return found


def _opens_for_write(tree: ast.AST) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        attr = fn.attr if isinstance(fn, ast.Attribute) else ""
        name = fn.id if isinstance(fn, ast.Name) else ""
        if attr in {
            "write_text",
            "write_bytes",
            "replace",
            "rename",
            "unlink",
            "rmtree",
            "fdopen",
        } and not (
            attr == "replace" and len(node.args) != 1 and not isinstance(fn.value, ast.Name)  # type: ignore[union-attr]
        ):
            if attr != "replace" or (isinstance(fn.value, ast.Name) and fn.value.id == "os"):  # type: ignore[union-attr]
                lines.append(node.lineno)
        if name == "open" or attr == "open":
            mode: Any = node.args[1] if len(node.args) > 1 else None
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode = kw.value
            if attr == "open" and isinstance(fn.value, ast.Name) and fn.value.id == "os":  # type: ignore[union-attr]
                lines.append(
                    node.lineno
                )  # os.open: flags, always treated as a write-capable primitive
            elif (
                isinstance(mode, ast.Constant)
                and isinstance(mode.value, str)
                and set(mode.value) & set("wax+")
            ):
                lines.append(node.lineno)
            elif mode is not None and not isinstance(mode, ast.Constant):
                lines.append(node.lineno)  # dynamic mode: cannot prove read-only
    return lines


def _restricted_uses(tree: ast.AST) -> dict[str, list[int]]:
    uses: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.alias):
            names.append(node.name.split(".")[-1])
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.append(node.name)
        for n in names:
            if n in RESTRICTED_NAMES:
                uses.setdefault(n, []).append(getattr(node, "lineno", 0))
    return uses


def scan_source(rel: str, source: str) -> list[str]:
    """Return human-readable violations for one module."""
    tree = ast.parse(source)
    problems: list[str] = []
    if not rel.startswith(GENERATED_PREFIX):
        allowed = NETWORK_IMPORT_ALLOWLIST.get(rel, (frozenset(), ""))[0]
        for banned in sorted(_banned_in(tree)):
            if banned not in allowed and not any(banned.startswith(a + ".") for a in allowed):
                problems.append(f"{rel}: imports {banned}")
    if rel not in FILE_WRITE_ALLOWLIST and not rel.startswith(GENERATED_PREFIX):
        problems += [f"{rel}:{ln}: file write/remove primitive" for ln in _opens_for_write(tree)]
    for name, lines in _restricted_uses(tree).items():
        if rel not in RESTRICTED_NAMES[name]:
            problems.append(f"{rel}:{lines[0]}: uses executor-only name {name!r}")
    return problems


def _modules() -> list[tuple[str, str]]:
    return [(str(p.relative_to(SRC)), p.read_text()) for p in sorted(SRC.rglob("*.py"))]


# ---- (b) static guard ------------------------------------------------------------------------------------


def test_no_module_outside_the_allowlist_touches_network_process_or_file_writes() -> None:
    problems = [p for rel, src in _modules() for p in scan_source(rel, src)]
    assert problems == []


def test_scanner_covers_the_whole_package() -> None:
    rels = {rel for rel, _ in _modules()}
    assert {
        "executor.py",
        "run.py",
        "models/gateway.py",
        "models/adapters/bedrock.py",
        "tools.py",
    } <= rels
    assert len(rels) > 25


def test_allowlist_has_no_stale_entries() -> None:
    mods = dict(_modules())
    for rel, (allowed, reason) in NETWORK_IMPORT_ALLOWLIST.items():
        assert reason and rel in mods
        assert allowed <= {m for m in _imports(ast.parse(mods[rel]))}, (
            f"{rel} no longer imports {allowed}"
        )
    for rel, reason in FILE_WRITE_ALLOWLIST.items():
        assert reason and _opens_for_write(ast.parse(mods[rel])), f"{rel} no longer writes files"
    for name, where in RESTRICTED_NAMES.items():
        for rel in where:
            assert name in _restricted_uses(ast.parse(mods[rel])), f"{rel} no longer needs {name}"


@pytest.mark.parametrize(
    ("source", "needle"),
    [
        ("import httpx", "imports httpx"),
        ("import subprocess", "imports subprocess"),
        ("from subprocess import run", "imports subprocess"),
        ("import socket", "imports socket"),
        ("import requests", "imports requests"),
        ("import urllib.request", "imports urllib.request"),
        ("from urllib import request", "imports urllib.request"),
        ("from urllib.request import urlopen", "imports urllib.request"),
        ("import aiohttp.client", "imports aiohttp"),
        ("from http import client", "imports http.client"),
        ("import grpc", "imports grpc"),
        ("__import__('subprocess')", "imports subprocess"),
        ("import importlib\nimportlib.import_module('socket')", "imports socket"),
        ("open('x', 'w')", "file write"),
        ("open('x', mode='a')", "file write"),
        ("open('x', 'rb+')", "file write"),
        ("open('x', m)", "file write"),
        ("from pathlib import Path\nPath('x').write_text('y')", "file write"),
        ("from pathlib import Path\nPath('x').write_bytes(b'y')", "file write"),
        ("import os\nos.open('x', 1)", "file write"),
        ("import os\nos.replace('a', 'b')", "file write"),
        ("action.perform(token, backends)", "executor-only name 'perform'"),
        ("action._execute(b)", "executor-only name '_execute'"),
        ("gw._complete(r)", "executor-only name '_complete'"),
        ("gw.unguarded_for_tests()", "executor-only name 'unguarded_for_tests'"),
        ("from axis_runtime.guard import ExecutionToken", "executor-only name 'ExecutionToken'"),
        (
            "from axis_runtime.guard import bind_executor_token as b",
            "executor-only name 'bind_executor_token'",
        ),
        ("class Sneaky:\n    async def perform(self): ...", "executor-only name 'perform'"),
    ],
)
def test_scanner_flags_violations(source: str, needle: str) -> None:
    problems = scan_source("rogue.py", source)
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize(
    "source",
    [
        "import json\nopen('x')",
        "open('x', 'r')",
        "open('x', 'rb')",
        "import asyncio",
        "from pathlib import Path\nPath('x').read_text()",
        "x = 'replace'.replace('a', 'b')",
        "import urllib.parse",
    ],
)
def test_scanner_accepts_benign_code(source: str) -> None:
    assert scan_source("fine.py", source) == []


def test_allowlist_is_scoped_to_exact_files() -> None:
    assert scan_source("tools.py", "import httpx") == []
    assert (
        scan_source("models/adapters/openai.py", "import httpx") != []
    )  # siblings are NOT allowlisted
    assert scan_source("models/secrets.py", "open('x', 'w')") == []
    assert scan_source("tools.py", "open('x', 'w')") != []
    assert scan_source("gate.py", "import grpc\nimport grpc.aio") == []
    assert scan_source("_gen/axis/runtime/v1/gate_pb2_grpc.py", "import grpc") == []
    assert scan_source("run.py", "import subprocess") != []


# ---- (a) behavioural guard -------------------------------------------------------------------------------


def test_every_action_type_has_a_bypass_sample() -> None:
    """Adding a new Action subclass without a sample makes this fail: it cannot dodge (a)."""
    assert set(all_action_types()) == set(SAMPLES)
    assert len(all_action_types()) >= 7


@pytest.mark.parametrize("cls", list(all_action_types()), ids=lambda c: c.__name__)
async def test_deny_yields_zero_side_effects_for_every_action_type(cls: type[Action]) -> None:
    ex, rec, effects, gate = await make_executor(ScriptedGate(deny("blocked by policy")))
    outcome = await ex.run(SAMPLES[cls](), pid=PID)
    assert isinstance(outcome, Denied)
    assert effects.total() == 0, effects.calls
    assert len(gate.requests) == 1 and gate.requests[0].enforcement_point == cls.enforcement_point
    assert rec.state.tool_calls == () and rec.state.model_calls == ()


@pytest.mark.parametrize("cls", list(all_action_types()), ids=lambda c: c.__name__)
async def test_approval_pending_yields_zero_side_effects_for_every_action_type(
    cls: type[Action],
) -> None:
    gate = ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="ap_1"))
    ex, rec, effects, _ = await make_executor(gate)
    assert isinstance(await ex.run(SAMPLES[cls](), pid=PID), PendingApproval)
    assert effects.total() == 0


@pytest.mark.parametrize("cls", list(all_action_types()), ids=lambda c: c.__name__)
async def test_allow_does_perform_so_the_guard_above_is_not_vacuous(cls: type[Action]) -> None:
    ex, _, effects, _ = await make_executor(ScriptedGate())
    await ex.run(SAMPLES[cls](), pid=PID)
    assert effects.total() >= 1


async def test_a_new_unregistered_action_subclass_is_picked_up_by_the_registry() -> None:
    class Rogue(Action):  # defined only for this test; concrete, so the registry must list it
        enforcement_point = axis_runtime.all_action_types()[0].enforcement_point
        name = "rogue"

        def tool_descriptor(self) -> dict[str, str]:
            return {}

        def gate_args(self) -> dict[str, Any]:
            return {}

        def with_args(self, doc: Any) -> Action:
            return self

        async def _execute(self, backends: Any) -> Any:
            return None

    try:
        assert Rogue in all_action_types()
        assert set(all_action_types()) != set(
            SAMPLES
        )  # ...and the sample-coverage test above would now fail
    finally:
        del Rogue
        gc.collect()  # subclasses are weakly referenced: make sure the test class does not leak
    assert set(all_action_types()) == set(SAMPLES)
