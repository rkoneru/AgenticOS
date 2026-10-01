"""Bypass guard (Python half, ADR-0009): no action path may skip the Risk Kernel.

(a) Behavioural: for EVERY concrete Action type a DENY (or approval-pending) gate means zero side effects.
(b) Static (``bypass_scan.py``): an ALLOWLIST scan of ``src/axis_runtime``: only listed imports,
    no eval/dynamic-import/introspection/process/network/file-write constructs, and executor-only
    names referenced only from the files that own them. The scanner is itself proven against a probe
    corpus (every probe must be flagged) plus negative controls.
(c) Dynamic: ``test_audit_hook.py`` records interpreter audit events while gated scenarios run.

Static analysis cannot prove the absence of bypasses; see docs/spec/runtime.md for the limits.
"""

from __future__ import annotations

import ast
import gc
from pathlib import Path
from typing import Any

import axis_runtime
import bypass_scan as bs
import pytest
from axis_runtime import Decision, all_action_types
from axis_runtime.actions import Action
from axis_runtime.executor import Denied, PendingApproval
from axis_runtime.gate import GateDecision
from conftest import ScriptedGate, allow, deny
from helpers import PID, SAMPLES, make_executor

SRC = Path(axis_runtime.__file__).resolve().parent


def _modules() -> list[tuple[str, str]]:
    return bs.package_modules(SRC)


# ---- (b) static guard ------------------------------------------------------------------------------------


def test_no_module_violates_the_allowlist_scan() -> None:
    problems = [p for rel, src in _modules() for p in bs.scan_source(rel, src)]
    assert problems == []


def test_scanner_covers_the_whole_package() -> None:
    rels = {rel for rel, _ in _modules()}
    assert {
        "executor.py",
        "run.py",
        "models/gateway.py",
        "models/endpoints.py",
        "models/adapters/bedrock.py",
        "tools.py",
        "temporal.py",
    } <= rels
    assert len(rels) > 25


def test_allowlists_have_no_stale_entries() -> None:
    """Every grant must still be needed: a removed use must also remove its allowlist entry."""
    mods = dict(_modules())
    raw = {
        rel: bs.raw_findings(rel, src) for rel, src in mods.items() if not rel.startswith("_gen/")
    }
    for rel, grants in bs.IO_IMPORTS.items():
        assert rel in mods
        imported = {m for m, _ in bs.imported_modules(ast.parse(mods[rel]))}
        for module, reason in grants.items():
            assert reason
            assert any(m == module or m.startswith(module + ".") for m in imported), (
                f"{rel} no longer imports {module}"
            )
    for rule, files in bs.EXEMPTIONS.items():
        for rel, reason in files.items():
            assert reason and any(f.rule == rule for f in raw[rel]), f"{rel} no longer needs {rule}"
    for name, files in bs.RESTRICTED_NAMES.items():
        for rel, reason in files.items():
            assert reason and any(f.rule == f"restricted:{name}" for f in raw[rel]), (
                f"{rel} no longer needs {name}"
            )
    for rel, reason in bs.GATEWAY_CONSTRUCTION_FILES.items():
        assert reason and any(f.rule == "gateway-construction" for f in raw[rel])


def test_safe_imports_are_all_used_and_commented() -> None:
    used = {
        m
        for rel, src in _modules()
        if not rel.startswith("_gen/")
        for m, _ in bs.imported_modules(ast.parse(src))
    }
    unused = {m for m in bs.SAFE_IMPORTS if m not in used}
    assert unused == set(), f"stale SAFE_IMPORTS entries: {sorted(unused)}"
    source = Path(bs.__file__).read_text()
    block = source[source.index("SAFE_IMPORTS: frozenset") : source.index("SAFE_PREFIXES")]
    for module in bs.SAFE_IMPORTS:  # one comment per entry
        line = next(ln for ln in block.splitlines() if f'"{module}"' in ln)
        assert "#" in line, f"SAFE_IMPORTS entry {module} has no justification comment"


# Every probe the independent reviewer used (plus the original corpus): each MUST be flagged.
PROBES: list[tuple[str, str]] = [
    # --- imports of IO-capable / unknown modules (allowlist: anything not listed is a violation)
    ("import httpx", "import:httpx"),
    ("import subprocess", "import:subprocess"),
    ("from subprocess import run", "import:subprocess"),
    ("import socket", "import:socket"),
    ("import requests", "import:requests"),
    ("import urllib.request", "import:urllib.request"),
    ("from urllib import request", "import:urllib.request"),
    ("from urllib.request import urlopen", "import:urllib.request"),
    ("import urllib\nurllib.request.urlopen('http://x')", "import:urllib"),
    ("import aiohttp.client", "import:aiohttp.client"),
    ("from http import client", "import:http.client"),
    ("import grpc", "import:grpc"),
    ("import ctypes", "import:ctypes"),
    ("import multiprocessing", "import:multiprocessing"),
    ("import pty", "import:pty"),
    ("import smtplib", "import:smtplib"),
    ("import ftplib", "import:ftplib"),
    ("import websockets", "import:websockets"),
    ("import ssl", "import:ssl"),
    ("import boto3", "import:boto3"),
    ("import openai", "import:openai"),
    ("import anthropic", "import:anthropic"),
    ("import psycopg", "import:psycopg"),
    ("import sqlite3", "import:sqlite3"),
    ("import pickle", "import:pickle"),
    ("import marshal", "import:marshal"),
    ("import shutil", "import:shutil"),
    ("import tempfile", "import:tempfile"),
    ("import sys\nsys.modules['x']", "import:sys"),
    ("import importlib", "import:importlib"),
    ("from importlib import import_module", "import:importlib"),
    ("import os", "import:os"),
    ("import os as o\no.system('id')", "import:os"),
    ("from os import system", "import:os"),
    ("import pathlib", "import:pathlib"),
    ("import builtins", "import:builtins"),
    ("import gc", "import:gc"),
    ("import types", "import:types"),
    ("import threading", "import:threading"),
    ("import asyncio.subprocess", "import:asyncio.subprocess"),
    ("import logging.handlers", "import:logging.handlers"),
    ("from logging import handlers", "import:logging.handlers"),
    ("from json import *", "import:json.*"),
    # --- dynamic execution / import / reflection
    ("eval('1+1')", "dynamic-exec"),
    ("exec('x=1')", "dynamic-exec"),
    ("compile('x', 'f', 'exec')", "dynamic-exec"),
    ("f = eval\nf('1')", "dynamic-exec"),
    ("__import__('subprocess')", "dynamic-exec"),
    ("__import__(name)", "dynamic-exec"),
    ("import importlib\nimportlib.import_module('socket')", "introspection"),
    ("import importlib\nimportlib.import_module(name)", "banned-qualified"),
    ("m.import_module(name)", "introspection"),
    ("getattr(a, 'per' + 'form')", "dynamic-attr"),
    ("getattr(a, name)", "dynamic-attr"),
    ("setattr(a, name, 1)", "dynamic-attr"),
    ("delattr(a, name)", "dynamic-attr"),
    ("getattr(a)", "dynamic-attr"),
    ("getattr(a, 'perform')", "restricted:perform"),
    ("vars(A)['perform']", "dynamic-exec"),
    ("A.__dict__['perform']", "introspection"),
    ("globals()['x']", "dynamic-exec"),
    ("locals()", "dynamic-exec"),
    ("f.__globals__", "introspection"),
    ("fn.__code__", "introspection"),
    ("object.__subclasses__()", "introspection"),
    ("frame.f_back.f_globals", "introspection"),
    ("x.__getattribute__('perform')", "introspection"),
    ("import sys\nsys.modules", "banned-qualified"),
    ("from sys import modules", "banned-qualified"),
    # --- process
    ("import os\nos.system('id')", "banned-qualified"),
    ("import os\nos.popen('id')", "process"),
    ("import os\nos.execv('/bin/sh', [])", "process"),
    ("import os\nos.execvp('sh', [])", "process"),
    ("import os\nos.spawnl(0, 'x')", "process"),
    ("import os\nos.fork()", "process"),
    ("import os\nos.posix_spawn('x', [], {})", "process"),
    ("import os\nos.kill(1, 9)", "banned-qualified"),
    ("import asyncio\nasyncio.create_subprocess_exec('ls')", "process"),
    ("import asyncio\nasyncio.create_subprocess_shell('ls')", "process"),
    ("import asyncio\nloop.subprocess_exec(f, 'ls')", "process"),
    # --- network
    ("import asyncio\nasyncio.open_connection('h', 1)", "net"),
    ("import asyncio\nasyncio.start_server(cb, 'h', 1)", "net"),
    ("import asyncio\nloop.create_connection(f, 'h', 1)", "net"),
    ("import asyncio\nloop.sock_connect(s, a)", "net"),
    ("import asyncio\nloop.getaddrinfo('h', 1)", "dns"),
    ("from socket import gethostbyname\ngethostbyname('h')", "dns"),
    ("urlopen(u)", "net"),
    # --- file writes / removals
    ("open('x', 'w')", "file-write"),
    ("open('x', mode='a')", "file-write"),
    ("open('x', 'rb+')", "file-write"),
    ("open('x', 'x')", "file-write"),
    ("open('x', m)", "file-write"),
    ("open('x', mode=m)", "file-write"),
    ("open('x', opener=o)", "file-write"),
    ("from pathlib import Path\nPath('x').write_text('y')", "file-write"),
    ("from pathlib import Path\nPath('x').write_bytes(b'y')", "file-write"),
    ("from pathlib import Path\nPath('x').touch()", "file-write"),
    ("from pathlib import Path\nPath('x').open('w')", "file-write"),
    ("from pathlib import Path\nPath('x').open(mode='a')", "file-write"),
    ("from pathlib import Path\nPath('x').open('r+')", "file-write"),
    ("from pathlib import Path\nPath('x').open(m)", "file-write"),
    ("from pathlib import Path\nPath('x').unlink()", "file-write"),
    ("from pathlib import Path\nPath('x').mkdir()", "file-write"),
    ("from pathlib import Path\nPath('x').rename('y')", "file-write"),
    ("from pathlib import Path\nPath('x').replace('y')", "file-write"),
    ("import os\nos.open('x', 1)", "file-write"),
    ("import os\nos.remove('x')", "file-write"),
    ("import os\nos.unlink('x')", "file-write"),
    ("import os\nos.rmdir('x')", "file-write"),
    ("import os\nos.rename('a', 'b')", "file-write"),
    ("import os\nos.replace('a', 'b')", "file-write"),
    ("import os\nos.makedirs('a')", "file-write"),
    ("import os as o\no.remove('x')", "file-write"),
    ("from os import remove", "file-write"),
    ("import shutil\nshutil.copy('a', 'b')", "banned-qualified"),
    ("import shutil\nshutil.rmtree('a')", "banned-qualified"),
    ("import logging\nlogging.FileHandler('f')", "logging-sink"),
    ("import logging\nlogging.SocketHandler('h', 1)", "logging-sink"),
    # --- native / serialisation escape hatches
    ("import ctypes\nctypes.CDLL(None)", "banned-qualified"),
    ("import pickle\npickle.loads(b)", "banned-qualified"),
    # --- executor-only names (RESTRICTED_NAMES)
    ("action.perform(token, backends)", "restricted:perform"),
    ("class Sneaky:\n    async def perform(self): ...", "restricted:perform"),
    ("action._execute(b)", "restricted:_execute"),
    ("backends.need('tools')", "restricted:need"),
    ("gw._complete(r)", "restricted:_complete"),
    ("gw._stream(r)", "restricted:_stream"),
    ("gw.unguarded_for_tests()", "restricted:unguarded_for_tests"),
    ("from axis_runtime.guard import ExecutionToken", "restricted:ExecutionToken"),
    (
        "from axis_runtime.guard import bind_executor_token as b",
        "restricted:bind_executor_token",
    ),
    ("from axis_runtime.executor import _TOKEN", "restricted:_TOKEN"),
    ("import axis_runtime.executor as e\ne._TOKEN", "restricted:_TOKEN"),
    ("getattr(e, '_TOKEN')", "restricted:_TOKEN"),
    ("from axis_runtime.guard import executing", "restricted:executing"),
    ("from axis_runtime.guard import in_executor", "restricted:in_executor"),
    ("guard._executing.set(True)", "restricted:_executing"),
    ("guard._bound_token", "restricted:_bound_token"),
    ("guard.token_is_valid(t)", "restricted:token_is_valid"),
    ("registry.call('t', {})", "restricted:call"),
    ("await ToolRegistry().call('t', {})", "restricted:call"),
    ("await mcp.call_tool('s', 'n', {})", "restricted:call_tool"),
    ("await backends.mcp.call_tool('s', 'n', {})", "restricted:call_tool"),
    ("await gateway.complete(request)", "restricted:complete"),
    ("async for e in gateway.stream(request): ...", "restricted:stream"),
    ("ModelGateway(secrets)", "gateway-construction"),
    ("models.ModelGateway(secrets)", "gateway-construction"),
    (
        # the reviewer's worst case: forging the executing marker to defeat the ModelGateway tripwire
        "from axis_runtime import guard\n"
        "async def go(gateway, request):\n"
        "    with guard.executing():\n"
        "        return await gateway.complete(request)",
        "restricted:executing",
    ),
    (
        "from axis_runtime import guard\n"
        "async def go(gateway, request):\n"
        "    with guard.executing():\n"
        "        return await gateway.complete(request)",
        "restricted:complete",
    ),
    # --- transitive reach through allowlisted "safe" modules (second review)
    ("import logging\nlogging.os.system('true')", "transitive-module"),
    ("import logging\nlogging.os.remove('x')", "transitive-module"),
    ("import logging\nlogging.os.open('x', 1)", "transitive-module"),
    ("import contextlib\ncontextlib.os.system('true')", "transitive-module"),
    ("import random\nrandom._os.system('true')", "transitive-module"),
    ("import typing\ntyping.sys.modules['os']", "transitive-module"),
    ("import typing\ntyping.sys.settrace(f)", "transitive-module"),
    ("import typing\ntyping.sys.addaudithook(f)", "transitive-module"),
    ("import asyncio\nasyncio.subprocess.subprocess.Popen(['ls'])", "transitive-module"),
    ("import asyncio\nasyncio.unix_events.subprocess.run(['ls'])", "transitive-module"),
    ("import asyncio\nasyncio.tasks.os.system('true')", "transitive-module"),
    ("import asyncio\nasyncio.streams.socket.socket().connect(a)", "transitive-module"),
    ("import inspect, logging\ninspect.getmodule(logging).os.system('true')", "transitive-module"),
    ("import logging\nlogging.io.FileIO(p, 'w')", "transitive-module"),
    ("import logging\nlogging.threading.Thread(target=f)", "transitive-module"),
    ("import asyncio\nasyncio.events.signal.raise_signal(1)", "transitive-module"),
    ("from typing import sys", "transitive-module"),
    ("from logging import os", "transitive-module"),
    ("from asyncio import subprocess", "import:asyncio.subprocess"),
    ("import inspect\ninspect.getmodule(x)", "unlisted-member"),
    ("import inspect\ninspect.stack()", "unlisted-member"),
    ("import asyncio\nasyncio.get_event_loop_policy()", "unlisted-member"),
    ("from asyncio import get_event_loop_policy", "unlisted-member"),
    ("import logging\nlogging.config.fileConfig('x')", "unlisted-member"),
    ("import typing\ntyping.functools.partial(f)", "unlisted-member"),
    ("import random\nrandom._inst", "unlisted-member"),
    ("import logging\nlogging.basicConfig(filename='x')", "logging-sink"),
    ("import logging\nlogging.FileIO('x', 'w')", "logging-sink"),
    ("from logging import basicConfig", "logging-sink"),
    ("import logging\nlogging.handlers.RotatingFileHandler('x')", "logging-sink"),
    ("import logging\nlogging.WatchedFileHandler('x')", "logging-sink"),
    ("getattr(f, '__globals__')", "introspection"),
    ("getattr(object, '__subclasses__')()", "introspection"),
    ("hasattr(x, '__code__')", "introspection"),
    ("setattr(x, '__closure__', 1)", "introspection"),
    ("getattr(logging, 'os')", "introspection"),
    ("getattr(b, 'exec')", "dynamic-exec"),
    ("import operator\noperator.attrgetter('__globals__')(f)", "introspection"),
    ("import operator\noperator.attrgetter('a.__class__.__mro__')(f)", "introspection"),
    ("import operator\noperator.methodcaller('__subclasses__')(object)", "introspection"),
    ("x['__globals__']", "introspection"),
    ("x['__builtins__']", "dynamic-exec"),
    ("x.__class__.__dict__['y']", "introspection"),
    ("b.exec('x=1')", "dynamic-exec"),
    ("b.eval('1')", "dynamic-exec"),
    ("import builtins\nbuiltins.eval('1')", "dynamic-exec"),
    ("b.compile('x', 'f', 'exec')", "dynamic-exec"),
    ("b.__import__('os')", "dynamic-exec"),
    ("x.globals()", "dynamic-exec"),
    ("type(x).__mro__", "introspection"),
    ("x.__bases__", "introspection"),
    ("x.__base__.__subclasses__()", "introspection"),
    ("loop.sock_sendall(s, b'x')", "net"),
    ("loop.sock_recv(s, 1)", "net"),
    ("loop.sock_accept(s)", "net"),
    ("loop.sendfile(t, f)", "net"),
    ("import os\nloop.run_in_executor(None, os.system, 'true')", "banned-qualified"),
    ("loop.run_in_executor(None, f)", "thread-escape"),
    ("import asyncio\nasyncio.to_thread(f)", "thread-escape"),
    ("import functools, os\nfunctools.partial(os.system, 'true')", "banned-qualified"),
]


@pytest.mark.parametrize(("source", "needle"), PROBES, ids=[f"{i}" for i in range(len(PROBES))])
def test_scanner_flags_every_probe(source: str, needle: str) -> None:
    problems = bs.scan_source("rogue.py", source)
    assert any(needle in p for p in problems), (source, problems)


BENIGN = [
    "import json\nopen('x')",
    "open('x', 'r')",
    "open('x', 'rb')",
    "open('x', mode='rt')",
    "import asyncio\nasyncio.sleep(1)",
    "import asyncio\nasyncio.get_running_loop()",
    "x = 'replace'.replace('a', 'b')",
    "import dataclasses\ndataclasses.replace(x)",
    "import dataclasses\ndataclasses.replace(x, a=1)",
    "import urllib.parse\nurllib.parse.quote('a')",
    "from urllib.parse import urlsplit",
    "import re\nre.compile('x')",
    "getattr(obj, 'literal')",
    "import logging\nlogging.getLogger('x').info('m')",
    "from axis_runtime.models import ModelError",
    "from collections.abc import Mapping",
    "import hashlib, hmac, json, time, secrets, random, struct, zlib",
    "from cryptography.fernet import Fernet",
    "from google.protobuf import json_format",
    "call = 1\nstream = 2\ncomplete = 3\nuse(call, stream, complete)",
    "def f(call, stream):\n    return call.method, stream",
    "class ModelGatewayError(Exception): ...",
    "dt.replace(tzinfo=None)",
    "from __future__ import annotations",
    "import logging\nlogging.getLogger(__name__).info('m %s', x)",
    "import asyncio\nawait asyncio.sleep(1)",
    "import asyncio\nawait asyncio.gather(a, b)",
    "import asyncio\nlock = asyncio.Lock()",
    "import asyncio\nasyncio.create_task(f())",
    "import asyncio\nasyncio.get_running_loop().time()",
    "from typing import cast, Any, TYPE_CHECKING\nx = cast(int, y)",
    "import typing\nx = typing.cast(int, y)",
    "import contextlib\n@contextlib.asynccontextmanager\nasync def f(): yield",
    "from contextlib import suppress, asynccontextmanager",
    "import random\nr = random.Random(x).uniform(0, 1)",
    "import inspect\ninspect.isabstract(c)",
    "import re\nre.compile('x')",
    "self._handle.signal(1)",
    "getattr(obj, 'name')",
    "x['key']",
    "d = {'exec': 1}\nd['other']",
    "operator_value = attrgetter('name')(obj)",
]


@pytest.mark.parametrize("source", BENIGN, ids=[f"{i}" for i in range(len(BENIGN))])
def test_scanner_accepts_benign_code(source: str) -> None:
    assert bs.scan_source("fine.py", source) == []


def test_path_open_reads_are_accepted_but_modes_are_checked_in_both_positions() -> None:
    src = "from pathlib import Path"
    assert not any("file-write" in p for p in bs.scan_source("x.py", f"{src}\nPath('x').open()"))
    assert not any(
        "file-write" in p for p in bs.scan_source("x.py", f"{src}\nPath('x').open('rb')")
    )
    assert any("file-write" in p for p in bs.scan_source("x.py", f"{src}\nPath('x').open('wb')"))


def test_allowlist_is_scoped_to_exact_files() -> None:
    assert bs.scan_source("tools.py", "import httpx") == []
    assert bs.scan_source("models/adapters/openai.py", "import httpx") != []  # siblings: no
    assert bs.scan_source("models/secrets.py", "import os\nos.replace('a', 'b')") == []
    assert bs.scan_source("tools.py", "import os\nos.replace('a', 'b')") != []
    assert bs.scan_source("gate.py", "import grpc\nimport grpc.aio") == []
    assert bs.scan_source("temporal.py", "from temporalio import workflow") == []
    assert bs.scan_source("run.py", "from temporalio import workflow") != []
    assert bs.scan_source("_gen/axis/runtime/v1/gate_pb2_grpc.py", "import grpc") == []
    assert bs.scan_source("run.py", "import subprocess") != []
    # an IO import grant is per module: base.py may import socket but not subprocess
    assert bs.scan_source("models/adapters/base.py", "import socket") == []
    assert bs.scan_source("models/adapters/base.py", "import subprocess") != []
    # an allowlisted file is still subject to every other rule
    assert bs.scan_source("tools.py", "import httpx\neval('1')") != []
    assert bs.scan_source("models/adapters/base.py", "loop.getaddrinfo('h', 1)") == []
    assert bs.scan_source("models/adapters/base.py", "loop.create_connection(f, 'h', 1)") != []
    # restricted names are per file
    assert bs.scan_source("executor.py", "x = _TOKEN") == []
    assert bs.scan_source("actions.py", "x = _TOKEN") != []
    assert bs.scan_source("actions.py", "await models.complete(r)") == []
    assert bs.scan_source("run.py", "await models.complete(r)") != []


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


class _Approvals:
    def __init__(self, record: dict[str, Any] | Exception) -> None:
        self.record = record

    async def resolve(self, tenant_id: str, approval_id: str) -> dict[str, Any]:
        if isinstance(self.record, Exception):
            raise self.record
        return self.record


def _gate_after_approval(second: GateDecision) -> ScriptedGate:
    return ScriptedGate(
        lambda r: (
            second
            if "approval" in r.context
            else GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="ap_1")
        )
    )


def _rec(outcome: str = "APPROVED", **over: Any) -> dict[str, Any]:
    from conftest import TENANT

    base = {"request_id": "ap_1", "tenant_id": TENANT, "run_id": "run_1", "outcome": outcome}
    return {**base, **over}


@pytest.mark.parametrize("cls", list(all_action_types()), ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "resolution",
    [
        _rec("DENIED"),
        _rec("EXPIRED"),
        _rec("APPROVED", request_id="someone-elses"),
        RuntimeError("approvals down"),
    ],
    ids=["denied", "expired", "mismatch", "unavailable"],
)
async def test_unapproved_resolution_yields_zero_side_effects_for_every_action_type(
    cls: type[Action], resolution: dict[str, Any] | Exception
) -> None:
    ex, _, effects, gate = await make_executor(
        _gate_after_approval(allow()), approvals=_Approvals(resolution)
    )
    assert isinstance(await ex.run(SAMPLES[cls](), pid=PID), Denied)
    assert effects.total() == 0
    assert len(gate.requests) == 1  # nothing was re-submitted without an APPROVED record


@pytest.mark.parametrize("cls", list(all_action_types()), ids=lambda c: c.__name__)
async def test_an_approval_never_bypasses_the_gate_for_every_action_type(
    cls: type[Action],
) -> None:
    for second in (deny("cap exceeded"), GateDecision(Decision.REQUIRE_APPROVAL, "again", "", "v")):
        ex, _, effects, gate = await make_executor(
            _gate_after_approval(second), approvals=_Approvals(_rec())
        )
        gate_decision = second.decision
        assert isinstance(await ex.run(SAMPLES[cls](), pid=PID), Denied), gate_decision
        assert effects.total() == 0 and len(gate.requests) == 2


@pytest.mark.parametrize("cls", list(all_action_types()), ids=lambda c: c.__name__)
async def test_approved_and_regated_does_perform_so_the_guard_above_is_not_vacuous(
    cls: type[Action],
) -> None:
    ex, _, effects, _ = await make_executor(
        _gate_after_approval(allow()), approvals=_Approvals(_rec())
    )
    await ex.run(SAMPLES[cls](), pid=PID)
    assert effects.total() >= 1


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
