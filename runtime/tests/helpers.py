"""Test helpers: recording side-effect backends and one sample Action per concrete type."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from axis_runtime.actions import (
    Action,
    Backends,
    BrowserExec,
    CodeExec,
    McpCall,
    MemoryWrite,
    MessageSend,
    ModelCall,
    ToolCall,
)
from axis_runtime.events import EventType, RunRecorder
from axis_runtime.executor import ActionExecutor, RunIdentity
from axis_runtime.models import Message, ModelRequest, ModelTarget
from axis_runtime.tools import ToolRegistry
from conftest import (
    TENANT,
    FakeClock,
    ScriptedGate,
    ScriptedTransport,
    make_gateway,
    openai_body,
)

PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"


@dataclass
class Effects:
    """Every real side effect lands here; a denied action must leave it empty."""

    calls: list[tuple[str, Any]] = field(default_factory=list)
    transport: ScriptedTransport = field(
        default_factory=lambda: ScriptedTransport([(200, openai_body("model says hi"))])
    )

    def total(self) -> int:
        return len(self.calls) + len(self.transport.calls)


class _Rec:
    def __init__(self, effects: Effects, kind: str) -> None:
        self.effects, self.kind = effects, kind

    async def call_tool(self, server: str, name: str, args: Mapping[str, Any]) -> Any:
        self.effects.calls.append((self.kind, (server, name, dict(args))))
        return {"mcp": "ok", "ssn": "111-22-3333"}

    async def run(self, *a: Any) -> Any:
        self.effects.calls.append((self.kind, a))
        return {"ran": True, "ssn": "111-22-3333"}

    async def write(self, scope: str, args: Mapping[str, Any]) -> Any:
        self.effects.calls.append((self.kind, (scope, dict(args))))
        return {"written": True}

    async def send(self, channel: str, args: Mapping[str, Any]) -> Any:
        self.effects.calls.append((self.kind, (channel, dict(args))))
        return {"sent": True}


def recording_backends(effects: Effects, clock: FakeClock | None = None) -> Backends:
    tools = ToolRegistry()

    def lookup(args: Mapping[str, Any]) -> Any:
        effects.calls.append(("tool", dict(args)))
        return {"found": True, "name": "Ada", "ssn": "111-22-3333"}

    tools.register("lookup", lookup, description="look things up")

    async def spawn(ref: str, args: Mapping[str, Any]) -> Any:
        effects.calls.append(("spawn", (ref, dict(args))))
        return {"child": "done"}

    return Backends(
        tools=tools,
        mcp=_Rec(effects, "mcp"),
        sandbox=_Rec(effects, "code"),
        browser=_Rec(effects, "browser"),
        memory=_Rec(effects, "memory"),
        channels=_Rec(effects, "channel"),
        models=make_gateway(effects.transport, clock or FakeClock()),
        spawn=spawn,
    )


def model_call() -> ModelCall:
    req = ModelRequest(
        tenant_id=TENANT,
        messages=(Message("system", "be brief"), Message("user", "patient SSN 111-22-3333 please")),
        target=ModelTarget("openai", "gpt-4o"),
    )
    return ModelCall(name="openai/gpt-4o", request=req)


SAMPLES: dict[type[Action], Callable[[], Action]] = {
    ToolCall: lambda: ToolCall(name="lookup", args={"q": "x", "ssn": "111-22-3333"}),
    McpCall: lambda: McpCall(name="search", mcp_server="kb", args={"q": "x", "ssn": "111-22-3333"}),
    CodeExec: lambda: CodeExec(name="py", args={"language": "python", "code": "print(1)"}),
    BrowserExec: lambda: BrowserExec(name="web", args={"url": "https://example.com"}),
    MessageSend: lambda: MessageSend(
        name="notify", channel="slack", args={"to": "#ops", "body": "hi"}
    ),
    MemoryWrite: lambda: MemoryWrite(name="remember", scope="long_term", args={"k": "v"}),
    ModelCall: model_call,
}


async def running_recorder(
    clock: FakeClock | None = None, *, to_state: str = "running"
) -> RunRecorder:
    from axis_runtime.events import InMemoryRunEventLog

    rec = await RunRecorder.start(
        InMemoryRunEventLog(), clock or FakeClock(), run_id="run_1", tenant_id=TENANT, meta={}
    )
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a@1"})
    steps = {
        "spawn": [],
        "ready": [("spawn", "ready", "init_complete")],
        "running": [("spawn", "ready", "init_complete"), ("ready", "running", "scheduled")],
    }[to_state]
    for frm, to, trig in steps:
        await rec.record(
            EventType.PROCESS_TRANSITION, PID, {"from": frm, "to": to, "trigger": trig}
        )
    return rec


def identity(phi: bool = False) -> RunIdentity:
    return RunIdentity(
        tenant_id=TENANT,
        run_id="run_1",
        trace_id="c" * 32,
        span_id="d" * 16,
        blueprint_name="claims-triage",
        blueprint_version="1.0.0",
        phi=phi,
    )


async def make_executor(
    gate: Any = None,
    effects: Effects | None = None,
    *,
    phi: bool = False,
    to_state: str = "running",
    approvals: Any = None,
) -> tuple[ActionExecutor, RunRecorder, Effects, ScriptedGate]:
    effects = effects or Effects()
    gate = gate or ScriptedGate()
    clock = FakeClock()
    rec = await running_recorder(clock, to_state=to_state)
    ex = ActionExecutor(
        gate=gate,
        recorder=rec,
        identity=identity(phi),
        backends=recording_backends(effects, clock),
        gate_timeout=0.2,
        approvals=approvals,
    )
    return ex, rec, effects, gate
