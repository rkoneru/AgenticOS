"""Actions: every external side effect the runtime can perform.

An Action is pure data plus a guarded ``perform``.  ``perform`` only works when called with the
capability token the ``ActionExecutor`` binds at import time, so the only supported way to run
an action is ``executor.run(action)`` (gate -> audit event -> perform).  Calling ``perform``
directly raises ``DirectExecutionError``.  The guard is a runtime tripwire, not a sandbox: the
AST bypass test additionally forbids any module except the executor from referencing it.
"""

from __future__ import annotations

import dataclasses
import inspect
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from axis_runtime.gate import EnforcementPoint
from axis_runtime.guard import (
    DirectExecutionError,
    ExecutionToken,
    bind_executor_token,
    executing,
    in_executor,
    token_is_valid,
)
from axis_runtime.models.types import ModelRequest, ModelResponse
from axis_runtime.redaction import REDACTED, redact_paths
from axis_runtime.tools import (
    BackendUnavailableError,
    BrowserRunner,
    ChannelSender,
    CodeSandbox,
    McpClient,
    MemoryStore,
    SpawnHandler,
    ToolRegistry,
)

if TYPE_CHECKING:
    from axis_runtime.models.gateway import ModelGateway


@dataclass
class Backends:
    """Implementations the executor hands to ``Action.perform``."""

    tools: ToolRegistry | None = None
    mcp: McpClient | None = None
    sandbox: CodeSandbox | None = None
    browser: BrowserRunner | None = None
    memory: MemoryStore | None = None
    channels: ChannelSender | None = None
    models: ModelGateway | None = None
    spawn: SpawnHandler | None = None

    def need(self, name: str) -> Any:
        available: dict[str, Any] = {
            "tools": self.tools,
            "mcp": self.mcp,
            "sandbox": self.sandbox,
            "browser": self.browser,
            "memory": self.memory,
            "channels": self.channels,
            "models": self.models,
            "spawn": self.spawn,
        }
        value = available[name]  # unknown names are a programming error (KeyError)
        if value is None:
            raise BackendUnavailableError(f"no {name} backend configured")
        return value


def to_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, str | int | float | bool):
        return obj
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_jsonable(dataclasses.asdict(obj))
    if isinstance(obj, Mapping):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [to_jsonable(v) for v in obj]
    return str(obj)


__all__ = [
    "Action",
    "Backends",
    "BrowserExec",
    "CodeExec",
    "DirectExecutionError",
    "ExecutionToken",
    "McpCall",
    "MemoryWrite",
    "MessageSend",
    "ModelCall",
    "ToolCall",
    "action_from_spec",
    "all_action_types",
    "bind_executor_token",
    "in_executor",
    "to_jsonable",
]


class Action(ABC):
    """Base class of every external action.  Subclasses are frozen dataclasses."""

    enforcement_point: ClassVar[EnforcementPoint]
    name: str

    # ---- what the gate sees ------------------------------------------------------------
    @abstractmethod
    def tool_descriptor(self) -> dict[str, str]:
        """``tool.{name,kind,side_effects}`` of the gate context."""

    @abstractmethod
    def gate_args(self) -> dict[str, Any]:
        """The document addressed by ``args.*`` paths."""

    @abstractmethod
    def with_args(self, doc: Mapping[str, Any]) -> Action:
        """A copy of this action carrying (redacted) arguments."""

    def redact_result(self, result: Any, paths: list[str]) -> Any:
        return redact_paths(to_jsonable(result), paths)

    # ---- what the event log stores -----------------------------------------------------
    def result_event(self, result: Any) -> tuple[str, dict[str, Any]]:
        return "tool_call_result", {
            "enforcement_point": self.enforcement_point.value,
            "name": self.name,
            "ok": True,
            "result": to_jsonable(result),
            "error": None,
        }

    def failure_event(self, error: str) -> tuple[str, dict[str, Any]]:
        return "tool_call_result", {
            "enforcement_point": self.enforcement_point.value,
            "name": self.name,
            "ok": False,
            "result": None,
            "error": error,
        }

    # ---- serialisation (Temporal activity boundary) -----------------------------------
    def to_spec(self) -> dict[str, Any]:
        return {"type": type(self).__name__, "fields": to_jsonable(dataclasses.asdict(self))}  # type: ignore[call-overload]

    # ---- execution ---------------------------------------------------------------------
    async def perform(self, token: ExecutionToken, backends: Backends) -> Any:
        if not token_is_valid(token):
            raise DirectExecutionError(
                f"{type(self).__name__} can only be executed through ActionExecutor.run()"
            )
        with executing():
            return await self._execute(backends)

    @abstractmethod
    async def _execute(self, backends: Backends) -> Any: ...


@dataclass(frozen=True)
class _ArgsAction(Action, ABC):
    name: str
    args: Mapping[str, Any] = field(default_factory=dict)

    def gate_args(self) -> dict[str, Any]:
        return dict(self.args)

    def with_args(self, doc: Mapping[str, Any]) -> Action:
        return dataclasses.replace(self, args=dict(doc))


@dataclass(frozen=True)
class ToolCall(_ArgsAction):
    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.TOOL_CALL
    kind: str = "function"
    side_effects: str = "write"
    ref: str | None = None

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": self.kind, "side_effects": self.side_effects}

    async def _execute(self, backends: Backends) -> Any:
        if self.kind == "agent":
            spawn: SpawnHandler = backends.need("spawn")
            return await spawn(self.ref or self.name, self.args)
        tools: ToolRegistry = backends.need("tools")
        return await tools.call(self.ref or self.name, self.args)


@dataclass(frozen=True)
class McpCall(_ArgsAction):
    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.MCP_CALL
    mcp_server: str = ""
    side_effects: str = "write"

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "mcp", "side_effects": self.side_effects}

    async def _execute(self, backends: Backends) -> Any:
        mcp: McpClient = backends.need("mcp")
        return await mcp.call_tool(self.mcp_server, self.name, self.args)


@dataclass(frozen=True)
class CodeExec(_ArgsAction):
    """``args = {"language": str, "code": str}``."""

    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.CODE_EXEC
    side_effects: str = "external"
    timeout_seconds: int = 60

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "code", "side_effects": self.side_effects}

    async def _execute(self, backends: Backends) -> Any:
        sandbox: CodeSandbox = backends.need("sandbox")
        return await sandbox.run(
            str(self.args.get("language", "")), str(self.args.get("code", "")), self.timeout_seconds
        )


@dataclass(frozen=True)
class BrowserExec(_ArgsAction):
    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.BROWSER_EXEC
    side_effects: str = "external"

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "browser", "side_effects": self.side_effects}

    async def _execute(self, backends: Backends) -> Any:
        browser: BrowserRunner = backends.need("browser")
        return await browser.run(self.args)


@dataclass(frozen=True)
class MessageSend(_ArgsAction):
    """Outbound message on a channel. ``args = {"to": ..., "body": ...}``."""

    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.MESSAGE_SEND
    channel: str = ""
    side_effects: str = "external"

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "channel", "side_effects": self.side_effects}

    async def _execute(self, backends: Backends) -> Any:
        channels: ChannelSender = backends.need("channels")
        return await channels.send(self.channel, self.args)


@dataclass(frozen=True)
class MemoryWrite(_ArgsAction):
    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.MEMORY_WRITE
    scope: str = "run"

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": f"memory:{self.scope}", "side_effects": "write"}

    async def _execute(self, backends: Backends) -> Any:
        memory: MemoryStore = backends.need("memory")
        return await memory.write(self.scope, self.args)


@dataclass(frozen=True)
class ModelCall(Action):
    """A call to a model provider: data egress, so it is gated like any tool."""

    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.MODEL_CALL
    request: ModelRequest = field(kw_only=True)
    name: str = "model"

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "model", "side_effects": "external"}

    def gate_args(self) -> dict[str, Any]:
        r = self.request
        return {
            "provider": r.target.provider,
            "model": r.target.model,
            "fallbacks": [f"{t.provider}/{t.model}" for t in r.fallbacks],
            "messages": [
                {"role": m.role, "content": m.content, "tool_calls": [c.name for c in m.tool_calls]}
                for m in r.messages
            ],
            "tool_names": [t.name for t in r.tools],
        }

    def with_args(self, doc: Mapping[str, Any]) -> Action:
        msgs = doc["messages"]
        if len(msgs) != len(self.request.messages):
            raise ValueError("redaction changed the message structure")
        new = tuple(
            dataclasses.replace(m, content=str(d["content"]))
            for m, d in zip(self.request.messages, msgs, strict=True)
        )
        return dataclasses.replace(self, request=dataclasses.replace(self.request, messages=new))

    def redact_result(self, result: Any, paths: list[str]) -> Any:
        if not isinstance(result, ModelResponse):
            return redact_paths(to_jsonable(result), paths)
        doc = redact_paths({"text": result.text}, paths)
        text = doc["text"] if isinstance(doc["text"], str) else REDACTED
        return dataclasses.replace(result, text=text)

    def result_event(self, result: Any) -> tuple[str, dict[str, Any]]:
        if not isinstance(result, ModelResponse):
            return super().result_event(result)
        cost = None
        if result.cost_usd is not None:
            cost = int((result.cost_usd * 1_000_000).to_integral_value())
        return "model_call", {
            "provider": result.provider,
            "model": result.model,
            "input_tokens": result.usage.input_tokens,
            "output_tokens": result.usage.output_tokens,
            "cached_tokens": result.usage.cached_tokens,
            "cost_micro_usd": cost,
            "finish_reason": result.finish_reason.value,
            "latency_ms": result.latency_ms,
            "attempts": [f"{a.provider}/{a.model}:{a.outcome}" for a in result.attempts],
        }

    def to_spec(self) -> dict[str, Any]:
        return {
            "type": "ModelCall",
            "fields": {"name": self.name, "request": self.request.to_dict()},
        }

    async def _execute(self, backends: Backends) -> Any:
        models: ModelGateway = backends.need("models")
        return await models.complete(self.request)


def action_from_spec(spec: Mapping[str, Any]) -> Action:
    """Rebuild an Action from ``to_spec()`` output (Temporal activity side)."""
    by_name = {t.__name__: t for t in all_action_types()}
    cls = by_name.get(str(spec.get("type")))
    if cls is None:
        raise ValueError(f"unknown action type {spec.get('type')!r}")
    fields = dict(spec["fields"])
    if cls is ModelCall:
        return ModelCall(name=fields["name"], request=ModelRequest.from_dict(fields["request"]))
    return cls(**fields)


def all_action_types() -> tuple[type[Action], ...]:
    """Every concrete Action subclass (registry for the bypass guard)."""
    found: dict[str, type[Action]] = {}
    stack: list[Any] = [Action]
    while stack:
        cls = stack.pop()
        for sub in cls.__subclasses__():
            stack.append(sub)
            if not inspect.isabstract(sub):
                found[f"{sub.__module__}.{sub.__qualname__}"] = sub
    return tuple(found[k] for k in sorted(found))
