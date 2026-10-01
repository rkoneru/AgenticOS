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

from axis_runtime.browser.args import gate_view, merge_redacted
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
from axis_runtime.sandbox.types import (
    SandboxBackend,
    SandboxLimits,
    SandboxPolicyError,
    SandboxResult,
    SandboxSpec,
    sha256_hex,
)
from axis_runtime.tools import (
    BackendUnavailableError,
    BrowserRunner,
    ChannelSender,
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
    sandbox: SandboxBackend | None = None
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
    "CodeRunAction",
    "DirectExecutionError",
    "ExecutionToken",
    "McpCall",
    "MemoryRead",
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
    #: The tool's name on the MCP server when it differs from the agent-facing ``name``.
    ref: str | None = None

    @property
    def qualified_name(self) -> str:
        """``server/tool``: the unambiguous identity policies and audit see.  Server names cannot
        contain ``/`` (``mcp.config.SERVER_NAME``), so no tool can impersonate another server's."""
        return f"{self.mcp_server}/{self.ref or self.name}"

    def tool_descriptor(self) -> dict[str, str]:
        return {
            "name": self.qualified_name,
            "kind": "mcp",
            "side_effects": self.side_effects,
            "server": self.mcp_server,
        }

    async def _execute(self, backends: Backends) -> Any:
        mcp: McpClient = backends.need("mcp")
        return await mcp.call_tool(self.mcp_server, self.ref or self.name, self.args)


@dataclass(frozen=True)
class CodeRunAction(_ArgsAction):
    """Run code in the sandbox.  ``args = {"language": str, "code": str}`` is what the agent gives.

    The gate sees ``language``, ``code_sha256``, ``code_bytes``, the limits and the network flag,
    NEVER the code text, and neither does the audit log.  ``network`` is wiring, not an agent
    argument: it defaults to False and is only set by deployment code; the policy decides on it.
    """

    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.CODE_EXEC
    side_effects: str = "external"
    timeout_seconds: int = 60
    network: bool = False
    limits: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._spec()  # validate early: unknown limits / language / env fail at construction

    def _spec(self) -> SandboxSpec:
        raw = {"wall_seconds": float(self.timeout_seconds), **dict(self.limits)}
        return SandboxSpec(
            language=str(self.args.get("language", "")),
            code=str(self.args.get("code", "")),
            limits=SandboxLimits.from_mapping(raw),
            network=self.network,
        )

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "code", "side_effects": self.side_effects}

    def gate_args(self) -> dict[str, Any]:
        return self._spec().describe()

    def with_args(self, doc: Mapping[str, Any]) -> Action:
        # The gate document holds metadata only; redacting it can never change the code that runs.
        args = {**self.args, "language": str(doc.get("language", self.args.get("language", "")))}
        try:
            return dataclasses.replace(self, args=args)
        except SandboxPolicyError as exc:  # the executor turns ValueError into a blocked action
            raise ValueError("redaction made the code action invalid") from exc

    def result_event(self, result: Any) -> tuple[str, dict[str, Any]]:
        summary = result.audit_summary() if isinstance(result, SandboxResult) else None
        if summary is None and isinstance(result, Mapping):
            summary = _summarise_result_dict(result)
        etype, data = super().result_event(None)
        data["result"] = {**self._spec().describe(), **(summary or {})}
        return etype, data

    async def _execute(self, backends: Backends) -> Any:
        sandbox: SandboxBackend = backends.need("sandbox")
        result = await sandbox.run(self._spec())
        return result.to_dict() if isinstance(result, SandboxResult) else result


def _summarise_result_dict(result: Mapping[str, Any]) -> dict[str, Any]:
    """Audit form of a result that is already a dict: hashes and sizes, never output text."""
    keep = (
        "exit_code",
        "ok",
        "killed_reason",
        "signal",
        "stdout_bytes",
        "stderr_bytes",
        "stdout_truncated",
        "stderr_truncated",
        "duration_seconds",
        "usage",
        "skipped_artifacts",
        "isolation",  # what protections this run actually had: part of the evidence
    )
    out = {k: result[k] for k in keep if k in result}
    for stream in ("stdout", "stderr"):
        text = result.get(stream)
        if isinstance(text, str):
            out[f"{stream}_sha256"] = sha256_hex(text.encode())
            out.setdefault(f"{stream}_bytes", len(text.encode()))
    arts = result.get("artifacts")
    if isinstance(arts, list):
        out["artifacts"] = [
            {k: a.get(k) for k in ("path", "size", "sha256")}
            for a in arts
            if isinstance(a, Mapping)
        ]
    return out


@dataclass(frozen=True)
class BrowserExec(_ArgsAction):
    """One browser operation: ``args = {"operation": navigate|click|type|extract|screenshot, ...}``.

    ``target_url`` is the page a non-navigation operation acts on (``BrowserWorker.action`` fills
    it from the worker's own state); the worker refuses to run if the live page differs. The gate
    sees a derived view (operation, sanitised URL, host, args hash; typed text only as a hash,
    nothing at all for sensitive fields), never the raw text. See docs/spec/browser.md.
    """

    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.BROWSER_EXEC
    side_effects: str = "external"
    target_url: str = ""

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "browser", "side_effects": self.side_effects}

    def gate_args(self) -> dict[str, Any]:
        return gate_view(self.args, self.target_url)

    def with_args(self, doc: Mapping[str, Any]) -> Action:
        return dataclasses.replace(self, args=merge_redacted(self.args, doc))

    def result_event(self, result: Any) -> tuple[str, dict[str, Any]]:
        # The extracted text goes back to the agent, not into the event log: only its hash and size.
        if isinstance(result, Mapping):
            result = {k: v for k, v in result.items() if k != "text"}
        return super().result_event(result)

    async def _execute(self, backends: Backends) -> Any:
        browser: BrowserRunner = backends.need("browser")
        return await browser.run({**self.args, "target_url": self.target_url})


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
class MemoryRead(_ArgsAction):
    """Agent-facing memory search: ``args = {"query": str, "scope"?: str, "limit"?: int}``.

    ``scopes`` is wiring, never an agent argument: the scopes the manifest's ``memory.*`` flags
    allow. The frozen policy DSL has no ``memory_read`` enforcement point, so a read is gated as a
    ``tool_call`` whose ``tool.kind`` is ``memory:read`` (docs/adr/0014). The gate sees the scopes,
    the limit and the query's hash and length, NEVER the query text; the event log keeps hits as
    ids, scores and content hashes. The agent itself receives the passages it is allowed to read.
    """

    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.TOOL_CALL
    scopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "scopes", tuple(self.scopes))
        self._parsed()  # validate early: a bad call is a tool error, never a gated action

    def _parsed(self) -> tuple[str, tuple[str, ...], int]:
        query = self.args.get("query")
        if not isinstance(query, str) or not query or len(query) > 4000:
            raise ValueError("memory search needs a 'query' of 1..4000 characters")
        scope = self.args.get("scope")
        if scope is None:
            chosen = self.scopes
        elif isinstance(scope, str) and scope in self.scopes:
            chosen = (scope,)
        else:
            raise ValueError("memory scope is not enabled for this agent")
        if not chosen:
            raise ValueError("this agent has no readable memory")
        limit = self.args.get("limit", 5)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise ValueError("limit must be an integer 1..20")
        return query, chosen, limit

    def tool_descriptor(self) -> dict[str, str]:
        return {"name": self.name, "kind": "memory:read", "side_effects": "read"}

    def gate_args(self) -> dict[str, Any]:
        query, chosen, limit = self._parsed()
        return {
            "scopes": list(chosen),
            "limit": limit,
            "query_len": len(query),
            "query_sha256": sha256_hex(query.encode()),
        }

    def with_args(self, doc: Mapping[str, Any]) -> Action:
        return self  # the gate document is metadata only: there is nothing in it to redact into

    def result_event(self, result: Any) -> tuple[str, dict[str, Any]]:
        hits = result.get("hits") if isinstance(result, Mapping) else None
        summary = [
            {
                "id": h.get("id"),
                "scope": h.get("scope"),
                "kb": h.get("kb"),
                "score": h.get("score"),
                "content_sha256": sha256_hex(str(h.get("content", "")).encode()),
                "content_bytes": len(str(h.get("content", "")).encode()),
            }
            for h in (hits if isinstance(hits, list) else [])
            if isinstance(h, Mapping)
        ]
        return super().result_event({"hits": summary})

    async def _execute(self, backends: Backends) -> Any:
        memory: MemoryStore = backends.need("memory")
        query, chosen, limit = self._parsed()
        return await memory.search(query, scopes=chosen, limit=limit)


@dataclass(frozen=True)
class ModelCall(Action):
    """A call to a model provider: data egress, so it is gated like any tool."""

    enforcement_point: ClassVar[EnforcementPoint] = EnforcementPoint.MODEL_CALL
    request: ModelRequest = field(kw_only=True)
    name: str = "model"
    #: A model answer NEXUS already holds (cache hit). The call is still gated and audited like the
    #: real one (same name, arguments and enforcement point), but ``perform`` returns this response
    #: instead of reaching the provider. Never serialised: a replay is not a Temporal activity.
    replay: ModelResponse | None = field(default=None, kw_only=True)

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
        if self.replay is not None:
            raise ValueError("a replayed model call cannot be serialised")
        return {
            "type": "ModelCall",
            "fields": {"name": self.name, "request": self.request.to_dict()},
        }

    async def _execute(self, backends: Backends) -> Any:
        if self.replay is not None:
            return self.replay
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
