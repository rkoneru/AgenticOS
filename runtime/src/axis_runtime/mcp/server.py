"""MCP server: exposes AXIS tools/agents to external MCP clients.  Transport-agnostic core.

``McpServer.handle(raw_body, bearer)`` takes one HTTP-style request body and returns a ``Reply``;
``http_server.McpHttpServer`` binds it to a socket, tests call it directly.

Security properties (docs/spec/mcp.md):

* Every request is authenticated by the injected ``Authenticator`` BEFORE it is parsed beyond its
  size.  An authenticator error, a missing or malformed token is ``401`` (fail closed).
* The tenant and principal come ONLY from the authenticator.  Nothing in a JSON-RPC message (params,
  ids, names) can select a tenant.  ``tools/list`` and ``tools/call`` look at one tenant's catalog
  filtered by the principal's scopes; a tool of another tenant is indistinguishable from an
  unknown tool.
* ``tools/call`` builds an Action and runs it THROUGH the injected runner (the ``ActionExecutor``
  bound to the principal's tenant, ``ActorType.MCP_CLIENT``): gate, audit event, then perform.
  This module never performs an action itself.
* Per-principal rate limit and in-flight cap, request size cap, result size cap, call timeout.
* Errors are fixed strings.  Exceptions, gate reasons and tool errors are never echoed.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from axis_runtime.actions import Action, to_jsonable
from axis_runtime.executor import (
    ActionOutcome,
    ActionRunner,
    Completed,
    Denied,
    Failed,
    PendingApproval,
    RunIdentity,
)
from axis_runtime.gate import ActorType
from axis_runtime.mcp import protocol
from axis_runtime.mcp.config import TOOL_NAME

SERVER_NAME = "axis"
SERVER_VERSION = "0.0.0"
_BEARER = re.compile(r"^Bearer ([\x21-\x7e]{1,4096})\Z", re.IGNORECASE)


@dataclass(frozen=True)
class Principal:
    """Who is calling, as established by the ``Authenticator`` (never by the message)."""

    tenant_id: str
    principal_id: str
    #: Tool names this principal may list and call; ``"*"`` = every tool of its tenant.
    scopes: frozenset[str] = frozenset({"*"})

    def may_use(self, tool_name: str) -> bool:
        return "*" in self.scopes or tool_name in self.scopes


class Authenticator(Protocol):
    async def authenticate(self, token: str) -> Principal | None: ...


@dataclass(frozen=True)
class ExposedTool:
    name: str
    description: str
    input_schema: Mapping[str, Any]
    #: Builds the Action for validated arguments (a ``ToolCall``/``McpCall``/agent spawn...). The
    #: executor, not this module, gates and performs it.
    build: Callable[[Mapping[str, Any]], Action]


class ToolCatalog(Protocol):
    def tools_for(self, principal: Principal) -> Sequence[ExposedTool]: ...


class TenantToolCatalog:
    """Operator-curated exposure per tenant; only the principal's tenant entries are read."""

    def __init__(self) -> None:
        self._tools: dict[str, dict[str, ExposedTool]] = {}

    def expose(self, tenant_id: str, tool: ExposedTool) -> None:
        if not TOOL_NAME.match(tool.name):
            raise ValueError("invalid tool name")
        self._tools.setdefault(tenant_id, {})[tool.name] = tool

    def tools_for(self, principal: Principal) -> Sequence[ExposedTool]:
        mine = self._tools.get(principal.tenant_id, {})
        return tuple(t for n, t in sorted(mine.items()) if principal.may_use(n))


_Key = tuple[str, str, str, protocol.RequestId]
RunnerFactory = Callable[[Principal], Awaitable[tuple[ActionRunner, str]]]


def mcp_identity(
    principal: Principal,
    *,
    run_id: str,
    trace_id: str,
    span_id: str,
    blueprint_name: str = "mcp-gateway",
    blueprint_version: str = "1",
) -> RunIdentity:
    """The ``RunIdentity`` an inbound call must run under: tenant from the principal, actor
    ``mcp_client``. Runner factories should use this so no code path forgets the actor type."""
    return RunIdentity(
        tenant_id=principal.tenant_id,
        run_id=run_id,
        trace_id=trace_id,
        span_id=span_id,
        blueprint_name=blueprint_name,
        blueprint_version=blueprint_version,
        actor_type=ActorType.MCP_CLIENT,
        actor_id=principal.principal_id,
    )


@dataclass(frozen=True)
class ServerLimits:
    max_request_bytes: int = 256 << 10
    max_result_chars: int = 64 << 10
    rate_per_second: float = 10.0
    burst: int = 20
    max_inflight_per_principal: int = 8
    call_timeout_seconds: float = 60.0
    max_tools_listed: int = 500
    max_rate_keys: int = 10_000


class RateLimiter:
    """Token bucket per key; the key table is bounded (oldest key evicted)."""

    def __init__(
        self, rate: float, burst: int, now: Callable[[], float], max_keys: int = 10_000
    ) -> None:
        self._rate, self._burst, self._now, self._max = rate, float(burst), now, max_keys
        self._buckets: dict[Any, tuple[float, float]] = {}

    def allow(self, key: Any) -> bool:
        t = self._now()
        tokens, last = self._buckets.pop(key, (self._burst, t))
        tokens = min(self._burst, tokens + max(t - last, 0.0) * self._rate)
        ok = tokens >= 1.0
        self._buckets[key] = (tokens - 1.0 if ok else tokens, t)
        while len(self._buckets) > self._max:
            self._buckets.pop(next(iter(self._buckets)))
        return ok


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes | None
    headers: tuple[tuple[str, str], ...] = ()


_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
    "null": (type(None),),
}


def check_arguments(schema: Mapping[str, Any], args: Mapping[str, Any]) -> str | None:
    """A deliberately small JSON-Schema subset: ``required``, ``additionalProperties: false`` and
    top-level property ``type``. Returns a fixed reason or None.  The authoritative checks are the
    gate's and the tool's own; this only rejects obviously malformed calls early."""
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    required = schema.get("required")
    if isinstance(required, list) and any(isinstance(r, str) and r not in args for r in required):
        return "missing required argument"
    if schema.get("additionalProperties") is False and any(k not in props for k in args):
        return "unexpected argument"
    for key, value in args.items():
        spec = props.get(key)
        want = spec.get("type") if isinstance(spec, dict) else None
        if isinstance(want, str) and want in _JSON_TYPES:
            ok = isinstance(value, _JSON_TYPES[want])
            if isinstance(value, bool) and want in ("integer", "number"):
                ok = False
            if not ok:
                return "argument has the wrong type"
    return None


def bearer_from_header(value: str | None) -> str | None:
    if value is None:
        return None
    m = _BEARER.match(value)
    return m.group(1) if m else None


@dataclass
class McpServer:
    authenticator: Authenticator
    catalog: ToolCatalog
    runner_factory: RunnerFactory
    limits: ServerLimits = field(default_factory=ServerLimits)
    monotonic: Callable[[], float] = time.monotonic
    _inflight: dict[tuple[str, str, str, protocol.RequestId], asyncio.Task[dict[str, Any]]] = field(
        default_factory=dict, init=False, repr=False
    )
    _cancelled: set[tuple[str, str, str, protocol.RequestId]] = field(
        default_factory=set, init=False, repr=False
    )
    _limiter: RateLimiter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        lim = self.limits
        self._limiter = RateLimiter(
            lim.rate_per_second, lim.burst, self.monotonic, lim.max_rate_keys
        )

    # ---- replies -----------------------------------------------------------------------------
    @staticmethod
    def _json(
        status: int, obj: Mapping[str, Any], headers: tuple[tuple[str, str], ...] = ()
    ) -> Reply:
        return Reply(status, protocol.dumps(obj).encode("ascii"), headers)

    def _error(
        self, status: int, request_id: protocol.RequestId | None, code: int, message: str
    ) -> Reply:
        return self._json(status, protocol.error_response(request_id, code, message))

    # ---- entry point -------------------------------------------------------------------------
    async def handle(self, raw: bytes, bearer: str | None) -> Reply:
        """One request body in, one ``Reply`` out. Never raises (except cancellation)."""
        try:
            return await self._handle(raw, bearer)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - nothing internal may escape to the client
            return self._error(500, None, protocol.INTERNAL_ERROR, "internal error")

    async def _handle(self, raw: bytes, bearer: str | None) -> Reply:
        if len(raw) > self.limits.max_request_bytes:
            return self._error(413, None, protocol.REQUEST_TOO_LARGE, "request too large")
        principal = await self._authenticate(bearer)
        if principal is None:
            return self._json(
                401,
                protocol.error_response(None, protocol.UNAUTHORIZED, "unauthorized"),
                (("WWW-Authenticate", "Bearer"),),
            )
        try:
            msg = protocol.classify(protocol.loads_strict(raw, self.limits.max_request_bytes))
        except protocol.ProtocolError as exc:
            return self._error(400, exc.request_id, exc.code, exc.message)
        if not self._limiter.allow((principal.tenant_id, principal.principal_id)):
            if msg.kind is protocol.Kind.REQUEST:
                return self._error(429, msg.id, protocol.RATE_LIMITED, "rate limit exceeded")
            return Reply(429, None)
        if msg.kind is protocol.Kind.RESPONSE:  # we never send requests; nothing to correlate
            return Reply(202, None)
        if msg.kind is protocol.Kind.NOTIFICATION:
            self._notification(principal, msg)
            return Reply(202, None)
        assert msg.id is not None and msg.method is not None  # noqa: S101 - classify guarantees
        return await self._request(principal, msg.id, msg.method, msg.body.get("params"))

    async def _authenticate(self, token: str | None) -> Principal | None:
        if token is None:
            return None
        try:
            principal = await self.authenticator.authenticate(token)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - an authenticator failure is a denial
            return None
        if (
            not isinstance(principal, Principal)
            or not principal.tenant_id
            or not principal.principal_id
        ):
            return None
        return principal

    # ---- notifications -----------------------------------------------------------------------
    def _notification(self, principal: Principal, msg: protocol.Message) -> None:
        if msg.method != "notifications/cancelled":
            return  # notifications/initialized and anything else: accepted, ignored
        params = msg.body.get("params")
        rid = params.get("requestId") if isinstance(params, dict) else None
        if not isinstance(rid, str | int) or isinstance(rid, bool):
            return
        key: _Key = (principal.tenant_id, principal.principal_id, type(rid).__name__, rid)
        task = self._inflight.get(key)  # only the caller's own requests are reachable
        if task is not None and not task.done():
            self._cancelled.add(key)
            task.cancel()

    # ---- requests ----------------------------------------------------------------------------
    async def _request(
        self, principal: Principal, rid: protocol.RequestId, method: str, params: Any
    ) -> Reply:
        if method == "ping":
            return self._json(200, protocol.result_response(rid, {}))
        if method == "initialize":
            return self._initialize(rid, params)
        if method == "tools/list":
            return self._list(principal, rid, params)
        if method == "tools/call":
            return await self._call(principal, rid, params)
        return self._error(200, rid, protocol.METHOD_NOT_FOUND, "method not found")

    def _initialize(self, rid: protocol.RequestId, params: Any) -> Reply:
        asked = params.get("protocolVersion") if isinstance(params, dict) else None
        if not isinstance(asked, str):
            return self._error(200, rid, protocol.INVALID_PARAMS, "invalid params")
        version = asked if asked in protocol.PROTOCOL_VERSIONS else protocol.PROTOCOL_VERSIONS[0]
        return self._json(
            200,
            protocol.result_response(
                rid,
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            ),
        )

    def _list(self, principal: Principal, rid: protocol.RequestId, params: Any) -> Reply:
        if params is not None and not isinstance(params, dict):
            return self._error(200, rid, protocol.INVALID_PARAMS, "invalid params")
        cursor = params.get("cursor") if isinstance(params, dict) else None
        if cursor is not None and not isinstance(cursor, str):
            return self._error(200, rid, protocol.INVALID_PARAMS, "invalid params")
        tools = [
            {"name": t.name, "description": t.description, "inputSchema": dict(t.input_schema)}
            for t in self.catalog.tools_for(principal)
            if principal.may_use(t.name)  # defence in depth: do not trust the catalog's filter
        ][: self.limits.max_tools_listed]
        # No pagination: a cursor (which we never issue) yields the same single page.
        return self._json(200, protocol.result_response(rid, {"tools": tools}))

    async def _call(self, principal: Principal, rid: protocol.RequestId, params: Any) -> Reply:
        if not isinstance(params, dict):
            return self._error(200, rid, protocol.INVALID_PARAMS, "invalid params")
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            return self._error(200, rid, protocol.INVALID_PARAMS, "invalid params")
        tool = next(
            (
                t
                for t in self.catalog.tools_for(principal)
                if t.name == name and principal.may_use(t.name)
            ),
            None,
        )
        if tool is None:  # unknown, out of scope and other-tenant look identical
            return self._error(200, rid, protocol.INVALID_PARAMS, "unknown tool")
        if check_arguments(tool.input_schema, args) is not None:
            return self._error(200, rid, protocol.INVALID_PARAMS, "invalid arguments")
        key = (principal.tenant_id, principal.principal_id, type(rid).__name__, rid)
        mine = sum(1 for k in self._inflight if k[:2] == key[:2])
        if key in self._inflight:
            return self._error(200, rid, protocol.INVALID_REQUEST, "request id already in use")
        if mine >= self.limits.max_inflight_per_principal:
            return self._error(429, rid, protocol.RATE_LIMITED, "too many concurrent requests")
        task = asyncio.ensure_future(self._run_tool(principal, tool, args))
        self._inflight[key] = task
        try:
            result = await asyncio.wait_for(task, self.limits.call_timeout_seconds)
        except TimeoutError:
            return self._error(200, rid, protocol.INTERNAL_ERROR, "request timed out")
        except asyncio.CancelledError:
            if key in self._cancelled:
                return self._error(200, rid, protocol.CANCELLED, "request cancelled")
            task.cancel()
            raise
        except Exception:  # noqa: BLE001
            return self._error(200, rid, protocol.INTERNAL_ERROR, "internal error")
        finally:
            self._inflight.pop(key, None)
            self._cancelled.discard(key)
        return self._json(200, protocol.result_response(rid, result))

    async def _run_tool(
        self, principal: Principal, tool: ExposedTool, args: Mapping[str, Any]
    ) -> dict[str, Any]:
        runner, pid = await self.runner_factory(principal)
        outcome: ActionOutcome = await runner.run(tool.build(dict(args)), pid=pid)
        return self._to_result(outcome)

    def _to_result(self, outcome: ActionOutcome) -> dict[str, Any]:
        def text(message: str, *, error: bool) -> dict[str, Any]:
            return {"content": [{"type": "text", "text": message}], "isError": error}

        if isinstance(outcome, Completed):
            body = json.dumps(to_jsonable(outcome.result), default=str)
            if len(body) > self.limits.max_result_chars:
                body = body[: self.limits.max_result_chars]
                return {
                    "content": [{"type": "text", "text": body}],
                    "isError": False,
                    "_meta": {"truncated": True},
                }
            return text(body, error=False)
        if isinstance(outcome, Denied):
            return text("Denied by policy. The call was not performed.", error=True)
        if isinstance(outcome, PendingApproval):
            return text("Approval required. The call was not performed.", error=True)
        if isinstance(outcome, Failed):
            return text("The tool failed.", error=True)
        return text("The tool failed.", error=True)
