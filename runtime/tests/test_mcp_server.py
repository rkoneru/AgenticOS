# ruff: noqa: S107
"""MCP server: authentication, tenant scoping, gating of inbound calls, limits, adversarial input."""

from __future__ import annotations

import asyncio
import json
import random
from typing import Any

import pytest
from axis_runtime.actions import Backends, ToolCall
from axis_runtime.events import EventType, InMemoryRunEventLog, RunRecorder
from axis_runtime.executor import ActionExecutor
from axis_runtime.mcp import (
    ExposedTool,
    McpServer,
    Principal,
    ServerLimits,
    TenantToolCatalog,
    mcp_identity,
)
from axis_runtime.mcp import protocol as p
from axis_runtime.mcp.server import RateLimiter, bearer_from_header, check_arguments
from axis_runtime.tools import ToolRegistry
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny
from helpers import PID

OTHER = "22222222-2222-4222-8222-222222222222"
ALICE = Principal(TENANT, "alice")
BOB = Principal(TENANT, "bob", frozenset({"lookup"}))
EVE = Principal(OTHER, "eve")
TOKENS = {"tok-alice": ALICE, "tok-bob": BOB, "tok-eve": EVE}


class Auth:
    def __init__(self) -> None:
        self.seen: list[str] = []

    async def authenticate(self, token: str) -> Principal | None:
        self.seen.append(token)
        if token == "boom":
            raise RuntimeError("db password is hunter2")
        if token == "weird":
            return Principal("", "x")
        return TOKENS.get(token)


class Harness:
    def __init__(self, gate: ScriptedGate | None = None, **limits: Any) -> None:
        self.gate = gate or ScriptedGate(allow())
        self.performed: list[tuple[str, dict[str, Any]]] = []
        self.recorders: dict[str, RunRecorder] = {}
        self.identities: list[Any] = []
        self.registry = ToolRegistry()
        self.registry.register("lookup", self._tool("lookup"))
        self.registry.register("admin", self._tool("admin"))
        self.registry.register("slow", self._slow)
        self.registry.register("fail", self._fail)
        self.registry.register("huge", lambda a: {"blob": "z" * 10_000})
        self.release = asyncio.Event()
        self.catalog = TenantToolCatalog()
        schema = {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
            "additionalProperties": False,
        }
        for name in ("lookup", "admin", "slow", "fail", "huge"):
            self.catalog.expose(
                TENANT, self._exposed(name, schema if name == "lookup" else {"type": "object"})
            )
        self.catalog.expose(OTHER, self._exposed("lookup", {"type": "object"}))
        self.catalog.expose(OTHER, self._exposed("other_only", {"type": "object"}, ref="lookup"))
        self.server = McpServer(
            Auth(),
            self.catalog,
            self.runner_factory,
            ServerLimits(**limits),
            monotonic=lambda: self.now,
        )
        self.now = 0.0

    def _tool(self, name: str) -> Any:
        def handler(args: Any) -> Any:
            self.performed.append((name, dict(args)))
            return {"ok": name, "echo": dict(args)}

        return handler

    async def _slow(self, args: Any) -> Any:
        await self.release.wait()
        return {"done": True}

    def _fail(self, args: Any) -> Any:
        raise RuntimeError("secret internal path /srv/keys")

    def _exposed(self, name: str, schema: Any, ref: str | None = None) -> ExposedTool:
        return ExposedTool(
            name, f"{name} tool", schema, lambda a: ToolCall(name=ref or name, args=a)
        )

    async def runner_factory(self, principal: Principal) -> tuple[ActionExecutor, str]:
        ident = mcp_identity(
            principal, run_id=f"mcp-{principal.principal_id}", trace_id="c" * 32, span_id="d" * 16
        )
        self.identities.append(ident)
        rec = await RunRecorder.start(
            InMemoryRunEventLog(),
            FakeClock(),
            run_id=ident.run_id,
            tenant_id=principal.tenant_id,
            meta={},
        )
        await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "mcp@1"})
        for frm, to, trig in (
            ("spawn", "ready", "init_complete"),
            ("ready", "running", "scheduled"),
        ):
            await rec.record(
                EventType.PROCESS_TRANSITION, PID, {"from": frm, "to": to, "trigger": trig}
            )
        self.recorders[principal.principal_id] = rec
        ex = ActionExecutor(
            gate=self.gate,
            recorder=rec,
            identity=ident,
            backends=Backends(tools=self.registry),
            gate_timeout=0.5,
        )
        return ex, PID

    async def post(self, body: Any, token: str | None = "tok-alice") -> tuple[int, Any]:
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        reply = await self.server.handle(raw, token)
        return reply.status, (json.loads(reply.body) if reply.body else None)

    async def rpc(
        self,
        method: str,
        params: Any = None,
        rid: Any = 1,
        token: str | None = "tok-alice",  # noqa: S107
    ) -> Any:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        return await self.post(msg, token)

    async def call(self, name: str, args: Any = None, **kw: Any) -> Any:
        return await self.rpc(
            "tools/call", {"name": name, "arguments": args if args is not None else {}}, **kw
        )


@pytest.fixture
def h() -> Harness:
    return Harness()


# ---- authentication ----------------------------------------------------------------------------


@pytest.mark.parametrize("token", [None, "", "nope", "boom", "weird"])
async def test_unauthenticated_is_401_and_nothing_runs(h: Harness, token: str | None) -> None:
    status, body = await h.call("lookup", {"q": "x"}, token=token)
    assert status == 401 and body["error"]["code"] == p.UNAUTHORIZED
    assert "hunter2" not in json.dumps(body)
    assert h.gate.requests == [] and h.performed == []


async def test_auth_happens_before_parsing(h: Harness) -> None:
    status, body = await h.post(b"{not json", token=None)
    assert status == 401 and body["error"]["code"] == p.UNAUTHORIZED
    assert h.server.authenticator.seen == []  # type: ignore[attr-defined]


def test_bearer_header_parsing() -> None:
    assert bearer_from_header("Bearer abc") == "abc"
    assert bearer_from_header("bearer abc") == "abc"
    for bad in (
        None,
        "",
        "Basic abc",
        "Bearer",
        "Bearer a b",
        "Bearer abc\n",
        "Bearer " + "a" * 5000,
    ):
        assert bearer_from_header(bad) is None


# ---- protocol ----------------------------------------------------------------------------------


async def test_initialize_ping_and_unknown_method(h: Harness) -> None:
    _, body = await h.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}})
    assert body["result"]["protocolVersion"] == "2025-03-26"
    assert body["result"]["capabilities"] == {"tools": {"listChanged": False}}
    _, body = await h.rpc("initialize", {"protocolVersion": "1999"})
    assert body["result"]["protocolVersion"] == p.PROTOCOL_VERSIONS[0]
    _, body = await h.rpc("initialize", {})
    assert body["error"]["code"] == p.INVALID_PARAMS
    _, body = await h.rpc("ping")
    assert body["result"] == {}
    for method in ("resources/list", "prompts/list", "sampling/createMessage", "x"):
        _, body = await h.rpc(method)
        assert body["error"]["code"] == p.METHOD_NOT_FOUND


async def test_id_is_echoed_with_its_exact_type(h: Harness) -> None:
    for rid in (0, 7, "seven", "1", -5, 2**40):
        _, body = await h.rpc("ping", rid=rid)
        assert body["id"] == rid and type(body["id"]) is type(rid)


@pytest.mark.parametrize("rid", [True, 1.5, None, [1], {"a": 1}])
async def test_bad_ids_are_invalid_requests(h: Harness, rid: Any) -> None:
    status, body = await h.post({"jsonrpc": "2.0", "id": rid, "method": "ping"})
    assert status == 400 and body["error"]["code"] == p.INVALID_REQUEST and body["id"] is None


async def test_notifications_get_no_body(h: Harness) -> None:
    for note in (
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"q": "x"}},
        },
        {"jsonrpc": "2.0", "method": "who/knows"},
    ):
        status, body = await h.post(note)
        assert status == 202 and body is None
    assert h.performed == [] and h.gate.requests == []  # a tools/call notification never runs


async def test_responses_are_ignored(h: Harness) -> None:
    status, body = await h.post({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert status == 202 and body is None


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]',
        b"null",
        b"\xff",
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
        b"[" * 50000,
    ],
)
async def test_malformed_json_rpc_is_a_400_error_object(h: Harness, raw: bytes) -> None:
    status, body = await h.post(raw)
    assert status == 400 and body["jsonrpc"] == "2.0" and "error" in body and "result" not in body


async def test_request_size_cap_before_anything_else() -> None:
    h = Harness(max_request_bytes=200)
    status, body = await h.post(b"x" * 201, token=None)
    assert status == 413 and body["error"]["code"] == p.REQUEST_TOO_LARGE
    huge = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "lookup", "arguments": {"q": "y" * 500}},
    }
    status, _ = await h.post(huge)
    assert status == 413
    assert h.gate.requests == []


async def test_random_garbage_never_crashes_and_never_executes(h: Harness) -> None:
    rng = random.Random(7)
    base = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "admin", "arguments": {}},
        }
    ).encode()
    for _ in range(400):
        raw = bytearray(base)
        for _ in range(rng.randint(1, 5)):
            raw[rng.randrange(len(raw))] = rng.randrange(256)
        status, _ = await h.post(bytes(raw), token="tok-bob")  # bob may NOT use admin
        assert status in (200, 202, 400, 429)
    assert all(name != "admin" for name, _ in h.performed)


# ---- listing: tenant and scope filtering -------------------------------------------------------


async def test_list_is_per_tenant_and_per_scope(h: Harness) -> None:
    def names(body: Any) -> set[str]:
        return {t["name"] for t in body["result"]["tools"]}

    _, a = await h.rpc("tools/list", token="tok-alice")
    _, b = await h.rpc("tools/list", token="tok-bob")
    _, e = await h.rpc("tools/list", token="tok-eve")
    assert names(a) == {"lookup", "admin", "slow", "fail", "huge"}
    assert names(b) == {"lookup"}
    assert names(e) == {"lookup", "other_only"}
    assert set(a["result"]["tools"][0]) == {"name", "description", "inputSchema"}


async def test_list_params_validation_and_cursor(h: Harness) -> None:
    _, body = await h.rpc("tools/list", {"cursor": 5})
    assert body["error"]["code"] == p.INVALID_PARAMS
    _, body = await h.rpc("tools/list", [1])
    assert body["error"]["code"] == p.INVALID_PARAMS
    _, body = await h.rpc("tools/list", {"cursor": "x"})
    assert len(body["result"]["tools"]) == 5 and "nextCursor" not in body["result"]


async def test_list_cap_and_defence_in_depth_filter() -> None:
    h = Harness(max_tools_listed=2)
    _, body = await h.rpc("tools/list")
    assert len(body["result"]["tools"]) == 2

    class LeakyCatalog:
        def tools_for(self, principal: Principal) -> Any:
            return [
                t for ts in h.catalog._tools.values() for t in ts.values()
            ]  # ignores tenant+scope

    h.server.catalog = LeakyCatalog()
    _, body = await h.rpc("tools/list", token="tok-bob")
    assert {t["name"] for t in body["result"]["tools"]} == {"lookup"}
    status, body = await h.call("admin", token="tok-bob")
    assert body["error"]["code"] == p.INVALID_PARAMS and h.performed == []


async def test_tenant_cannot_be_chosen_by_the_message(h: Harness) -> None:
    sneaky = {"name": "other_only", "arguments": {}, "tenant_id": OTHER, "_meta": {"tenant": OTHER}}
    _, body = await h.rpc("tools/call", sneaky)  # alice is TENANT; other_only is OTHER's
    assert body["error"]["message"] == "unknown tool"
    _, body = await h.rpc(
        "tools/call", {"name": "lookup", "arguments": {"q": "x"}, "tenant_id": OTHER}
    )
    assert h.gate.requests[-1].tenant_id == TENANT
    assert h.identities[-1].tenant_id == TENANT


# ---- calls go through executor + gate ----------------------------------------------------------


async def test_call_is_gated_audited_and_attributed_to_the_mcp_client(h: Harness) -> None:
    status, body = await h.call("lookup", {"q": "x"}, token="tok-bob")
    assert status == 200 and body["result"]["isError"] is False
    assert json.loads(body["result"]["content"][0]["text"]) == {"ok": "lookup", "echo": {"q": "x"}}
    (req,) = h.gate.requests
    assert req.actor_type.value == "mcp_client" and req.actor_id == "bob"
    assert req.tenant_id == TENANT and req.context["actor"]["type"] == "mcp_client"
    assert req.context["inbound"] == {"transport": "mcp", "principal": "bob"}
    assert req.context["args"] == {"q": "x"} and req.context["tool"]["name"] == "lookup"
    events = (
        [e.type for e in h.recorders["bob"].state.events]
        if hasattr(h.recorders["bob"].state, "events")
        else None
    )
    assert h.recorders["bob"].state.gate_decisions  # the decision was recorded in the run log
    assert events is None or EventType.GATE_DECISION in events


async def test_denied_call_performs_nothing_and_does_not_leak_the_reason() -> None:
    h = Harness(ScriptedGate(deny("policy pci-7: card number rule matched")))
    _, body = await h.call("lookup", {"q": "x"})
    result = body["result"]
    assert result["isError"] is True and "pci" not in json.dumps(body)
    assert h.performed == [] and len(h.gate.requests) == 1


async def test_gate_failure_is_a_denial() -> None:
    class Down:
        async def evaluate(self, request: Any) -> Any:
            raise ConnectionError("kernel at 10.0.0.9 unreachable")

    h = Harness(Down())  # type: ignore[arg-type]
    _, body = await h.call("lookup", {"q": "x"})
    assert body["result"]["isError"] is True and "10.0.0.9" not in json.dumps(body)
    assert h.performed == []


async def test_approval_required_and_tool_failure_are_opaque() -> None:
    from axis_runtime import Decision
    from axis_runtime.gate import GateDecision

    h = Harness(
        ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "needs cfo", approval_id="apr_1"))
    )
    _, body = await h.call("lookup", {"q": "x"})
    assert (
        body["result"]["isError"] is True
        and "cfo" not in json.dumps(body)
        and "apr_1" not in json.dumps(body)
    )
    h = Harness()
    _, body = await h.call("fail")
    assert body["result"]["isError"] is True and "keys" not in json.dumps(body)


async def test_result_is_truncated_with_a_marker() -> None:
    h = Harness(max_result_chars=100)
    _, body = await h.call("huge")
    assert len(body["result"]["content"][0]["text"]) == 100
    assert body["result"]["_meta"] == {"truncated": True}


async def test_argument_validation(h: Harness) -> None:
    for params in (
        {"name": "lookup", "arguments": {}},  # required missing
        {"name": "lookup", "arguments": {"q": 5}},
        {"name": "lookup", "arguments": {"q": "x", "extra": 1}},
        {"name": "lookup", "arguments": []},
        {"name": 5},
        {"arguments": {}},
        [],
    ):
        _, body = await h.rpc("tools/call", params)
        assert body["error"]["code"] == p.INVALID_PARAMS
    assert h.gate.requests == []
    _, body = await h.rpc("tools/call", {"name": "huge"})  # arguments default to {}
    assert body["result"]["isError"] is False


def test_check_arguments_subset() -> None:
    schema = {
        "properties": {"n": {"type": "integer"}, "f": {"type": "number"}, "b": {"type": "boolean"}}
    }
    assert check_arguments(schema, {"n": 1, "f": 1.5, "b": True}) is None
    assert check_arguments(schema, {"n": True}) is not None  # bool is not an integer
    assert check_arguments(schema, {"f": False}) is not None
    assert check_arguments(schema, {"n": 1.5}) is not None
    assert check_arguments({}, {"anything": 1}) is None
    assert check_arguments({"properties": {"a": {"type": "wat"}}}, {"a": 1}) is None


# ---- ids, concurrency, cancel -----------------------------------------------------------------


async def start_slow(h: Harness, rid: Any, token: str = "tok-alice") -> asyncio.Task[Any]:
    task = asyncio.create_task(h.call("slow", rid=rid, token=token))
    for _ in range(100):
        await asyncio.sleep(0)
        if h.server._inflight:
            break
    return task


async def test_duplicate_inflight_id_is_rejected_and_ids_are_type_exact(h: Harness) -> None:
    t1 = await start_slow(h, 1)
    _, dup = await h.call("lookup", {"q": "x"}, rid=1)
    assert dup["error"]["code"] == p.INVALID_REQUEST
    t2 = await start_slow(h, "1")  # "1" is a different id from 1
    assert len(h.server._inflight) == 2
    h.release.set()
    assert (await t1)[1]["result"]["isError"] is False
    assert (await t2)[1]["id"] == "1"
    assert h.server._inflight == {}


async def test_cancel_notification_cancels_only_the_callers_own_request(h: Harness) -> None:
    other = Harness()
    mine = await start_slow(h, 5)
    # a different principal cancelling the same id (even in the same tenant) has no effect
    cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 5}}
    status, _ = await h.post(cancel, token="tok-bob")
    assert status == 202 and not mine.done()
    status, _ = await h.post(cancel | {"params": {"requestId": "5"}})  # wrong id type
    assert not mine.done()
    for junk in ({"requestId": True}, {"requestId": None}, {}, []):
        await h.post(cancel | {"params": junk})
    assert not mine.done()
    await h.post(cancel)
    _, body = await mine
    assert body["error"]["code"] == p.CANCELLED and body["id"] == 5
    assert h.server._cancelled == set() and h.server._inflight == {}
    await other.post(cancel)  # cancelling something that does not exist is harmless


async def test_outer_cancellation_propagates_and_cleans_up(h: Harness) -> None:
    t = await start_slow(h, 9)
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t
    await asyncio.sleep(0)
    assert h.server._inflight == {}


async def test_inflight_cap_and_timeout() -> None:
    h = Harness(max_inflight_per_principal=2, burst=100)
    t1, t2 = await start_slow(h, 1), await start_slow(h, 2)
    status, body = await h.call("slow", rid=3)
    assert status == 429 and body["error"]["code"] == p.RATE_LIMITED
    _, other = await h.call(
        "lookup", {"q": "x"}, rid=3, token="tok-bob"
    )  # other principal unaffected
    assert other["result"]["isError"] is False
    h.release.set()
    await t1, await t2
    h = Harness(call_timeout_seconds=0.05)
    _, body = await h.call("slow")
    assert body["error"]["message"] == "request timed out" and h.server._inflight == {}


# ---- rate limit --------------------------------------------------------------------------------


async def test_rate_limit_per_principal_with_refill() -> None:
    h = Harness(rate_per_second=1.0, burst=2)
    statuses = [(await h.rpc("ping", rid=i))[0] for i in range(4)]
    assert statuses == [200, 200, 429, 429]
    _, body = await h.rpc("ping", token="tok-bob")  # other principals have their own bucket
    assert body["result"] == {}
    h.now += 2.0
    assert (await h.rpc("ping"))[0] == 200
    status, none = await h.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert status in (202, 429)


async def test_rate_limited_notifications_are_dropped_silently() -> None:
    h = Harness(rate_per_second=0.001, burst=1)
    await h.rpc("ping")
    status, body = await h.post(
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
    )
    assert status == 429 and body is None


def test_rate_limiter_unit_and_bounded_keys() -> None:
    t = [0.0]
    rl = RateLimiter(1.0, 2, lambda: t[0], max_keys=3)
    assert [rl.allow("a") for _ in range(3)] == [True, True, False]
    t[0] = 1.0
    assert rl.allow("a") is True
    for k in "bcdef":
        rl.allow(k)
    assert len(rl._buckets) == 3
    t[0] = 0.5  # clock going backwards never mints tokens
    assert rl.allow("zzz") is True


# ---- robustness --------------------------------------------------------------------------------


async def test_internal_errors_never_leak() -> None:
    h = Harness()

    async def bad_factory(principal: Principal) -> Any:
        raise RuntimeError("postgres://admin:hunter2@db/prod")

    h.server.runner_factory = bad_factory
    status, body = await h.call("lookup", {"q": "x"})
    assert body["error"]["code"] == p.INTERNAL_ERROR and "hunter2" not in json.dumps(body)

    class Boom:
        def tools_for(self, principal: Principal) -> Any:
            raise RuntimeError("/etc/shadow")

    h.server.catalog = Boom()
    status, body = await h.rpc("tools/list")
    assert (
        status == 500
        and "shadow" not in json.dumps(body)
        and body["error"]["message"] == "internal error"
    )


async def test_catalog_rejects_bad_names_and_exposes_sorted() -> None:
    cat = TenantToolCatalog()
    with pytest.raises(ValueError):
        cat.expose(TENANT, ExposedTool("a/b", "", {}, lambda a: ToolCall(name="x")))
    assert cat.tools_for(ALICE) == ()


def test_server_never_calls_perform() -> None:
    import inspect

    from axis_runtime.mcp import server

    src = inspect.getsource(server)
    assert ".perform" not in src and "_execute" not in src
