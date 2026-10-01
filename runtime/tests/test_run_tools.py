"""Run-loop wiring of memory, MCP, code and browser tools (Phase 4 / E).

Unit level: scripted gate, mock memory service, fake MCP source and fake browser backend. The real
stack (Risk Kernel over gRPC, Postgres audit, real Chromium and sandbox) is ``e2e/test_phase4_tools.py``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

import httpx
import pytest
from axis_runtime.actions import Backends, MemoryRead
from axis_runtime.browser.policy import BrowserPolicy
from axis_runtime.browser.worker import BrowserWorkerFactory, static_policies
from axis_runtime.events import EventType
from axis_runtime.gate import EnforcementPoint, GateDecision
from axis_runtime.manifest import ManifestError, MemorySpec, RuntimeManifest
from axis_runtime.mcp.errors import McpServerNotAllowed
from axis_runtime.memory import MemoryUnavailable, MemoryWiring
from axis_runtime.models import ModelTarget
from axis_runtime.models.types import ToolDefinition
from axis_runtime.nexus import InMemoryTracer, LlmStage, NexusRouter, RagStage
from axis_runtime.process import ExitReason
from axis_runtime.run import RunContext, RunDeps, run_agent
from axis_runtime.tooldefs import MEMORY_SEARCH, MEMORY_WRITE
from conftest import (
    TENANT,
    ScriptedGate,
    ScriptedTransport,
    allow,
    deny,
    make_deps,
    make_manifest,
    manifest_dict,
    openai_body,
)
from test_browser_unit import FakeBackend, resolver_for

PUBLIC = "93.184.216.34"


def turn(*calls: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    return openai_body(None, [(f"call_{i}", n, a) for i, (n, a) in enumerate(calls)])


def tool_names(call: Any) -> list[str]:
    return [t["function"]["name"] for t in json.loads(call.body).get("tools", [])]


class MemService:
    """A mock memory service over httpx (the same wire the dev server speaks)."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler
        self.transport = httpx.MockTransport(self._respond)

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._handler is not None:
            return self._handler(request)
        if request.url.path.endswith("/write"):
            return httpx.Response(200, json={"id": "m1", "deduped": False})
        return httpx.Response(
            200,
            json={
                "hits": [
                    {
                        "id": "h1",
                        "scope": "agent",
                        "kb": None,
                        "content": "fact one",
                        "score": 0.4,
                    }
                ]
            },
        )

    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests]

    def wiring(self) -> MemoryWiring:
        return MemoryWiring("http://mem", token="tok", transport=self.transport)  # noqa: S106


def mem_manifest(**memory: Any) -> RuntimeManifest:
    flags = {"run": False, "session": False, "long_term": True, "knowledge_bases": []}
    return make_manifest(memory={**flags, **memory}, tools=[])


def gate_by_point(table: Mapping[str, GateDecision]) -> ScriptedGate:
    return ScriptedGate(lambda r: table.get(r.enforcement_point.value, allow()))


# ---- manifest ---------------------------------------------------------------------------------------


def test_manifest_parses_memory_flags_and_defaults_to_all_off() -> None:
    m = make_manifest(
        memory={"run": True, "session": False, "long_term": True, "knowledge_bases": ["kb"]}
    )
    assert m.memory == MemorySpec(run=True, long_term=True, knowledge_bases=("kb",))
    assert m.memory.writable_scopes() == ("run", "long_term")
    assert m.memory.readable_scopes() == ("run", "long_term", "kb")
    raw = manifest_dict()
    del raw["memory"]
    assert RuntimeManifest.from_dict(raw).memory == MemorySpec()
    assert not MemorySpec().any


@pytest.mark.parametrize(
    "bad", ["x", {"run": "yes"}, {"knowledge_bases": "kb"}, {"knowledge_bases": [1]}]
)
def test_manifest_rejects_malformed_memory(bad: Any) -> None:
    with pytest.raises(ManifestError):
        RuntimeManifest.from_dict({**manifest_dict(), "memory": bad})


# ---- memory tools -------------------------------------------------------------------------------------


async def test_memory_tools_are_shown_gated_and_performed_with_the_run_principal() -> None:
    svc = MemService()
    gate = ScriptedGate()
    transport = ScriptedTransport(
        [
            (
                200,
                turn(
                    (MEMORY_WRITE, {"scope": "long_term", "content": "likes email"}),
                    (MEMORY_SEARCH, {"query": "contact preference"}),
                ),
            ),
            (200, openai_body("done")),
        ]
    )
    deps = make_deps(
        gate=gate,
        transport=transport,
        memory=svc.wiring(),
        principal="alice",
        principal_groups=("support",),
    )
    result = await run_agent(mem_manifest(), "go", deps)
    assert result.status == "completed"
    assert tool_names(transport.calls[0]) == [MEMORY_WRITE, MEMORY_SEARCH]
    points = [(r.enforcement_point, r.action) for r in gate.requests]
    assert points == [
        (EnforcementPoint.MODEL_CALL, "openai/gpt-4o"),
        (EnforcementPoint.MEMORY_WRITE, MEMORY_WRITE),
        (EnforcementPoint.TOOL_CALL, MEMORY_SEARCH),
        (EnforcementPoint.MODEL_CALL, "openai/gpt-4o"),
    ]
    write_ctx, read_ctx = gate.requests[1].context, gate.requests[2].context
    assert write_ctx["tool"]["kind"] == "memory:long_term"
    assert read_ctx["tool"] == {
        "name": MEMORY_SEARCH,
        "kind": "memory:read",
        "side_effects": "read",
    }
    assert "contact preference" not in json.dumps(
        read_ctx
    )  # the query text is not in the gate request
    write, search = svc.bodies()
    assert write["principal"] == {"id": "alice", "groups": ["support"]}
    assert (write["scope"], write["owner_ref"]) == ("agent", "claims-triage")
    assert write["tenant_id"] == TENANT and "acl" not in write
    assert search["scopes"] == ["agent"] and search["owner_ref"] == "claims-triage"
    log = await deps.log.read(result.run_id)
    summary = [e.data for e in log if e.data.get("name") == MEMORY_SEARCH][0]
    assert summary["result"]["hits"][0]["content_sha256"] and "fact one" not in json.dumps(summary)
    assert all(r.headers["authorization"] == "Bearer tok" for r in svc.requests)


async def test_a_denied_memory_call_never_reaches_the_service() -> None:
    svc = MemService()
    gate = gate_by_point({"memory_write": deny("no writes"), "tool_call": deny("no reads")})
    transport = ScriptedTransport(
        [
            (
                200,
                turn(
                    (MEMORY_WRITE, {"scope": "long_term", "content": "x"}),
                    (MEMORY_SEARCH, {"query": "x"}),
                ),
            ),
            (200, openai_body("done")),
        ]
    )
    result = await run_agent(
        mem_manifest(), "go", make_deps(gate=gate, transport=transport, memory=svc.wiring())
    )
    assert result.status == "completed" and svc.requests == []
    replies = [m for m in json.loads(transport.calls[1].body)["messages"] if m["role"] == "tool"]
    assert [m["content"] for m in replies] == [
        "denied by policy: no writes",
        "denied by policy: no reads",
    ]


@pytest.mark.parametrize(
    "call",
    [
        (MEMORY_WRITE, {"scope": "session", "content": "x"}),  # flag off
        (MEMORY_WRITE, {"scope": "tenant", "content": "x"}),  # never agent-writable
        (MEMORY_WRITE, {"scope": "long_term", "content": "x", "acl": {"tenant": True}}),
        (MEMORY_WRITE, {"scope": "long_term", "content": "x", "phi": False}),
        (MEMORY_SEARCH, {"query": "x", "scope": "kb"}),  # no knowledge bases
        (MEMORY_SEARCH, {"query": "x", "principal": "bob"}),
        (MEMORY_SEARCH, {"query": ""}),
        (MEMORY_SEARCH, {"query": "x", "limit": 99}),
    ],
)
async def test_invalid_memory_arguments_are_a_tool_error_with_no_gate_request(
    call: tuple[str, dict[str, Any]],
) -> None:
    svc, gate = MemService(), ScriptedGate()
    transport = ScriptedTransport([(200, turn(call)), (200, openai_body("done"))])
    await run_agent(
        mem_manifest(), "go", make_deps(gate=gate, transport=transport, memory=svc.wiring())
    )
    assert svc.requests == []
    assert [r.enforcement_point for r in gate.requests] == [EnforcementPoint.MODEL_CALL] * 2
    reply = [m for m in json.loads(transport.calls[1].body)["messages"] if m["role"] == "tool"][0]
    assert reply["content"].startswith("invalid arguments for tool")


async def test_memory_is_not_exposed_without_flags_or_without_a_service() -> None:
    for manifest, memory in (
        (
            make_manifest(
                memory={"run": False, "session": False, "long_term": False, "knowledge_bases": []},
                tools=[],
            ),
            MemService().wiring(),
        ),
        (mem_manifest(), None),
    ):
        transport = ScriptedTransport(
            [
                (200, turn((MEMORY_WRITE, {"scope": "long_term", "content": "x"}))),
                (200, openai_body("d")),
            ]
        )
        await run_agent(manifest, "go", make_deps(transport=transport, memory=memory))
        assert tool_names(transport.calls[0]) == []
        reply = [m for m in json.loads(transport.calls[1].body)["messages"] if m["role"] == "tool"][
            0
        ]
        assert reply["content"] == f"unknown tool {MEMORY_WRITE!r}"


async def test_phi_agents_flag_memory_writes_as_phi_and_run_scope_needs_an_owner() -> None:
    svc = MemService()
    m = make_manifest(
        memory={"run": True, "session": True, "long_term": False, "knowledge_bases": []},
        tools=[],
        data={"phi": True},
    )
    transport = ScriptedTransport(
        [
            (
                200,
                turn(
                    (MEMORY_WRITE, {"scope": "run", "content": "a"}),
                    (MEMORY_WRITE, {"scope": "session", "content": "b"}),
                ),
            ),
            (200, openai_body("done")),
        ]
    )
    deps = make_deps(transport=transport, memory=svc.wiring(), session_id="s-1")
    await run_agent(m, "go", deps)
    run_body, session_body = svc.bodies()
    assert run_body["phi"] is True and session_body["phi"] is True
    assert session_body["owner_ref"] == "s-1" and run_body["owner_ref"].startswith("run_")


async def test_a_manifest_tool_cannot_take_a_reserved_memory_name() -> None:
    m = make_manifest(
        memory={"run": False, "session": False, "long_term": True, "knowledge_bases": []},
        tools=[{"name": MEMORY_WRITE, "kind": "function", "side_effects": "read"}],
    )
    deps = make_deps(memory=MemService().wiring())
    result = await run_agent(m, "go", deps)
    assert result.exit_reason is ExitReason.FAILED
    assert "reserved for memory tools" in await _init_detail(deps, result.run_id)


async def test_the_rag_stage_gets_the_run_principal_and_its_passages_reach_the_model() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "hits": [
                    {
                        "id": "d1",
                        "scope": "kb",
                        "kb": "handbook",
                        "content": "Refunds take five days.",
                        "score": 0.5,
                    }
                ]
            },
        )

    svc = MemService(handler)
    transport = ScriptedTransport([(200, openai_body("five days"))])
    seen: list[RunContext] = []

    def nexus(ctx: RunContext) -> NexusRouter:
        seen.append(ctx)
        assert ctx.memory_retriever is not None
        stages: dict[str, Any] = {
            "rag": RagStage(ctx.memory_retriever, answer_threshold=2.0),
            "llm": LlmStage(ctx.runner, ModelTarget("openai", "gpt-4o")),
        }
        return NexusRouter.from_manifest(
            make_manifest(routing={"stages": ["rag", "llm"]}),
            stages,
            tracer=InMemoryTracer(),
            sink=ctx.nexus_event_sink(),
        )

    m = make_manifest(
        memory={
            "run": False,
            "session": False,
            "long_term": False,
            "knowledge_bases": ["handbook"],
        },
        routing={"stages": ["rag", "llm"]},
        tools=[],
    )
    deps = make_deps(
        transport=transport,
        memory=svc.wiring(),
        principal="alice",
        principal_groups=("g",),
        nexus_factory=nexus,
    )
    result = await run_agent(m, "how long do refunds take", deps)
    assert result.output == "five days"
    (search,) = svc.bodies()
    assert search["principal"] == {"id": "alice", "groups": ["g"]}
    assert search["kbs"] == ["handbook"] and search["scopes"] == ["kb"]
    sent = json.loads(transport.calls[0].body)["messages"]
    context = [x for x in sent if x["role"] == "system" and x["content"].startswith("Context:")]
    assert len(context) == 1 and "Refunds take five days." in context[0]["content"]
    assert sent.index(context[0]) == 1  # right after the agent's own system prompt
    assert seen[0].memory_retriever is not None
    assert seen[0].closers == []  # the retriever's client was released at the end of the run


async def test_the_default_principal_is_the_agent_and_a_service_outage_fails_the_tool_only() -> (
    None
):
    svc = MemService(lambda r: httpx.Response(503, json={}))
    gate = ScriptedGate()
    transport = ScriptedTransport(
        [(200, turn((MEMORY_SEARCH, {"query": "x"}))), (200, openai_body("done"))]
    )
    result = await run_agent(
        mem_manifest(), "go", make_deps(gate=gate, transport=transport, memory=svc.wiring())
    )
    assert result.status == "completed"
    assert svc.bodies()[0]["principal"]["id"] == "agent:claims-triage"
    reply = [m for m in json.loads(transport.calls[1].body)["messages"] if m["role"] == "tool"][0]
    assert "MemoryUnavailable" in reply["content"]


async def test_memory_backend_and_deps_are_mutually_exclusive() -> None:
    deps = make_deps(memory=MemService().wiring(), backends=Backends(memory=object()))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="mutually exclusive"):
        await run_agent(mem_manifest(), "go", deps)


# ---- the memory backend's search ---------------------------------------------------------------------


async def test_backend_search_merges_scopes_by_score_and_validates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        hit = {
            "id": body["scopes"][0],
            "scope": body["scopes"][0],
            "kb": None,
            "content": "c",
            "score": {"agent": 0.2, "kb": 0.9}[body["scopes"][0]],
        }
        return httpx.Response(200, json={"hits": [hit]})

    svc = MemService(handler)
    b = svc.wiring().backend(
        tenant_id=TENANT, principal="p", groups=(), owner_refs={"agent": "a"}, kbs=["kb1"]
    )
    out = await b.search("q", scopes=["long_term", "kb", "kb"], limit=5)
    assert [h["id"] for h in out["hits"]] == ["kb", "agent"] and len(svc.requests) == 2
    assert (await b.search("q", scopes=["long_term"], limit=0))["hits"][0][
        "id"
    ] == "agent"  # clamped to 1
    for bad_scopes in (["galaxy"],):
        with pytest.raises(ValueError, match="unknown memory scope"):
            await b.search("q", scopes=bad_scopes)
    with pytest.raises(ValueError, match="query"):
        await b.search("", scopes=["kb"])
    no_kb = svc.wiring().backend(tenant_id=TENANT, principal="p", groups=(), owner_refs={}, kbs=[])
    assert (await no_kb.search("q", scopes=["kb"]))["hits"] == []
    with pytest.raises(ValueError, match="no owner"):
        await no_kb.search("q", scopes=["long_term"])
    for payload in ({"hits": "x"}, {"hits": [{"id": 1}]}):
        bad = (
            MemService(lambda r, p=payload: httpx.Response(200, json=p))
            .wiring()
            .backend(tenant_id=TENANT, principal="p", groups=(), owner_refs={"agent": "a"}, kbs=[])
        )
        with pytest.raises(MemoryUnavailable):
            await bad.search("q", scopes=["long_term"])


def test_memory_read_validation_and_serialisation() -> None:
    a = MemoryRead(name="memory_search", scopes=["long_term", "kb"], args={"query": "q"})  # type: ignore[arg-type]
    assert a.scopes == ("long_term", "kb")
    assert a.with_args({}) is a
    assert a.gate_args()["scopes"] == ["long_term", "kb"]
    assert a.result_event("not a mapping")[1]["result"] == {"hits": []}
    for args in (
        {},
        {"query": "q", "scope": "run"},
        {"query": "q", "limit": True},
        {"query": "q" * 5000},
    ):
        with pytest.raises(ValueError):
            MemoryRead(name="m", scopes=("long_term",), args=args)
    with pytest.raises(ValueError, match="no readable memory"):
        MemoryRead(name="m", scopes=(), args={"query": "q"})


# ---- MCP: spawn-time checks and model-facing schemas ---------------------------------------------------


class FakeMcpSource:
    def __init__(self, *, allow: bool = True, offered: tuple[str, ...] = ("lookup",)) -> None:
        self.allow, self.offered = allow, offered
        self.checked = 0

    def check_manifest(self, manifest: RuntimeManifest) -> None:
        self.checked += 1
        if not self.allow:
            raise McpServerNotAllowed("MCP server is not allowed for this tenant")

    async def definitions_for(self, manifest: RuntimeManifest) -> Mapping[str, ToolDefinition]:
        return {
            t.name: ToolDefinition(t.name, "server says", {"type": "object", "required": ["q"]})
            for t in manifest.tools
            if t.kind == "mcp" and (t.ref or t.name) in self.offered
        }

    async def call_tool(self, server: str, name: str, args: Mapping[str, Any]) -> Any:
        return {"content": [{"type": "text", "text": "hi"}]}


MCP_TOOLS = [
    {
        "name": "kb-lookup",
        "kind": "mcp",
        "mcp_server": "kb",
        "ref": "lookup",
        "side_effects": "read",
    }
]


async def test_mcp_tools_are_checked_at_spawn_and_the_model_sees_the_server_schema() -> None:
    src = FakeMcpSource()
    transport = ScriptedTransport(
        [(200, turn(("kb-lookup", {"q": "x"}))), (200, openai_body("done"))]
    )
    gate = ScriptedGate()
    result = await run_agent(
        make_manifest(tools=MCP_TOOLS),
        "go",
        make_deps(gate=gate, transport=transport, backends=Backends(mcp=src)),
    )
    assert result.status == "completed" and src.checked == 1
    (tool,) = json.loads(transport.calls[0].body)["tools"]
    assert tool["function"]["description"] == "server says"
    assert tool["function"]["parameters"]["required"] == ["q"]
    assert gate.requests[1].enforcement_point is EnforcementPoint.MCP_CALL
    assert gate.requests[1].context["tool"]["name"] == "kb/lookup"


@pytest.mark.parametrize("src", [FakeMcpSource(allow=False), FakeMcpSource(offered=())])
async def test_an_invalid_mcp_manifest_fails_at_spawn_before_any_model_call(
    src: FakeMcpSource,
) -> None:
    transport = ScriptedTransport([(200, openai_body("never"))])
    gate = ScriptedGate()
    deps = make_deps(gate=gate, transport=transport, backends=Backends(mcp=src))
    result = await run_agent(make_manifest(tools=MCP_TOOLS), "go", deps)
    assert result.exit_reason is ExitReason.FAILED
    assert transport.calls == [] and gate.requests == []
    assert (await _init_detail(deps, result.run_id)).startswith("init: ")


async def _init_detail(deps: RunDeps, run_id: str) -> str:
    events = await deps.log.read(run_id)
    return str([e.data for e in events if e.type == EventType.PROCESS_TRANSITION][-1]["detail"])


# ---- code and browser: definitions, per-run worker, closing -----------------------------------------


class FakeCodeSandbox:
    async def run(self, spec: Any) -> Any:
        return {"exit_code": 0, "stdout": "1\n", "stderr": ""}


async def test_code_and_browser_tools_are_defined_for_the_model_and_the_worker_is_closed() -> None:
    backend = FakeBackend()
    factory = BrowserWorkerFactory(
        backend,
        static_policies({(TENANT, "claims-triage"): {"allowed_domains": ["example.com"]}}),
        resolver=resolver_for({"example.com": [PUBLIC]}),
    )
    tools = [
        {"name": "py", "kind": "code", "side_effects": "external"},
        {"name": "web", "kind": "browser", "side_effects": "external"},
    ]
    transport = ScriptedTransport(
        [
            (
                200,
                turn(
                    ("py", {"language": "python", "code": "print(1)"}),
                    ("web", {"operation": "navigate", "url": "https://example.com/"}),
                    ("web", {"operation": "extract", "target_url": "https://evil.example/"}),
                ),
            ),
            (200, openai_body("done")),
        ]
    )
    gate = ScriptedGate()
    deps = make_deps(
        gate=gate,
        transport=transport,
        backends=Backends(sandbox=FakeCodeSandbox()),
        browser=factory,
    )  # type: ignore[arg-type]
    result = await run_agent(make_manifest(tools=tools), "go", deps)
    assert result.status == "completed"
    defs = {
        t["function"]["name"]: t["function"] for t in json.loads(transport.calls[0].body)["tools"]
    }
    assert defs["py"]["parameters"]["properties"]["language"]["enum"] == ["python", "shell"]
    assert "allowlist" in defs["web"]["description"]
    (session,) = backend.sessions
    assert session.closed  # the run's context is destroyed when the run ends
    web = [r for r in gate.requests if r.enforcement_point is EnforcementPoint.BROWSER_EXEC]
    assert [r.context["args"]["operation"] for r in web] == ["navigate", "extract"]
    # the page an operation acts on comes from the worker: the agent's claim was dropped
    assert web[1].context["args"]["url"] == "https://example.com/"
    assert ("extract", None) in [c for c in session.calls]


async def test_browser_factory_and_backend_are_mutually_exclusive_and_a_failed_start_closes() -> (
    None
):
    factory = BrowserWorkerFactory(FakeBackend(), lambda t, a: None)
    deps = make_deps(backends=Backends(browser=object()), browser=factory)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="mutually exclusive"):
        await run_agent(make_manifest(), "go", deps)

    backend = FakeBackend()
    closed: list[bool] = []

    def boom(ctx: RunContext) -> Any:
        closed.append(ctx.browser_worker is not None)
        raise RuntimeError("nexus factory failed")

    deps = make_deps(browser=BrowserWorkerFactory(backend, lambda t, a: None), nexus_factory=boom)
    with pytest.raises(RuntimeError, match="nexus factory failed"):
        await run_agent(make_manifest(), "go", deps)
    assert closed == [True]


def test_static_policies_parse_eagerly_and_default_to_no_policy() -> None:
    provider = static_policies({("t", "a"): {"allowed_domains": ["example.com"]}})
    pol = provider("t", "a")
    assert isinstance(pol, BrowserPolicy) and pol.allowed_hosts == ("example.com",)
    assert provider("t", "other") is None and provider("other", "a") is None
    with pytest.raises(Exception, match="unknown browser config keys"):
        static_policies({("t", "a"): {"nope": 1}})


async def test_no_gate_decision_means_no_tool_runs_for_the_new_tool_kinds() -> None:
    effects: list[str] = []

    class Sandbox:
        async def run(self, spec: Any) -> Any:
            effects.append("code")

    tools = [{"name": "py", "kind": "code", "side_effects": "external"}]
    transport = ScriptedTransport(
        [(200, turn(("py", {"language": "python", "code": "x"}))), (200, openai_body("done"))]
    )
    deps = make_deps(
        gate=ScriptedGate(deny("no")), transport=transport, backends=Backends(sandbox=Sandbox())
    )  # type: ignore[arg-type]
    result = await run_agent(make_manifest(tools=tools), "go", deps)
    assert result.exit_reason is ExitReason.POLICY_DENIED  # the first model call is denied
    assert effects == []
