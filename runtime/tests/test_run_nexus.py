"""NEXUS in the run loop: model steps are routed, stage telemetry lands in the run log and trace."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from axis_runtime import Decision
from axis_runtime.events import replay
from axis_runtime.gate import GateDecision
from axis_runtime.models import Message, ModelTarget, ToolDefinition
from axis_runtime.nexus import (
    CacheStage,
    InMemoryCache,
    InMemoryTracer,
    LlmStage,
    NexusRouter,
    Rule,
    RulesStage,
)
from axis_runtime.nexus.cache import cache_key
from axis_runtime.nexus.types import RouteRequest
from axis_runtime.run import RunContext, RunDeps, run_agent
from conftest import (
    FakeClock,
    ScriptedGate,
    ScriptedTransport,
    allow,
    deny,
    make_deps,
    make_manifest,
)
from helpers import Effects
from test_run import final, registry, tool_turn


class Harness:
    def __init__(self, rules: list[Rule] | None = None, ttl: float = 300.0) -> None:
        self.clock = FakeClock()
        self.cache = InMemoryCache(self.clock)
        self.tracer = InMemoryTracer()
        self.rules = rules or []
        self.ttl = ttl

    def factory(self, manifest: Any) -> Any:
        def build(ctx: RunContext) -> NexusRouter:
            p = manifest.primary
            return NexusRouter(
                [
                    CacheStage(self.cache, self.clock, ttl_seconds=self.ttl),
                    RulesStage(self.rules),
                    LlmStage(ctx.runner, ModelTarget(p.provider, p.model, p.endpoint, p.params)),
                ],
                tracer=self.tracer,
                sink=ctx.nexus_event_sink(),
                clock=self.clock,
            )

        return build


def deps(h: Harness, manifest: Any, *bodies: Any, gate: Any = None, **kw: Any) -> RunDeps:
    transport = ScriptedTransport([(200, b) for b in bodies])
    d = make_deps(gate=gate, transport=transport, tools=registry(kw.pop("effects", None)), **kw)
    d.nexus_factory = h.factory(manifest)
    return d


def stages(result: Any) -> list[tuple[str, str, str]]:
    return [(s.stage, s.outcome, s.cost_usd) for s in result.state.nexus_stages]


async def test_model_step_is_routed_cache_rules_llm_and_stage_metrics_reach_log_and_trace() -> None:
    m = make_manifest()
    h = Harness()
    gate = ScriptedGate()
    d = deps(h, m, final("the answer"), gate=gate, trace_id="f" * 32)
    r = await run_agent(m, "what is the deductible?", d)
    assert (r.status, r.output) == ("completed", "the answer")
    # in the run log: one nexus_stage per attempted stage (hit/miss + cost), then the route summary
    assert [(s, o) for s, o, _ in stages(r)] == [
        ("cache", "miss"),
        ("rules", "miss"),
        ("llm", "hit"),
    ]
    llm = r.state.nexus_stages[2]
    assert llm.tokens == 15 and Decimal(llm.cost_usd) > 0
    route = r.state.nexus_routes[0]
    assert route.status == "hit" and route.hit_stage == "llm"
    assert Decimal(route.total_cost_usd) == Decimal(llm.cost_usd)
    assert set(route.cost_by_stage) == {"cache", "rules", "llm"}
    assert replay(await d.log.read(r.run_id)) == r.state
    # in the exported trace: a route span with one child per stage, carrying the same metrics
    spans = h.tracer.export()
    root = next(s for s in spans if s["name"] == "nexus.route")
    kids = [s for s in spans if s["parent_span_id"] == root["span_id"]]
    assert [k["name"] for k in kids] == [
        "nexus.stage.cache",
        "nexus.stage.rules",
        "nexus.stage.llm",
    ]
    assert [(k["attributes"]["nexus.hit"]) for k in kids] == [False, False, True]
    assert kids[2]["attributes"]["nexus.cost_usd"] == float(Decimal(llm.cost_usd))
    assert root["attributes"]["nexus.trace_id"] == "f" * 32 == gate.requests[0].trace_id
    # the model call was a gated action as before
    assert [q.enforcement_point.value for q in gate.requests] == ["model_call"]
    assert gate.requests[0].action == "openai/gpt-4o"


async def test_second_identical_run_is_a_cache_hit_with_no_gate_call_no_provider_call_and_zero_cost() -> (
    None
):
    m = make_manifest()
    h = Harness()
    gate = ScriptedGate()
    first = deps(h, m, final("cached answer"), gate=gate)
    r1 = await run_agent(m, "same question", first)
    second = deps(h, m, final("MUST NOT BE REQUESTED"), gate=gate)
    r2 = await run_agent(m, "same question", second)
    assert r2.output == "cached answer"
    assert stages(r2)[0][:2] == ("cache", "hit") and [s[0] for s in stages(r2)] == ["cache"]
    assert r2.state.nexus_routes[0].hit_stage == "cache"
    assert Decimal(r2.state.nexus_routes[0].total_cost_usd) == 0
    assert Decimal(r1.state.nexus_routes[0].total_cost_usd) > 0  # the second call is cheaper
    assert len(second.models._transport.calls) == 0  # type: ignore[attr-defined]  # noqa: SLF001
    assert r2.state.model_calls == () and r1.state.model_calls != ()
    assert len(gate.requests) == 1  # only the first run's model call was a gated action
    # trace shows the short-circuit
    names = [s["name"] for s in h.tracer.export()]
    assert names.count("nexus.stage.llm") == 1


async def test_rules_stage_answers_without_a_model_call() -> None:
    m = make_manifest()
    h = Harness(rules=[Rule("hours", "exact", "what are your hours", "9 to 5")])
    d = deps(h, m, final("MUST NOT BE REQUESTED"))
    r = await run_agent(m, "What are your  hours", d)
    assert r.output == "9 to 5"
    assert [(s, o) for s, o, _ in stages(r)] == [("cache", "miss"), ("rules", "hit")]
    assert len(d.models._transport.calls) == 0  # type: ignore[attr-defined]  # noqa: SLF001


async def test_cache_never_replays_across_different_conversations_or_tool_sets() -> None:
    m = make_manifest()
    h = Harness()
    d1 = deps(h, m, final("answer one"))
    d2 = deps(h, m, final("answer two"))
    assert (await run_agent(m, "question one", d1)).output == "answer one"
    assert (await run_agent(m, "question two", d2)).output == "answer two"
    base = RouteRequest(
        tenant_id="t", prompt="p", pid="axp_x", messages=(Message("user", "p"),),
        tools=(ToolDefinition("a"),),
    )  # fmt: skip
    import dataclasses

    other_tools = dataclasses.replace(base, tools=(ToolDefinition("b"),))
    other_args = dataclasses.replace(
        base, messages=(Message("user", "p"), Message("tool", "x", tool_call_id="1", name="t"))
    )
    assert len({cache_key(x) for x in (base, other_tools, other_args)}) == 3


async def test_a_tool_calling_turn_is_routed_gated_and_not_cached() -> None:
    m = make_manifest()
    h = Harness()
    effects = Effects()
    gate = ScriptedGate()
    d = deps(
        h, m, tool_turn(("lookup_claim", {"id": "C-1"})), final("done"), gate=gate, effects=effects
    )
    r = await run_agent(m, "status of C-1?", d)
    assert r.output == "done" and effects.calls == [("tool", {"id": "C-1"})]
    assert [q.enforcement_point.value for q in gate.requests] == [
        "model_call",
        "tool_call",
        "model_call",
    ]
    assert [s[:2] for s in stages(r)] == [("cache", "miss"), ("rules", "miss"), ("llm", "hit")] * 2
    # a response carrying tool calls is not written back; neither is the final turn's key shared
    assert h.cache.size("11111111-1111-4111-8111-111111111111") == 1


async def test_a_gate_deny_on_the_llm_stage_ends_the_run_policy_denied_with_the_stage_recorded() -> (
    None
):
    m = make_manifest()
    h = Harness()
    d = deps(h, m, final("never"), gate=ScriptedGate(deny("model egress blocked")))
    r = await run_agent(m, "hi", d)
    assert r.status == "policy_denied"
    assert "model egress blocked" in (r.state.processes[r.pid].exit_detail or "")
    assert len(d.models._transport.calls) == 0  # type: ignore[attr-defined]  # noqa: SLF001
    assert [(s, o) for s, o, _ in stages(r)] == [
        ("cache", "miss"),
        ("rules", "miss"),
        ("llm", "miss"),
    ]
    assert r.state.nexus_routes[0].status == "blocked"
    assert h.cache.size("11111111-1111-4111-8111-111111111111") == 0


async def test_an_approval_pending_model_call_parks_the_run() -> None:
    m = make_manifest()
    h = Harness()
    gate = ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="ap_9"))
    r = await run_agent(m, "hi", deps(h, m, final("never"), gate=gate))
    assert r.status == "awaiting_approval" and r.approval_id == "ap_9"


async def test_a_failed_model_call_exhausts_routing_and_fails_the_process() -> None:
    m = make_manifest()
    h = Harness()
    transport = ScriptedTransport([(400, {"error": {"type": "invalid_request_error"}})])
    d = make_deps(gate=ScriptedGate(), transport=transport, tools=registry())
    d.nexus_factory = h.factory(m)
    r = await run_agent(m, "hi", d)
    assert r.status == "failed" and "no routing stage produced an answer" in (
        r.state.processes[r.pid].exit_detail or ""
    )


async def test_phi_runs_are_never_cached() -> None:
    m = make_manifest(data={"phi": True})
    h = Harness()
    gate = ScriptedGate(
        lambda q: (
            GateDecision(
                Decision.ALLOW_WITH_REDACTION, "phi", redact_fields=("messages.0.content",)
            )
            if q.enforcement_point.value == "model_call"
            else allow()
        )
    )
    d1, d2 = deps(h, m, final("a"), gate=gate), deps(h, m, final("b"), gate=gate)
    r1 = await run_agent(m, "same", d1)
    r2 = await run_agent(m, "same", d2)
    assert [r1.status, r2.status] == ["completed", "completed"]
    assert r2.output == "b" and len(d2.models._transport.calls) == 1  # type: ignore[attr-defined]  # noqa: SLF001
    assert all(s.reason == "phi" for s in r2.state.nexus_stages if s.stage == "cache")


async def test_the_sink_appends_nothing_outside_a_routing_process() -> None:
    m = make_manifest()
    h = Harness()
    d = deps(h, m, final("x"))
    r = await run_agent(m, "hi", d)
    n = len(await d.log.read(r.run_id))
    from axis_runtime.run import NexusRunSink

    class Stub:
        processes: dict[str, Any] = {}
        recorder: Any = None

    await NexusRunSink(Stub()).emit("nexus_stage", {})  # type: ignore[arg-type]  # no acting pid: dropped
    assert len(await d.log.read(r.run_id)) == n


async def test_the_llm_stage_sends_the_agents_whole_conversation_and_its_tools() -> None:
    import json

    m = make_manifest()
    h = Harness()
    d = deps(h, m, tool_turn(("lookup_claim", {"id": "C-1"})), final("done"))
    await run_agent(m, "status of C-1?", d)
    first, second = (json.loads(c.body) for c in d.models._transport.calls)  # type: ignore[attr-defined]  # noqa: SLF001
    assert [t["function"]["name"] for t in first["tools"]] == ["lookup_claim"]
    assert [t["function"]["name"] for t in second["tools"]] == ["lookup_claim"]
    roles = [x["role"] for x in second["messages"]]
    assert roles == ["system", "user", "assistant", "tool"]  # the tool result reached the model
    assert json.loads(second["messages"][-1]["content"])["claim"] == "C-1"
