"""NEXUS router: ordering, short-circuit, failure handling, telemetry, cost attribution, manifest."""

from __future__ import annotations

import asyncio
import random
from decimal import Decimal

import pytest
from axis_runtime.manifest import ManifestError
from axis_runtime.nexus import (
    Hit,
    InMemoryEventSink,
    InMemoryTracer,
    Miss,
    NexusConfigError,
    NexusRouter,
    RouteState,
)
from axis_runtime.nexus.types import RouteRequest
from conftest import FakeClock, make_manifest, manifest_dict
from nexus_helpers import ScriptedStage, hit, req

CANON = ["cache", "rules", "mpm", "rag", "llm"]


def pipeline(
    outcomes: dict[str, object], log: list[str], names: list[str] | None = None
) -> list[ScriptedStage]:
    return [ScriptedStage(n, outcomes.get(n), log) for n in (names or CANON)]  # type: ignore[arg-type]


async def test_first_hit_short_circuits() -> None:
    log: list[str] = []
    stages = pipeline({"rules": hit("from rules"), "llm": hit("from llm")}, log)
    res = await NexusRouter(stages).route(req())
    assert res.status == "hit" and res.answer == "from rules" and res.hit_stage == "rules"
    assert log == ["cache", "rules"]
    assert [s.outcome for s in res.stages] == ["miss", "hit"]


async def test_all_miss_is_exhausted_not_fabricated() -> None:
    res = await NexusRouter(pipeline({}, [])).route(req())
    assert res.status == "exhausted" and res.answer is None and res.hit_stage is None
    assert len(res.stages) == 5


async def test_fallthrough_ordering_property() -> None:
    """For random subsets/orders of stages and random hit positions the router visits stages in
    declaration order and stops at the first hit; stages after it are never run."""
    rng = random.Random(20260930)
    for _ in range(200):
        names = [n for n in ["cache", "rules", "mpm", "rag"] if rng.random() < 0.7]
        rng.shuffle(names)
        names.append("llm")
        hit_at = rng.choice([None, *range(len(names))])
        log: list[str] = []
        stages = [
            ScriptedStage(n, hit(f"a-{n}") if i == hit_at else Miss("m"), log)
            for i, n in enumerate(names)
        ]
        res = await NexusRouter(stages).route(req())
        if hit_at is None:
            assert log == names and res.status == "exhausted"
        else:
            assert log == names[: hit_at + 1]
            assert res.hit_stage == names[hit_at] and res.answer == f"a-{names[hit_at]}"


async def test_stage_exception_is_a_miss_and_falls_through() -> None:
    def boom(r: RouteRequest, s: RouteState) -> Hit:
        raise RuntimeError("secret prompt text: What is my deductible?")

    log: list[str] = []
    stages = pipeline({"rules": boom, "llm": hit("llm answer")}, log)
    sink, tracer = InMemoryEventSink(), InMemoryTracer()
    res = await NexusRouter(stages, sink=sink, tracer=tracer).route(req())
    assert res.status == "hit" and res.hit_stage == "llm" and log == CANON[:2] + CANON[2:]
    rules_rec = next(s for s in res.stages if s.stage == "rules")
    assert rules_rec.outcome == "miss" and rules_rec.reason == "error:RuntimeError"
    # the exception message (which may contain user data) is nowhere in telemetry
    assert "deductible" not in repr(sink.events) and "deductible" not in repr(tracer.spans)
    span = tracer.named("nexus.stage.rules")[0]
    assert span.ok is False


async def test_stage_timeout_is_a_miss_but_llm_is_not_timed_out_by_router() -> None:
    class Slow:
        name = "rules"

        async def run(self, request: RouteRequest, state: RouteState) -> Hit:
            await asyncio.sleep(1)
            return hit("late")

    log: list[str] = []
    res = await NexusRouter(
        [Slow(), ScriptedStage("llm", hit("llm"), log)], stage_timeout_s=0.01
    ).route(req())
    assert res.hit_stage == "llm" and res.stages[0].reason == "timeout"


async def test_malformed_outcomes_are_misses() -> None:
    class Weird:
        name = "rules"

        async def run(self, request: RouteRequest, state: RouteState) -> Hit:
            return "not an outcome"  # type: ignore[return-value]

    stages = [
        Weird(),
        ScriptedStage("mpm", Hit("x", confidence=2.0)),
        ScriptedStage("rag", Hit("x", tokens=-1)),
        ScriptedStage("llm", hit("ok")),
    ]
    res = await NexusRouter(stages).route(req())
    assert [s.reason for s in res.stages[:3]] == [
        "invalid_outcome",
        "invalid_hit:confidence_out_of_range",
        "invalid_hit:negative_cost_or_tokens",
    ]
    assert res.answer == "ok"


async def test_cancellation_is_not_swallowed() -> None:
    class Cancelled:
        name = "rules"

        async def run(self, request: RouteRequest, state: RouteState) -> Hit:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await NexusRouter([Cancelled()]).route(req())


async def test_blocked_miss_is_terminal() -> None:
    log: list[str] = []
    stages = [
        ScriptedStage("rules", Miss("denied:policy", blocked=True), log),
        ScriptedStage("llm", hit("never"), log),
    ]
    res = await NexusRouter(stages).route(req())
    assert res.status == "blocked" and res.blocked_reason == "denied:policy" and log == ["rules"]


async def test_telemetry_spans_events_and_cost_attribution() -> None:
    clock = FakeClock()

    def slow_miss(r: RouteRequest, s: RouteState) -> Miss:
        clock.mono += 0.25
        return Miss("below_threshold", cost=Decimal("0.0001"), tokens=7, cache_key_hash="abc")

    stages = [
        ScriptedStage("mpm", slow_miss),
        ScriptedStage("llm", hit("answer text", cost="0.0123", tokens=100)),
    ]
    tracer, sink = InMemoryTracer(), InMemoryEventSink()
    res = await NexusRouter(stages, tracer=tracer, sink=sink, clock=clock).route(
        req("secret prompt body")
    )
    assert res.total_cost_usd == Decimal("0.0124") and res.total_tokens == 107
    assert res.cost_by_stage == {"mpm": Decimal("0.0001"), "llm": Decimal("0.0123")}
    assert res.stages[0].latency_ms == pytest.approx(250.0)

    root = tracer.named("nexus.route")[0]
    assert root.attributes["nexus.status"] == "hit" and root.attributes["nexus.hit_stage"] == "llm"
    s_mpm, s_llm = tracer.named("nexus.stage.mpm")[0], tracer.named("nexus.stage.llm")[0]
    assert s_mpm.parent is root and s_mpm.ended and s_llm.ended
    assert s_mpm.attributes["nexus.hit"] is False and s_llm.attributes["nexus.hit"] is True
    assert s_mpm.attributes["nexus.latency_ms"] == pytest.approx(250.0)
    assert s_mpm.attributes["nexus.tokens"] == 7 and s_llm.attributes["nexus.tokens"] == 100
    assert s_llm.attributes["nexus.cost_usd"] == pytest.approx(0.0123)
    assert s_mpm.attributes["nexus.cache_key_hash"] == "abc"

    stage_events = sink.of_type("nexus_stage")
    assert [e["stage"] for e in stage_events] == ["mpm", "llm"]
    assert stage_events[1]["cost_usd"] == "0.0123" and stage_events[0]["outcome"] == "miss"
    route_event = sink.of_type("nexus_route")[0]
    assert route_event["cost_by_stage"] == {"mpm": "0.0001", "llm": "0.0123"}
    for blob in (repr(sink.events), repr(tracer.spans)):
        assert "secret prompt body" not in blob and "answer text" not in blob


async def test_failing_sink_never_breaks_routing() -> None:
    class BadSink:
        async def emit(self, event_type: str, data: object) -> None:
            raise OSError("disk full")

    res = await NexusRouter([ScriptedStage("llm", hit("fine"))], sink=BadSink()).route(req())
    assert res.status == "hit" and res.sink_errors == 2  # one stage event + one route event


async def test_write_back_only_reaches_stages_before_the_hit() -> None:
    seen: list[tuple[str, str]] = []

    class Learner(ScriptedStage):
        async def write_back(self, request: RouteRequest, h: Hit, source: str) -> None:
            seen.append((self.name, source))

    class Broken(ScriptedStage):
        async def write_back(self, request: RouteRequest, h: Hit, source: str) -> None:
            raise RuntimeError("store down")

    sink = InMemoryEventSink()
    stages = [Learner("cache"), Broken("rules"), ScriptedStage("mpm", hit("x")), Learner("llm")]
    res = await NexusRouter(stages[:3], sink=sink).route(req())
    assert seen == [("cache", "mpm")] and res.sink_errors == 1
    assert any(e.get("outcome") == "write_back_error" for e in sink.of_type("nexus_stage"))


async def test_miss_context_flows_to_later_stages() -> None:
    from axis_runtime.nexus import Passage

    got: list[int] = []

    def llm(r: RouteRequest, s: RouteState) -> Hit:
        got.append(len(s.retrieved))
        return hit("ok")

    p = Passage("p1", "t", "text")
    await NexusRouter(
        [ScriptedStage("rag", Miss("low", context=(p,))), ScriptedStage("llm", llm)]
    ).route(req())
    assert got == [1]


# ---- configuration -----------------------------------------------------------------------------------


def test_config_errors() -> None:
    with pytest.raises(NexusConfigError, match="duplicate"):
        NexusRouter([ScriptedStage("cache"), ScriptedStage("cache")])
    with pytest.raises(NexusConfigError, match="unknown"):
        NexusRouter([ScriptedStage("bogus")])
    with pytest.raises(NexusConfigError, match="last"):
        NexusRouter([ScriptedStage("llm"), ScriptedStage("cache")])


async def test_from_manifest_honours_declared_order() -> None:
    m = make_manifest(routing={"stages": ["rules", "cache", "llm"]})
    assert m.routing_stages == ("rules", "cache", "llm")
    log: list[str] = []
    avail = {n: ScriptedStage(n, None, log) for n in CANON}
    router = NexusRouter.from_manifest(m, avail)
    assert router.stage_names == ("rules", "cache", "llm")
    await router.route(req())
    assert log == ["rules", "cache", "llm"]  # mpm / rag declared nowhere: never run


def test_from_manifest_missing_implementation_fails_closed() -> None:
    m = make_manifest(routing={"stages": ["cache", "rag", "llm"]})
    with pytest.raises(NexusConfigError, match="rag"):
        NexusRouter.from_manifest(m, {"cache": ScriptedStage("cache"), "llm": ScriptedStage("llm")})


def test_manifest_routing_parsing() -> None:
    raw = manifest_dict()
    del raw["routing"]
    from axis_runtime.manifest import RuntimeManifest

    assert RuntimeManifest.from_dict(raw).routing_stages == ("llm",)
    raw["routing"] = {}
    assert RuntimeManifest.from_dict(raw).routing_stages == ("llm",)
    raw["routing"] = None
    assert RuntimeManifest.from_dict(raw).routing_stages == ("llm",)
    for bad in (
        "x",
        {"stages": "cache"},
        {"stages": ["nope"]},
        {"stages": ["llm", "llm"]},
        {"stages": [1]},
    ):
        raw["routing"] = bad
        with pytest.raises(ManifestError):
            RuntimeManifest.from_dict(raw)
