"""NEXUS stages: cache isolation/TTL/PHI, rules, MPM registry + slot + benchmark, RAG, LLM via gate."""

from __future__ import annotations

import random
from decimal import Decimal

import pytest
from axis_runtime.models import ModelTarget
from axis_runtime.nexus import (
    CacheStage,
    FixedModel,
    Hit,
    InMemoryCache,
    InMemoryEventSink,
    InMemoryRetriever,
    KeywordModel,
    LabeledExample,
    LlmStage,
    ManualClock,
    MicroModelRegistry,
    MpmStage,
    NexusRouter,
    Passage,
    Prediction,
    RagStage,
    Rule,
    RulesStage,
    UnsafePatternError,
    benchmark,
    cache_key,
    compile_safe,
)
from axis_runtime.nexus.types import RouteState
from conftest import FakeClock, ScriptedGate, deny
from helpers import make_executor
from nexus_helpers import T1, T2, ScriptedStage, hit, req

S = RouteState()


# ---- cache ---------------------------------------------------------------------------------------------


def make_cache(ttl: float = 60.0, **kw: object) -> tuple[CacheStage, InMemoryCache, FakeClock]:
    clock = FakeClock()
    store = InMemoryCache(clock, **kw)  # type: ignore[arg-type]
    return CacheStage(store, clock, ttl_seconds=ttl), store, clock


async def test_cache_roundtrip_through_router_and_ttl() -> None:
    cache, _, clock = make_cache(ttl=60)
    llm = ScriptedStage("llm", hit("computed", cost="0.01", tokens=50))
    router = NexusRouter([cache, llm], clock=clock)
    first = await router.route(req())
    assert first.hit_stage == "llm" and llm.calls == 1
    second = await router.route(req("  What is my   deductible? "))  # whitespace-normalised
    assert second.hit_stage == "cache" and second.answer == "computed" and llm.calls == 1
    assert second.total_cost_usd == 0 and second.stages[0].cache_key_hash
    assert len(second.stages[0].cache_key_hash or "") == 16
    clock.advance(61)
    third = await router.route(req())
    assert third.hit_stage == "llm" and llm.calls == 2  # expired


async def test_cache_never_hits_across_tenants_property() -> None:
    cache, store, _ = make_cache()
    rng = random.Random(7)
    words = ["claim", "policy", "refund", "limit", "a", "b", "claim status"]
    for _ in range(300):
        prompt = " ".join(rng.choice(words) for _ in range(rng.randint(1, 4)))
        principal = rng.choice(["u1", "u2", ""])
        writer = req(prompt, tenant_id=T1, principal=principal)
        await cache.write_back(writer, Hit(f"secret-of-{T1}"), "llm")
        reader = req(prompt, tenant_id=T2, principal=principal)
        assert (await cache.run(reader, S)).__class__.__name__ == "Miss"
        # even a direct store read of tenant 2 with tenant 1's key finds nothing
        assert await store.get(T2, cache_key(writer)) is None
        assert (await cache.run(writer, S)).__class__.__name__ == "Hit"
    assert store.size(T2) == 0
    assert cache_key(req("x", tenant_id=T1)) != cache_key(req("x", tenant_id=T2))


async def test_cache_scoped_by_principal_by_default() -> None:
    cache, _, _ = make_cache()
    await cache.write_back(req(principal="alice"), Hit("alice-only"), "rag")
    assert isinstance(
        await cache.run(req(principal="bob"), S), type(await cache.run(req(principal="bob"), S))
    )
    assert (await cache.run(req(principal="bob"), S)).__class__.__name__ == "Miss"
    assert (await cache.run(req(principal="alice"), S)).__class__.__name__ == "Hit"
    shared = CacheStage(InMemoryCache(FakeClock()), FakeClock(), scope_principal=False)
    await shared.write_back(req(principal="alice"), Hit("shared"), "llm")
    assert (await shared.run(req(principal="bob"), S)).__class__.__name__ == "Hit"


async def test_cache_skips_phi_in_both_directions() -> None:
    cache, store, _ = make_cache()
    phi = req(phi=True)
    await cache.write_back(phi, Hit("phi answer"), "llm")
    assert store.size(T1) == 0
    await cache.write_back(req(), Hit("clean"), "llm")  # same prompt, now non-PHI, is cached
    out = await cache.run(phi, S)
    assert out.__class__.__name__ == "Miss" and out.reason == "phi"  # type: ignore[union-attr]


async def test_cache_skips_uncacheable_and_tool_call_responses() -> None:
    from axis_runtime.models import ToolCallRequest

    cache, store, _ = make_cache()
    await cache.write_back(req(), Hit("x", cacheable=False), "llm")
    await cache.write_back(req(), Hit("x", tool_calls=(ToolCallRequest("1", "t", {}),)), "llm")
    assert store.size(T1) == 0


async def test_cache_lru_bound_per_tenant_and_validation() -> None:
    cache, store, _ = make_cache(max_entries_per_tenant=2)
    for i in range(3):
        await cache.write_back(req(f"p{i}"), Hit(str(i)), "llm")
    assert store.size(T1) == 2
    assert (await cache.run(req("p0"), S)).__class__.__name__ == "Miss"  # evicted
    await cache.run(req("p1"), S)  # touch p1 -> p2 becomes least recent
    await cache.write_back(req("p3"), Hit("3"), "llm")
    assert (await cache.run(req("p2"), S)).__class__.__name__ == "Miss"
    assert (await cache.run(req("p1"), S)).__class__.__name__ == "Hit"
    await cache.write_back(req("p1"), Hit("1b"), "llm")  # overwrite keeps size
    assert store.size(T1) == 2
    with pytest.raises(ValueError):
        InMemoryCache(FakeClock(), max_entries_per_tenant=0)
    with pytest.raises(ValueError):
        CacheStage(store, FakeClock(), ttl_seconds=0)
    with pytest.raises(ValueError):
        await store.get("", "k")
    with pytest.raises(ValueError):
        await store.put("", "k", None)  # type: ignore[arg-type]


async def test_cache_key_hash_in_telemetry_is_not_the_prompt() -> None:
    cache, _, _ = make_cache()
    out = await cache.run(req("very secret prompt"), S)
    assert out.cache_key_hash is not None and "secret" not in out.cache_key_hash  # type: ignore[union-attr]


# ---- rules -------------------------------------------------------------------------------------------------


async def test_rules_exact_regex_intent_and_priority() -> None:
    rules = RulesStage(
        [
            Rule("r1", "exact", "Hello   there", "hi!"),
            Rule("r2", "regex", r"^order\s+#\d+$", "order lookup"),
            Rule("r3", "intent", "billing", "billing answer"),
            Rule("r4", "regex", r"hello", "second"),
        ]
    )
    out = await rules.run(req("hello THERE"), S)
    assert isinstance(out, Hit) and out.answer == "hi!" and out.cacheable is False
    assert out.meta["rule_id"] == "r1"
    assert (await rules.run(req("Order #1234"), S)).answer == "order lookup"  # type: ignore[union-attr]
    assert (await rules.run(req("anything", intent="billing"), S)).answer == "billing answer"  # type: ignore[union-attr]
    assert (await rules.run(req("anything", intent="other"), S)).__class__.__name__ == "Miss"
    assert (await rules.run(req("anything"), S)).__class__.__name__ == "Miss"
    assert (await rules.run(req("say hello"), S)).answer == "second"  # type: ignore[union-attr]


async def test_rules_are_tenant_scoped() -> None:
    rules = RulesStage(
        [Rule("t1", "exact", "secret", "t1 only", tenant_id=T1), Rule("g", "exact", "ping", "pong")]
    )
    assert (await rules.run(req("secret", tenant_id=T1), S)).__class__.__name__ == "Hit"
    assert (await rules.run(req("secret", tenant_id=T2), S)).__class__.__name__ == "Miss"
    assert (await rules.run(req("ping", tenant_id=T2), S)).__class__.__name__ == "Hit"


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"(a*)*b",
        r"(\w+)*x",
        r"(a|b)\1",
        r"(?=x)y",
        r"(?!x)y",
        r"(?<=x)y",
        "x" * 300,
        "(unclosed",
    ],
)
def test_unsafe_patterns_rejected(pattern: str) -> None:
    with pytest.raises(UnsafePatternError):
        compile_safe(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a|aa)+$",  # overlapping alternation under a quantifier: exponential, no inner quantifier
        r"^(\w|\d)+$",
        r"(a|a)*b",
        r"(?:a|aa)+c",
        r"(ab)+(ab)+(ab)+x",
        r"(a?){30}a{30}",
        r"a*a*a*b",  # polynomial: three adjacent unbounded repeats
        r".*.*.*x",
        r"\d+\s*\d+\s*\d+;",
        r"a?" * 12 + "a" * 12,  # 2^12 optional atoms
        r"a*+a*+a*+b",
    ],
)
def test_review_redos_shapes_the_denylist_missed_are_rejected(pattern: str) -> None:
    with pytest.raises(UnsafePatternError):
        compile_safe(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^order\s+#\d+$",
        r"needle",
        r"^(?i:hello|hi)\s+there[!.]?$",
        r"\bfoo\b.*bar",
        r"[a-z]+@x\.io",
        r"[]a]+x",
        r"[^]x\]]+y",
        r"a+?b",
        r"x{3}y",
        r"a{,5}b",
        r"\d{1,3}\.",
        r"a{b",
        r"(?:ab)?c",
        r"a|b|c",
    ],
)
def test_review_ordinary_rule_patterns_still_compile(pattern: str) -> None:
    compile_safe(pattern)


async def test_review_a_hostile_regex_cannot_stall_the_event_loop() -> None:
    import time

    start = time.monotonic()
    for pattern in (r"a*a*a*a*a*b", r"(a|aa)+$"):
        try:
            RulesStage([Rule("r", "regex", pattern, "x")])
        except UnsafePatternError:
            continue
        await RulesStage([Rule("r", "regex", pattern, "x")]).run(req("a" * 40 + "!"), S)
    assert time.monotonic() - start < 2.0


async def test_rules_bound_regex_input_and_validate_config() -> None:
    rules = RulesStage([Rule("r", "regex", r"needle", "found")])
    assert (await rules.run(req("x" * 5000 + " needle"), S)).__class__.__name__ == "Miss"
    with pytest.raises(ValueError, match="duplicate"):
        RulesStage([Rule("a", "exact", "x", "y"), Rule("a", "exact", "z", "y")])
    with pytest.raises(ValueError, match="kind"):
        RulesStage([Rule("a", "glob", "x", "y")])  # type: ignore[arg-type]
    with pytest.raises(UnsafePatternError):
        RulesStage([Rule("a", "regex", r"(a+)+", "y")])


async def test_rules_hits_are_not_cached_by_the_router() -> None:
    cache, store, clock = make_cache()
    router = NexusRouter([cache, RulesStage([Rule("r", "exact", "ping", "pong")])], clock=clock)
    assert (await router.route(req("ping"))).hit_stage == "rules"
    assert store.size(T1) == 0


# ---- MPM -------------------------------------------------------------------------------------------------


def test_registry_register_get_list_tenant_scoped() -> None:
    reg = MicroModelRegistry()
    plat = FixedModel("plat", "classify", "x", 0.9)
    mine = FixedModel("mine", "classify", "y", 0.9)
    other = FixedModel("theirs", "classify", "z", 0.9)
    reg.register(plat)
    reg.register(mine, tenant_id=T1)
    reg.register(other, tenant_id=T2)
    assert [m.id for m in reg.list(T1, "classify")] == ["mine", "plat"]
    assert [m.id for m in reg.list(T2)] == ["plat", "theirs"]
    assert reg.get(T1, "theirs") is None and reg.get(T1, "mine") is mine
    assert reg.list(T1, "summarise") == []
    with pytest.raises(ValueError, match="already"):
        reg.register(FixedModel("mine", "classify", "q", 0.1), tenant_id=T1)
    shadow = FixedModel("plat", "classify", "tenant version", 0.9)
    reg.register(shadow, tenant_id=T1)  # tenant model shadows the platform one
    assert reg.get(T1, "plat") is shadow and reg.get(T2, "plat") is plat
    assert reg.unregister("plat", tenant_id=T1) and not reg.unregister("plat", tenant_id=T1)
    with pytest.raises(ValueError, match="tenant_id"):
        reg.list("")
    with pytest.raises(ValueError, match="capability"):
        reg.register(
            type("M", (), {"id": "m", "capabilities": frozenset()})()  # type: ignore[arg-type]
        )


async def test_mpm_threshold_and_fallthrough() -> None:
    reg = MicroModelRegistry()
    reg.register(FixedModel("a", "triage", "low", 0.5, cost_per_call=Decimal("0.001")))
    reg.register(FixedModel("b", "triage", "mid", 0.7, cost_per_call=Decimal("0.002")))
    stage = MpmStage(reg, threshold=0.8)
    out = await stage.run(req(capability="triage"), S)
    assert out.__class__.__name__ == "Miss" and out.reason == "below_threshold"  # type: ignore[union-attr]
    assert out.cost == Decimal("0.003")
    reg.register(FixedModel("c", "triage", "high", 0.95, cost_per_call=Decimal("0.004")))
    out = await stage.run(req(capability="triage"), S)
    assert isinstance(out, Hit) and out.answer == "high" and out.meta["model_id"] == "c"
    assert out.cost == Decimal("0.007")  # every model consulted is paid for
    # exactly at the threshold counts as a hit
    edge = MicroModelRegistry()
    edge.register(FixedModel("e", "k", "ok", 0.8))
    assert isinstance(await MpmStage(edge, threshold=0.8).run(req(capability="k"), S), Hit)


async def test_mpm_no_capability_no_model_abstain_and_broken_model() -> None:
    reg = MicroModelRegistry()
    stage = MpmStage(reg)
    assert (await stage.run(req(), S)).reason == "no_capability"  # type: ignore[union-attr]
    assert (await stage.run(req(capability="x"), S)).reason == "no_model"  # type: ignore[union-attr]
    reg.register(KeywordModel("kw", "x", {"l": ["alpha"]}))

    class Broken:
        id = "broken"
        capabilities = frozenset({"x"})

        async def predict(self, tenant_id: str, prompt: str) -> Prediction:
            raise RuntimeError("model crashed")

    reg.register(Broken())
    out = await stage.run(req("nothing relevant", capability="x"), S)
    assert out.reason == "abstained"  # type: ignore[union-attr]
    out = await stage.run(req("alpha", capability="x"), S)
    assert isinstance(out, Hit) and out.answer == "l"
    with pytest.raises(ValueError):
        MpmStage(reg, threshold=1.5)


async def test_mpm_models_of_other_tenants_are_invisible_to_the_slot() -> None:
    reg = MicroModelRegistry()
    reg.register(FixedModel("t2-only", "k", "leak", 1.0), tenant_id=T2)
    out = await MpmStage(reg).run(req(capability="k", tenant_id=T1), S)
    assert out.reason == "no_model"  # type: ignore[union-attr]


def _kw_model(clock: ManualClock | None = None, latency: float = 0.0) -> KeywordModel:
    return KeywordModel(
        "kw",
        "triage",
        {"fraud": ["stolen", "fraud", "scam"], "billing": ["invoice", "charge", "refund"]},
        cost_per_call=Decimal("0.0005"),
        latency_s=latency,
        clock=clock,
    )


async def test_keyword_model_is_deterministic() -> None:
    m = _kw_model()
    a = await m.predict(T1, "refund the invoice for the scam")
    b = await m.predict(T1, "refund the invoice for the scam")
    assert (
        a == b and a is not None and a.answer == "billing" and a.confidence == pytest.approx(2 / 3)
    )
    assert await m.predict(T1, "hello") is None


async def test_benchmark_is_computed_not_hard_coded() -> None:
    data = [
        LabeledExample(T1, "my card was stolen", "fraud"),
        LabeledExample(T1, "refund this charge", "billing"),
        LabeledExample(T1, "scam and refund", "fraud"),  # tie -> alphabetical "fraud"? see model
        LabeledExample(T1, "hello world", "billing"),  # model abstains -> wrong
    ]
    clock = ManualClock()
    rep = await benchmark(_kw_model(clock, 0.010), data, clock, threshold=0.8)
    assert (
        rep.n == 4
        and rep.mean_latency_ms == pytest.approx(10.0)
        and rep.p95_latency_ms == pytest.approx(10.0)
    )
    assert rep.total_cost == Decimal("0.0015") and rep.mean_cost == Decimal("0.000375")
    # recompute independently from the model itself
    right = 0
    for ex in data:
        p = await _kw_model().predict(ex.tenant_id, ex.prompt)
        right += bool(p and p.answer == ex.expected)
    assert rep.correct == right and rep.accuracy == right / 4
    assert rep.answered == 2 and rep.coverage == 0.5  # only the two single-label prompts reach 0.8
    assert rep.selective_accuracy == 1.0
    # a slower model changes the measured latency; a worse dataset changes accuracy
    clock2 = ManualClock()
    slow = await benchmark(_kw_model(clock2, 0.050), data, clock2)
    assert slow.mean_latency_ms == pytest.approx(50.0) and slow.accuracy == rep.accuracy
    flipped = [LabeledExample(e.tenant_id, e.prompt, "none") for e in data]
    clock3 = ManualClock()
    assert (await benchmark(_kw_model(), flipped, clock3)).accuracy == 0.0
    with pytest.raises(ValueError):
        await benchmark(_kw_model(), [], clock)


async def test_benchmark_handles_crashing_model_and_no_answers() -> None:
    class Crash:
        id = "crash"
        capabilities = frozenset({"c"})

        async def predict(self, tenant_id: str, prompt: str) -> Prediction:
            raise RuntimeError

    rep = await benchmark(Crash(), [LabeledExample(T1, "a", "b")], ManualClock())
    assert rep.accuracy == 0.0 and rep.selective_accuracy == 0.0 and rep.answered == 0


# ---- RAG ---------------------------------------------------------------------------------------------------


def _retriever() -> InMemoryRetriever:
    return InMemoryRetriever(
        [
            Passage("a", T1, "the deductible is five hundred dollars"),
            Passage(
                "b",
                T1,
                "restricted payroll data for managers",
                allowed_principals=frozenset({"boss"}),
            ),
            Passage("c", T2, "the deductible is nine hundred dollars"),
        ]
    )


async def test_retriever_enforces_tenant_and_acl() -> None:
    r = _retriever()
    got = await r.retrieve(tenant_id=T1, principal="user-1", query="deductible payroll", limit=5)
    assert [p.id for p in got] == ["a"]  # not b (ACL), not c (other tenant)
    got = await r.retrieve(tenant_id=T1, principal="boss", query="payroll", limit=5)
    assert [p.id for p in got] == ["b"]
    assert await r.retrieve(tenant_id=T1, principal="x", query="", limit=5) == []
    with pytest.raises(ValueError):
        await r.retrieve(tenant_id="", principal="x", query="q", limit=1)
    r.add(Passage("d", T1, "deductible info extra words"))
    ids = [p.id for p in await r.retrieve(tenant_id=T1, principal="u", query="deductible", limit=1)]
    assert ids == ["a"]  # score tie broken by id, limit honoured


async def test_rag_answers_context_or_misses() -> None:
    stage = RagStage(_retriever(), answer_threshold=0.9)
    out = await stage.run(req("deductible five hundred dollars"), S)
    assert isinstance(out, Hit) and "five hundred" in out.answer and out.confidence >= 0.9
    out = await stage.run(req("deductible amount please"), S)
    assert out.__class__.__name__ == "Miss" and out.reason == "low_score" and len(out.context) == 1  # type: ignore[union-attr]
    out = await stage.run(req("completely unrelated zebra"), S)
    assert out.reason == "no_passages"  # type: ignore[union-attr]
    with pytest.raises(ValueError):
        RagStage(_retriever(), limit=0)


async def test_rag_rechecks_a_misbehaving_retriever() -> None:
    class Leaky:
        calls: list[dict[str, object]] = []

        async def retrieve(
            self, *, tenant_id: str, principal: str, query: str, limit: int
        ) -> list[Passage]:
            self.calls.append({"tenant_id": tenant_id, "principal": principal})
            return [
                Passage("x", T2, "other tenant", 1.0),
                Passage("y", T1, "acl'd", 1.0, frozenset({"boss"})),
            ]

    leaky = Leaky()
    out = await RagStage(leaky).run(req("q"), S)
    assert out.reason == "no_passages"  # type: ignore[union-attr]
    assert leaky.calls == [{"tenant_id": T1, "principal": "user-1"}]


async def test_rag_passages_reach_llm_prompt_through_executor() -> None:
    ex, _, effects, _ = await make_executor()
    llm = LlmStage(ex, ModelTarget("openai", "gpt-4o"))
    router = NexusRouter([RagStage(_retriever(), answer_threshold=0.99), llm])
    res = await router.route(req("deductible amount please"))
    assert res.hit_stage == "llm"
    sent = effects.transport.calls[0].body
    assert "five hundred dollars" in str(sent) and "nine hundred" not in str(sent)


# ---- LLM stage: always through the executor / Risk Kernel ---------------------------------------------------


async def test_llm_stage_goes_through_the_gate_and_gateway() -> None:
    ex, rec, effects, gate = await make_executor()
    sink = InMemoryEventSink()
    router = NexusRouter(
        [LlmStage(ex, ModelTarget("openai", "gpt-4o"), system_prompt="Be brief.")],
        sink=sink,
    )
    res = await router.route(req("hi"))
    assert res.status == "hit" and res.answer == "model says hi" and res.hit_stage == "llm"
    assert len(gate.requests) == 1 and gate.requests[0].enforcement_point.value == "model_call"
    assert len(effects.transport.calls) == 1
    assert res.total_tokens == 15 and res.stages[0].cost_usd >= 0
    assert [e.type for e in await rec.log.read("run_1")][-2:] == ["gate_decision", "model_call"]
    assert "Be brief." in str(effects.transport.calls[0].body)


async def test_llm_stage_deny_is_terminal_and_calls_no_provider() -> None:
    ex, _, effects, _ = await make_executor(ScriptedGate(deny("policy")))
    router = NexusRouter([LlmStage(ex, ModelTarget("openai", "gpt-4o"))])
    res = await router.route(req())
    assert res.status == "blocked" and res.blocked_reason == "denied:policy" and res.answer is None
    assert effects.total() == 0


async def test_gate_error_at_llm_stage_fails_closed() -> None:
    class Down:
        async def evaluate(self, request: object) -> object:
            raise ConnectionError("kernel down")

    ex, _, effects, _ = await make_executor(Down())
    res = await NexusRouter([LlmStage(ex, ModelTarget("openai", "gpt-4o"))]).route(req())
    assert res.status == "blocked" and effects.total() == 0


async def test_llm_stage_pending_approval_failure_and_unexpected_result() -> None:
    from axis_runtime import Decision
    from axis_runtime.gate import GateDecision

    pend = GateDecision(Decision.REQUIRE_APPROVAL, "needs human", approval_id="apr_1")
    ex, _, effects, _ = await make_executor(ScriptedGate(pend))
    res = await NexusRouter([LlmStage(ex, ModelTarget("openai", "gpt-4o"))]).route(req())
    assert res.status == "blocked" and res.blocked_reason == "approval_pending:apr_1"
    assert effects.total() == 0

    redact = GateDecision(Decision.ALLOW_WITH_REDACTION, "r", redact_fields=("result.text",))
    ex2, _, _, _ = await make_executor(ScriptedGate(redact))
    res = await NexusRouter([LlmStage(ex2, ModelTarget("openai", "gpt-4o"))]).route(req())
    assert res.status == "hit" and res.answer != "model says hi"  # redacted by the gate decision


async def test_llm_provider_failure_is_a_miss() -> None:
    from conftest import ScriptedTransport
    from helpers import Effects

    effects = Effects(transport=ScriptedTransport([(401, {"error": "bad key"})]))
    ex, _, _, _ = await make_executor(effects=effects)
    res = await NexusRouter([LlmStage(ex, ModelTarget("openai", "gpt-4o"))]).route(req())
    assert res.status == "exhausted" and res.stages[0].reason == "model_failed"


async def test_full_pipeline_cache_fills_then_serves() -> None:
    ex, _, effects, gate = await make_executor()
    cache, store, clock = make_cache()
    reg = MicroModelRegistry()
    stages = {
        "cache": cache,
        "rules": RulesStage([Rule("r", "exact", "ping", "pong")]),
        "mpm": MpmStage(reg),
        "rag": RagStage(InMemoryRetriever()),
        "llm": LlmStage(ex, ModelTarget("openai", "gpt-4o")),
    }
    router = NexusRouter(list(stages.values()), clock=clock)
    r1 = await router.route(req("novel question"))
    r2 = await router.route(req("novel question"))
    assert (r1.hit_stage, r2.hit_stage) == ("llm", "cache")
    assert len(gate.requests) == 1 and len(effects.transport.calls) == 1
    assert [s.stage for s in r1.stages] == ["cache", "rules", "mpm", "rag", "llm"]
    phi = await router.route(req("novel question", phi=True))
    assert phi.hit_stage == "llm" and len(gate.requests) == 2  # PHI bypasses the cache


async def test_llm_stage_non_response_result_is_a_miss() -> None:
    from axis_runtime.executor import Completed
    from conftest import allow

    class Odd:
        async def run(self, action: object, *, pid: str) -> Completed:
            return Completed({"redacted": "dict"}, allow())

    res = await NexusRouter([LlmStage(Odd(), ModelTarget("openai", "gpt-4o"))]).route(req())  # type: ignore[arg-type]
    assert res.status == "exhausted" and res.stages[0].reason == "unexpected_result"


def test_hash_text_is_short_and_stable() -> None:
    from axis_runtime.nexus.types import hash_text

    assert (
        hash_text("x") == hash_text("x") and len(hash_text("x")) == 16 and "x" not in hash_text("x")
    )
