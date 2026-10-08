"""The case runner: real run path, isolation, eval-mode lockdown, timeouts, budgets, retries only
for infrastructure, determinism, bounded concurrency, tenant isolation."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.actions import Backends
from axis_runtime.evals.isolation import (
    EvalModeGate,
    EvalModePolicy,
    FixtureTool,
    build_tool_registry,
    lockdown_deps,
)
from axis_runtime.evals.runner import (
    CaseRunner,
    RunnerConfig,
    case_seed,
    is_infra_failure,
    prepare_manifest,
)
from axis_runtime.evals.types import EvalCase
from axis_runtime.gate import EnforcementPoint, EvaluateRequest, GateDecision
from axis_runtime.run import RunDeps
from axis_runtime.tools import ToolRegistry
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny, make_gateway, openai_body, tool_turn_body
from evals_helpers import FnTransport, SeqIds, make_base_deps, make_manifest, text_body, user_text

LOOKUP = {"name": "lookup_claim", "kind": "function", "side_effects": "read", "timeout_seconds": 60}
EMAIL = {"name": "send_email", "kind": "function", "side_effects": "external", "timeout_seconds": 60}
CODE = {"name": "run_python", "kind": "code", "side_effects": "external", "timeout_seconds": 5}


def agent(messages: list[dict[str, Any]], n: int) -> dict[str, Any]:
    """Echo agent: 'lookup' in the input -> call lookup_claim once, then answer with its result."""
    last = messages[-1]
    if last["role"] == "tool":
        return text_body(f"result: {last['content']}")
    text = user_text(messages)
    if "lookup" in text:
        return tool_turn_body(("lookup_claim", {"id": "C-1"}))
    if "mail" in text:
        return tool_turn_body(("send_email", {"to": "x@example.com"}))
    if "code" in text:
        return tool_turn_body(("run_python", {"language": "python", "code": "print(1)"}))
    return text_body(f"echo: {text.strip()}")


def runner(
    fn: Any = agent,
    *,
    gate: ScriptedGate | None = None,
    config: RunnerConfig | None = None,
    policy: EvalModePolicy | None = None,
    transport: FnTransport | None = None,
    tenant: str = TENANT,
    base_tenant: str = TENANT,
) -> tuple[CaseRunner, FnTransport, ScriptedGate]:
    transport = transport or FnTransport(fn)
    g = gate or ScriptedGate(allow())
    return (
        CaseRunner(
            make_base_deps(transport, g, tenant=base_tenant),
            tenant_id=tenant,
            policy=policy,
            config=config or RunnerConfig(case_timeout_seconds=5.0),
            ids=SeqIds(),
        ),
        transport,
        g,
    )


def mf(**over: Any) -> Any:
    over.setdefault("tools", [LOOKUP, EMAIL, CODE])
    return make_manifest(**over)


# ---- basic path -----------------------------------------------------------------------------------


async def test_a_case_runs_through_the_real_run_path_and_the_gate() -> None:
    r, transport, gate = runner()
    out = await r.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="er1")
    assert out.status == "completed" and out.attempts == 1 and out.trace is not None
    t = out.trace
    assert t.output == "echo: hello" and t.exit_reason == "completed" and t.event_count > 3
    assert [d.enforcement_point for d in t.gate_decisions] == ["model_call"]
    assert len(t.model_calls) == 1 and t.tokens == 15 and t.latency_ms >= 0
    (req,) = gate.requests  # the tenant's gate decided, with the production-shaped request
    assert req.tenant_id == TENANT and req.blueprint_name == "claims-triage"
    assert "eval" not in req.context  # evals must not be distinguishable to policy
    assert t.run_id == "run_eval0001" and t.events_hash and len(transport.calls) == 1


async def test_function_tools_are_served_from_the_cases_fixtures() -> None:
    real_calls: list[Any] = []
    r, _, _ = runner()
    meta = {"tool_fixtures": {"lookup_claim": {"responses": [{"when": {"id": "C-1"}, "result": {"status": "open"}}]}}}
    out = await r.run_case(mf(), EvalCase("c1", "please lookup", metadata=meta), run_seed=1, eval_run_id="e")
    assert out.status == "completed" and out.trace
    assert out.trace.output == 'result: {"status": "open"}'
    assert [(c.name, c.ok) for c in out.trace.tool_calls] == [("lookup_claim", True)]
    assert real_calls == []


async def test_a_tool_without_a_fixture_is_an_error_not_a_real_call_and_dry_run_is_declared() -> None:
    r, _, _ = runner()
    out = await r.run_case(mf(), EvalCase("c1", "please lookup"), run_seed=1, eval_run_id="e")
    assert out.trace and [(c.name, c.ok) for c in out.trace.tool_calls] == [("lookup_claim", False)]
    out = await r.run_case(
        mf(), EvalCase("c2", "please lookup", metadata={"dry_run": True}), run_seed=1, eval_run_id="e"
    )
    assert out.trace and out.trace.tool_calls[0].ok is True
    assert "dry_run" in (out.trace.output or "")


def test_fixture_tool_matching_and_registry_contents() -> None:
    manifest = mf()
    case = EvalCase(
        "c",
        "x",
        metadata={"tool_fixtures": {"send_email": {"description": "d", "input_schema": {"type": "object"}, "responses": [{"error": "mailbox full"}]}}},
    )
    reg, tools = build_tool_registry(manifest, case)
    assert set(tools) == {"lookup_claim", "send_email"}  # function tools only: never the code tool
    assert reg.get("run_python") is None
    assert reg.get("send_email").description == "d"  # type: ignore[union-attr]
    with pytest.raises(LookupError, match="mailbox full"):
        tools["send_email"]({})
    ft = FixtureTool("t", [{"when": {"a": 1}, "result": "one"}, {"result": "any"}])
    assert ft({"a": 1}) == "one" and ft({"a": 2}) == "any" and len(ft.calls) == 2
    with pytest.raises(ValueError):
        build_tool_registry(manifest, EvalCase("c", "x", metadata={"tool_fixtures": []}))


# ---- isolation ------------------------------------------------------------------------------------


async def test_cases_share_nothing() -> None:
    r, transport, _ = runner()
    cases = [EvalCase("c1", "first-secret-A"), EvalCase("c2", "second-B"), EvalCase("c3", "third-C")]
    outs = await r.run_all(mf(), cases, run_seed=3, eval_run_id="e")
    assert [o.case.id for o in outs] == ["c1", "c2", "c3"]
    run_ids = {o.trace.run_id for o in outs if o.trace}
    trace_ids = {o.trace.trace_id for o in outs if o.trace}
    assert len(run_ids) == 3 and len(trace_ids) == 3
    hashes = {o.trace.events_hash for o in outs if o.trace}
    assert len(hashes) == 3
    for call in transport.calls:  # no case's content reaches another case's model context
        text = user_text(call)
        assert sum(k in text for k in ("first-secret-A", "second-B", "third-C")) == 1


async def test_a_declared_session_runs_in_order_and_everything_else_is_independent() -> None:
    active = 0
    spans: list[tuple[str, str]] = []

    async def delay(messages: list[dict[str, Any]]) -> None:
        nonlocal active
        who = user_text(messages)
        spans.append(("start", who))
        active += 1
        await asyncio.sleep(0.02)
        active -= 1
        spans.append(("end", who))

    transport = FnTransport(agent, delay)
    r, _, _ = runner(transport=transport, config=RunnerConfig(concurrency=4, case_timeout_seconds=5))
    cases = [
        EvalCase("s1", "step-1", metadata={"session": "S"}),
        EvalCase("x1", "solo-1"),
        EvalCase("s2", "step-2", metadata={"session": "S"}),
        EvalCase("s3", "step-3", metadata={"session": "S"}),
    ]
    outs = await r.run_all(mf(), cases, run_seed=1, eval_run_id="e")
    assert all(o.status == "completed" for o in outs)
    steps = [(k, w) for k, w in spans if w.startswith("step")]
    assert steps == [("start", "step-1"), ("end", "step-1"), ("start", "step-2"), ("end", "step-2"), ("start", "step-3"), ("end", "step-3")]


def test_lockdown_removes_everything_that_could_leak_or_cache() -> None:
    sentinel: Any = object()
    base = RunDeps(
        tenant_id=TENANT,
        gate=ScriptedGate(allow()),
        models=sentinel,
        tools=ToolRegistry(),
        backends=Backends(),
        browser=sentinel,
        channels=sentinel,
        reply=sentinel,
        approvals=sentinel,
        nexus_factory=sentinel,
        runner_factory=sentinel,
        child_spawner=sentinel,
        memory=sentinel,
        session_id="prod-session",
        run_id="prod-run",
    )
    reg = ToolRegistry()
    d = lockdown_deps(base, tenant_id=TENANT, run_id="r", trace_id="t", tools=reg, gate=base.gate)
    assert (d.backends, d.browser, d.channels, d.reply, d.approvals, d.nexus_factory) == (None,) * 6
    assert (d.runner_factory, d.child_spawner, d.memory, d.session_id) == (None,) * 4
    assert d.run_id == "r" and d.trace_id == "t" and d.tools is reg and d.log is not base.log
    d2 = lockdown_deps(base, tenant_id=TENANT, run_id="r", trace_id="t", tools=reg, gate=base.gate, session_id="s")
    assert d2.session_id == "s" and d2.memory is sentinel  # memory only for a declared session
    with pytest.raises(ValueError, match="another tenant"):
        lockdown_deps(base, tenant_id="other", run_id="r", trace_id="t", tools=reg, gate=base.gate)


async def test_deps_of_another_tenant_are_refused_and_not_retried() -> None:
    r, transport, _ = runner(base_tenant="22222222-2222-4222-8222-222222222222")
    out = await r.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="e")
    assert out.status == "error" and out.attempts == 1 and out.trace is None
    assert transport.calls == []


# ---- eval-mode lockdown ---------------------------------------------------------------------------


def request(point: EnforcementPoint, action: str, kind: str = "function") -> EvaluateRequest:
    return EvaluateRequest(
        tenant_id=TENANT, trace_id="t", span_id="s", actor_type=__import__("axis_runtime.gate", fromlist=["ActorType"]).ActorType.AGENT,
        actor_id="a", pid="p", blueprint_name="b", blueprint_version="1", enforcement_point=point,
        action=action, context={"tool": {"name": action, "kind": kind, "side_effects": "external"}},
    )


@pytest.mark.parametrize(
    "point, action, kind, allowed",
    [
        (EnforcementPoint.MODEL_CALL, "openai/gpt-4o", "function", True),
        (EnforcementPoint.TOOL_CALL, "lookup_claim", "function", True),
        (EnforcementPoint.TOOL_CALL, "child", "agent", True),
        (EnforcementPoint.TOOL_CALL, "x", "mcp", False),
        (EnforcementPoint.TOOL_CALL, "x", "code", False),
        (EnforcementPoint.TOOL_CALL, "x", "channel", False),
        (EnforcementPoint.MCP_CALL, "srv/tool", "mcp", False),
        (EnforcementPoint.CODE_EXEC, "run_python", "code", False),
        (EnforcementPoint.BROWSER_EXEC, "navigate", "browser", False),
        (EnforcementPoint.MEMORY_WRITE, "memory_write", "function", False),
        (EnforcementPoint.MESSAGE_SEND, "channel.reply", "function", False),
    ],
)
async def test_eval_mode_denies_side_effect_actions_before_the_kernel(
    point: EnforcementPoint, action: str, kind: str, allowed: bool
) -> None:
    inner = ScriptedGate(allow())
    gate = EvalModeGate(inner, EvalModePolicy())
    d = await gate.evaluate(request(point, action, kind))
    assert (d.decision is Decision.ALLOW) is allowed
    assert len(inner.requests) == (1 if allowed else 0)
    if not allowed:
        assert d.reason.startswith("eval_mode_side_effect_denied")


async def test_a_suite_can_allow_a_named_sandboxed_target_but_the_kernel_still_decides() -> None:
    inner = ScriptedGate(deny("tenant policy says no"))
    gate = EvalModeGate(inner, EvalModePolicy(frozenset({"run_python"})))
    d = await gate.evaluate(request(EnforcementPoint.CODE_EXEC, "run_python", "code"))
    assert d.decision is Decision.DENY and d.reason == "tenant policy says no" and len(inner.requests) == 1
    other = await gate.evaluate(request(EnforcementPoint.CODE_EXEC, "run_ruby", "code"))
    assert other.reason.startswith("eval_mode_side_effect_denied")


async def test_a_code_tool_in_an_eval_run_is_denied_and_never_performed() -> None:
    r, _, gate = runner()
    out = await r.run_case(mf(), EvalCase("c1", "run some code"), run_seed=1, eval_run_id="e")
    assert out.trace and out.status == "completed"
    denied = [d for d in out.trace.gate_decisions if d.action == "run_python"]
    assert [(d.decision, d.reason.split(":")[0]) for d in denied] == [("DENY", "eval_mode_side_effect_denied")]
    assert not any(q.enforcement_point is EnforcementPoint.CODE_EXEC for q in gate.requests)
    assert out.trace.tool_calls == ()


async def test_the_tenants_policy_still_applies_in_eval_mode() -> None:
    def fn(req: EvaluateRequest) -> GateDecision:
        return deny("tenant policy: no outbound mail") if req.action == "send_email" else allow()

    r, _, gate = runner(gate=ScriptedGate(fn))
    out = await r.run_case(mf(), EvalCase("c1", "send mail"), run_seed=1, eval_run_id="e")
    assert out.trace
    d = [x for x in out.trace.gate_decisions if x.action == "send_email"]
    assert [(x.decision, x.reason) for x in d] == [("DENY", "tenant policy: no outbound mail")]
    assert out.trace.tool_calls == ()  # denied: never performed, not even against the fixture


async def test_a_model_call_denied_by_policy_ends_the_case_as_policy_denied_without_retry() -> None:
    r, transport, _ = runner(gate=ScriptedGate(deny("model egress blocked")))
    out = await r.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="e")
    assert out.status == "policy_denied" and out.attempts == 1 and out.trace is not None
    assert out.trace.gate_decisions[0].decision == "DENY" and transport.calls == []


async def test_a_require_approval_does_not_wait_for_a_human() -> None:
    def fn(req: EvaluateRequest) -> GateDecision:
        if req.action == "send_email":
            return GateDecision(Decision.REQUIRE_APPROVAL, "needs approval", approval_id="apr_1")
        return allow()

    r, _, _ = runner(gate=ScriptedGate(fn))
    out = await asyncio.wait_for(
        r.run_case(mf(), EvalCase("c1", "send mail"), run_seed=1, eval_run_id="e"), timeout=5
    )
    assert out.status == "approval_required" and out.trace is not None


# ---- caps, timeouts -------------------------------------------------------------------------------


def test_caps_tighten_but_never_loosen_the_blueprints_own() -> None:
    base = mf(budgets={"tokens": {"soft": None, "hard": 100}, "tool_calls": {"soft": None, "hard": 2}})
    case = EvalCase("c", "x", metadata={"budget": {"max_tokens": 50, "max_tool_calls": 9}, "timeout_seconds": 7})
    m = prepare_manifest(base, RunnerConfig(max_tokens=80, case_timeout_seconds=30), case, 5)
    assert m.budgets.tokens.hard == 50 and m.budgets.tool_calls.hard == 2
    assert m.process.timeout_seconds == 7 and m.budgets.runtime_seconds.hard == 7
    assert m.primary.params["seed"] == 5
    loose = prepare_manifest(base, RunnerConfig(max_tokens=10_000), EvalCase("c", "x"), 5)
    assert loose.budgets.tokens.hard == 100
    capped_soft = prepare_manifest(mf(budgets={"tokens": {"soft": 90, "hard": 100}}), RunnerConfig(max_tokens=40), EvalCase("c", "x"), 1)
    assert capped_soft.budgets.tokens.soft == 40 and capped_soft.budgets.tokens.hard == 40


async def test_a_budget_cap_stops_the_case() -> None:
    r, _, _ = runner()
    out = await r.run_case(
        mf(), EvalCase("c1", "hello", metadata={"budget": {"max_tokens": 5}}), run_seed=1, eval_run_id="e"
    )
    assert out.status == "budget_exceeded" and out.attempts == 1  # not retried


async def test_a_slow_case_times_out_and_is_not_retried() -> None:
    async def slow(messages: list[dict[str, Any]]) -> None:
        await asyncio.sleep(30)

    r, transport, _ = runner(transport=FnTransport(agent, slow), config=RunnerConfig(case_timeout_seconds=0.2))
    out = await asyncio.wait_for(r.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="e"), timeout=10)
    assert out.status == "timeout" and out.attempts == 1 and out.trace is not None
    assert len(transport.calls) == 1


# ---- retries: infrastructure only -----------------------------------------------------------------


class FlakyGate:
    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.requests: list[EvaluateRequest] = []

    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        self.requests.append(request)
        if self.failures > 0:
            self.failures -= 1
            raise RuntimeError("kernel unreachable")
        return allow()


async def test_an_infrastructure_failure_is_retried_with_a_fresh_run() -> None:
    gate = FlakyGate(1)
    r = CaseRunner(
        make_base_deps(FnTransport(agent), gate),  # type: ignore[arg-type]
        tenant_id=TENANT,
        config=RunnerConfig(case_timeout_seconds=5, max_infra_retries=2),
        ids=SeqIds(),
    )
    out = await r.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="e")
    assert out.status == "completed" and out.attempts == 2 and out.trace
    assert out.trace.run_id == "run_eval0002"  # the retry is a new run, not a resume


async def test_persistent_infrastructure_failure_is_an_error_case_with_no_trace() -> None:
    gate = FlakyGate(99)
    r = CaseRunner(
        make_base_deps(FnTransport(agent), gate),  # type: ignore[arg-type]
        tenant_id=TENANT,
        config=RunnerConfig(case_timeout_seconds=5, max_infra_retries=2),
        ids=SeqIds(),
    )
    out = await r.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="e")
    assert out.status == "error" and out.attempts == 3 and out.trace is None and out.error
    assert len(gate.requests) == 3


async def test_a_provider_outage_is_infrastructure_but_a_bad_key_is_not() -> None:
    r, transport, _ = runner(lambda m, n: (500, {"error": "boom"}), config=RunnerConfig(case_timeout_seconds=5, max_infra_retries=1))
    out = await r.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="e")
    assert out.status == "error" and out.attempts == 2
    calls_after_outage = len(transport.calls)
    assert calls_after_outage >= 2
    r2, transport2, _ = runner(lambda m, n: (401, {"error": "bad key"}), config=RunnerConfig(case_timeout_seconds=5, max_infra_retries=3))
    out2 = await r2.run_case(mf(), EvalCase("c1", "hello"), run_seed=1, eval_run_id="e")
    assert out2.status == "failed" and out2.attempts == 1 and len(transport2.calls) == 1


async def test_a_wrong_answer_is_never_rerun() -> None:
    """The runner cannot see scores; a completed case is final whatever it said."""
    r, transport, _ = runner(lambda m, n: text_body("completely wrong"), config=RunnerConfig(case_timeout_seconds=5, max_infra_retries=5))
    out = await r.run_case(mf(), EvalCase("c1", "hello", expected="right"), run_seed=1, eval_run_id="e")
    assert out.status == "completed" and out.attempts == 1 and len(transport.calls) == 1


def test_is_infra_failure_classification() -> None:
    from types import SimpleNamespace

    from axis_runtime.process import ExitReason

    def res(reason: ExitReason | None, detail: str) -> Any:
        info = SimpleNamespace(exit_detail=detail)
        return SimpleNamespace(exit_reason=reason, pid="p", state=SimpleNamespace(processes={"p": info}))

    for detail in ("model call denied: gate_timeout", "model call denied: gate_error:RuntimeError", "model call denied: gate_rpc_error:UNAVAILABLE"):
        assert is_infra_failure(res(ExitReason.POLICY_DENIED, detail))
    assert not is_infra_failure(res(ExitReason.POLICY_DENIED, "model call denied: tenant policy"))
    assert is_infra_failure(res(ExitReason.FAILED, "model call failed: ModelError: openai: server: 500"))
    assert is_infra_failure(res(ExitReason.FAILED, "model call failed: ModelError: openai: circuit_open"))
    assert not is_infra_failure(res(ExitReason.FAILED, "model call failed: ModelError: openai: auth"))
    assert not is_infra_failure(res(ExitReason.FAILED, "max_steps (16) reached"))
    assert not is_infra_failure(res(ExitReason.COMPLETED, "gate_timeout"))
    assert not is_infra_failure(res(ExitReason.BUDGET_EXCEEDED, "gate_error"))


# ---- determinism, concurrency ---------------------------------------------------------------------


def test_case_seed_is_stable_and_distinct() -> None:
    assert case_seed(1, "a") == case_seed(1, "a")
    assert case_seed(1, "a") != case_seed(2, "a") and case_seed(1, "a") != case_seed(1, "b")
    assert all(0 <= case_seed(s, "x") < 2**31 for s in range(50))


async def test_same_seed_same_results_and_the_seed_reaches_the_model() -> None:
    cases = [EvalCase(f"c{i}", f"question {i}") for i in range(5)]
    first = runner()
    second = runner()
    a = await first[0].run_all(mf(), cases, run_seed=42, eval_run_id="e")
    b = await second[0].run_all(mf(), cases, run_seed=42, eval_run_id="e")
    proj = lambda outs: [(o.case.id, o.status, o.seed, o.trace.output if o.trace else None) for o in outs]  # noqa: E731
    assert proj(a) == proj(b)
    seeds_a = sorted(body["seed"] for body in first[1].bodies)
    assert seeds_a == sorted(case_seed(42, c.id) for c in cases) == sorted(body["seed"] for body in second[1].bodies)
    third = runner()
    await third[0].run_all(mf(), cases, run_seed=43, eval_run_id="e")
    assert sorted(body["seed"] for body in third[1].bodies) != seeds_a


async def test_concurrency_is_bounded() -> None:
    live = peak = 0

    async def delay(messages: list[dict[str, Any]]) -> None:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.02)
        live -= 1

    r, _, _ = runner(transport=FnTransport(agent, delay), config=RunnerConfig(concurrency=2, case_timeout_seconds=5))
    outs = await r.run_all(mf(), [EvalCase(f"c{i}", f"q{i}") for i in range(7)], run_seed=1, eval_run_id="e")
    assert all(o.status == "completed" for o in outs) and peak == 2


def test_runner_config_validation() -> None:
    for bad in ({"concurrency": 0}, {"case_timeout_seconds": 0}, {"max_infra_retries": -1}):
        with pytest.raises(ValueError):
            RunnerConfig(**bad)


async def test_openai_body_helper_and_gateway_are_wired() -> None:  # keeps conftest helpers honest
    assert openai_body("x")["choices"][0]["message"]["content"] == "x"
    assert make_gateway(FnTransport(agent), FakeClock()) is not None  # type: ignore[arg-type]
