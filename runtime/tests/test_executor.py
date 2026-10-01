"""ActionExecutor: the only path to a side effect, and only after the gate says so."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from axis_runtime import Decision, all_action_types
from axis_runtime.actions import (
    Action,
    Backends,
    ExecutionToken,
    ModelCall,
    ToolCall,
    action_from_spec,
    bind_executor_token,
    in_executor,
)
from axis_runtime.events import EventType, replay
from axis_runtime.executor import (
    ActionExecutor,
    Completed,
    Denied,
    Failed,
    PendingApproval,
)
from axis_runtime.gate import EvaluateRequest, GateDecision
from axis_runtime.guard import DirectExecutionError
from axis_runtime.models import Message, ModelRequest, ModelTarget
from axis_runtime.tools import BackendUnavailableError
from conftest import ScriptedGate, allow, deny
from helpers import PID, SAMPLES, Effects, make_executor, running_recorder


def types_of(events: list[Any]) -> list[str]:
    return [e.type for e in events]


async def test_allow_performs_and_records_decision_then_result() -> None:
    ex, rec, effects, gate = await make_executor()
    out = await ex.run(ToolCall(name="lookup", args={"q": "x"}, side_effects="read"), pid=PID)
    assert isinstance(out, Completed) and out.result["found"] is True
    assert effects.calls == [("tool", {"q": "x"})]
    events = await rec.log.read("run_1")
    assert types_of(events)[-2:] == [EventType.GATE_DECISION, EventType.TOOL_CALL_RESULT]
    assert replay(events) == rec.state
    req: EvaluateRequest = gate.requests[0]
    assert req.enforcement_point.value == "tool_call" and req.action == "lookup" and req.pid == PID
    ctx = req.context
    assert ctx["tool"] == {"name": "lookup", "kind": "function", "side_effects": "read"}
    assert ctx["args"] == {"q": "x"} and ctx["data"] == {"phi": False}
    assert ctx["tenant"]["id"] == req.tenant_id and ctx["run"] == {"id": "run_1"}
    assert ctx["agent"] == {"name": "claims-triage", "version": "1.0.0"}
    assert ctx["actor"] == {"type": "agent", "id": PID} and ctx["enforcement_point"] == "tool_call"


async def test_phi_flag_reaches_the_policy_input() -> None:
    ex, _, _, gate = await make_executor(phi=True)
    await ex.run(ToolCall(name="lookup"), pid=PID)
    assert gate.requests[0].context["data"]["phi"] is True


async def test_deny_performs_nothing_and_is_audited() -> None:
    ex, rec, effects, _ = await make_executor(ScriptedGate(deny("pii egress")))
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "pii egress"
    assert effects.total() == 0
    events = await rec.log.read("run_1")
    assert types_of(events)[-1] == EventType.GATE_DECISION and events[-1].data["decision"] == "DENY"
    assert rec.state.tool_calls == ()


async def test_require_approval_performs_nothing() -> None:
    gate = ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "needs human", approval_id="ap_7"))
    ex, rec, effects, _ = await make_executor(gate)
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, PendingApproval) and out.approval_id == "ap_7"
    assert effects.total() == 0
    assert rec.state.gate_decisions[-1].approval_id == "ap_7"
    assert rec.state.tool_calls == ()


async def test_redaction_applies_to_args_before_and_result_after() -> None:
    gate = ScriptedGate(
        GateDecision(Decision.ALLOW_WITH_REDACTION, "phi", redact_fields=("args.ssn", "result.ssn"))
    )
    ex, rec, effects, _ = await make_executor(gate)
    out = await ex.run(ToolCall(name="lookup", args={"q": "x", "ssn": "123"}), pid=PID)
    assert isinstance(out, Completed)
    assert effects.calls == [("tool", {"q": "x", "ssn": "[REDACTED]"})]  # tool never saw the SSN
    assert out.result["ssn"] == "[REDACTED]" and out.result["name"] == "Ada"
    assert rec.state.tool_calls[-1].result["ssn"] == "[REDACTED]"  # log holds the redacted result
    assert "111-22-3333" not in json.dumps([e.to_dict() for e in await rec.log.read("run_1")])


async def test_unprefixed_redaction_path_hits_args_and_result() -> None:
    gate = ScriptedGate(GateDecision(Decision.ALLOW_WITH_REDACTION, "x", redact_fields=("ssn",)))
    ex, _, effects, _ = await make_executor(gate)
    out = await ex.run(ToolCall(name="lookup", args={"ssn": "123"}), pid=PID)
    assert effects.calls[0][1]["ssn"] == "[REDACTED]"
    assert isinstance(out, Completed) and out.result["ssn"] == "[REDACTED]"


async def test_malformed_redaction_path_fails_closed() -> None:
    gate = ScriptedGate(
        GateDecision(Decision.ALLOW_WITH_REDACTION, "x", redact_fields=("args..ssn",))
    )
    ex, rec, effects, _ = await make_executor(gate)
    out = await ex.run(ToolCall(name="lookup", args={"ssn": "123"}), pid=PID)
    assert isinstance(out, Denied) and out.reason == "redaction_failed"
    assert effects.total() == 0 and rec.state.blocked_actions == 1


class _BoomGate:
    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        raise ConnectionError("kernel down; token=abc123")


class _SlowGate:
    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        await asyncio.sleep(5)
        return allow()


@pytest.mark.parametrize(
    ("gate", "reason"),
    [
        (_BoomGate(), "gate_error:ConnectionError"),
        (_SlowGate(), "gate_timeout"),
        (ScriptedGate(GateDecision("UNSPECIFIED")), "gate_unknown_decision"),  # type: ignore[arg-type]
        (ScriptedGate(GateDecision(Decision.ALLOW_WITH_REDACTION)), "gate_malformed_response"),
    ],
    ids=["exception", "timeout", "unspecified", "malformed"],
)
@pytest.mark.parametrize("make", list(SAMPLES.values()), ids=[t.__name__ for t in SAMPLES])
async def test_every_gate_failure_mode_denies_every_action_type(
    gate: Any, reason: str, make: Any
) -> None:
    ex, rec, effects, _ = await make_executor(gate)
    out = await ex.run(make(), pid=PID)
    assert isinstance(out, Denied) and out.reason.startswith(reason)
    assert out.decision.decision is Decision.DENY
    assert effects.total() == 0
    assert rec.state.gate_decisions[-1].decision is Decision.DENY
    assert "abc123" not in json.dumps([e.to_dict() for e in await rec.log.read("run_1")])


async def test_executor_wraps_a_misbehaving_gate_even_if_failclosed_is_bypassed() -> None:
    ex, _, effects, _ = await make_executor(_BoomGate())

    # replace the wrapper by one that re-raises: executor itself must still deny
    class Raw:
        async def evaluate(self, request: EvaluateRequest) -> GateDecision:
            raise RuntimeError("x")

    ex._gate = Raw()  # type: ignore[assignment]  # noqa: SLF001
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert (
        isinstance(out, Denied) and out.reason == "gate_error:RuntimeError" and effects.total() == 0
    )


async def test_unknown_decision_object_is_denied_defensively() -> None:
    ex, _, effects, _ = await make_executor()

    class Weird:
        async def evaluate(self, request: EvaluateRequest) -> GateDecision:
            d = GateDecision(Decision.ALLOW)
            object.__setattr__(d, "decision", _Fake())
            return d

    class _Fake(str):  # looks like a str, is not a Decision
        pass

    ex._gate = Weird()  # type: ignore[assignment]  # noqa: SLF001
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and effects.total() == 0


# ---- capability guard --------------------------------------------------------------------------


@pytest.mark.parametrize("make", list(SAMPLES.values()), ids=[t.__name__ for t in SAMPLES])
async def test_perform_cannot_be_called_directly(make: Any) -> None:
    action: Action = make()
    backends = Backends()
    with pytest.raises(DirectExecutionError):
        await action.perform(ExecutionToken(), backends)  # a forged token
    with pytest.raises(DirectExecutionError):
        await action.perform(None, backends)  # type: ignore[arg-type]


def test_token_can_only_be_bound_once() -> None:
    with pytest.raises(DirectExecutionError, match="already bound"):
        bind_executor_token(ExecutionToken())


async def test_model_gateway_refuses_calls_outside_the_executor() -> None:
    _, _, effects, _ = await make_executor()
    from helpers import recording_backends

    gw = recording_backends(effects).models
    assert gw is not None and not in_executor()
    req = ModelRequest(
        tenant_id="t", messages=(Message("user", "hi"),), target=ModelTarget("openai", "m")
    )
    with pytest.raises(DirectExecutionError):
        await gw.complete(req)
    with pytest.raises(DirectExecutionError):
        gw.stream(req)
    assert effects.total() == 0


# ---- process state gating --------------------------------------------------------------------


async def test_unknown_pid_raises() -> None:
    ex, _, _, _ = await make_executor()
    with pytest.raises(KeyError):
        await ex.run(ToolCall(name="lookup"), pid="axp_01ARZ3NDEKTSV4RRFFQ69G5FAW")


@pytest.mark.parametrize("state", ["spawn", "ready"])
async def test_non_running_process_cannot_act(state: str) -> None:
    ex, rec, effects, gate = await make_executor(to_state=state)
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == f"process_not_runnable:{state}"
    assert effects.total() == 0 and gate.requests == [] and rec.state.blocked_actions == 1


async def test_terminated_process_cannot_act() -> None:
    ex, rec, effects, gate = await make_executor()
    await rec.record(
        EventType.PROCESS_TRANSITION,
        PID,
        {"from": "running", "to": "terminated", "trigger": "KILL", "exit_reason": "killed"},
    )
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and "terminated" in out.reason
    assert effects.total() == 0 and gate.requests == []


async def test_kill_during_gate_evaluation_blocks_the_action() -> None:
    effects = Effects()
    rec = await running_recorder()
    holder: dict[str, Any] = {}

    class KillingGate:
        async def evaluate(self, request: EvaluateRequest) -> GateDecision:
            await rec.record(
                EventType.PROCESS_TRANSITION,
                PID,
                {"from": "running", "to": "terminated", "trigger": "KILL", "exit_reason": "killed"},
            )
            return allow()

    from helpers import identity, recording_backends

    ex = ActionExecutor(
        gate=KillingGate(), recorder=rec, identity=identity(), backends=recording_backends(effects)
    )
    holder["ex"] = ex
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "process_terminated_during_gate"
    assert effects.total() == 0
    assert rec.state.gate_decisions == ()  # an allow for a dead process is never recorded
    assert replay(await rec.log.read("run_1")) == rec.state


async def test_waiting_process_may_act() -> None:
    ex, rec, effects, _ = await make_executor()
    await rec.record(
        EventType.PROCESS_TRANSITION, PID, {"from": "running", "to": "waiting", "trigger": "await"}
    )
    assert isinstance(await ex.run(ToolCall(name="lookup"), pid=PID), Completed)
    assert effects.total() == 1


# ---- failures, ids, cancellation ---------------------------------------------------------------


async def test_action_exception_is_recorded_and_returned_as_failed() -> None:
    ex, rec, _, _ = await make_executor()
    out = await ex.run(ToolCall(name="missing-tool"), pid=PID)  # registry has no such tool
    assert isinstance(out, Failed) and out.error.startswith("ToolNotFoundError")
    rec_call = rec.state.tool_calls[-1]
    assert rec_call.ok is False and rec_call.error == out.error
    assert rec.state.gate_decisions[-1].decision is Decision.ALLOW  # the gate allowed it first


async def test_missing_backend_is_a_failed_action_not_a_crash() -> None:
    ex, _, _, _ = await make_executor()
    ex._backends.mcp = None  # noqa: SLF001
    out = await ex.run(
        SAMPLES[__import__("axis_runtime.actions", fromlist=["McpCall"]).McpCall](), pid=PID
    )
    assert isinstance(out, Failed) and BackendUnavailableError.__name__ in out.error


async def test_long_error_messages_are_truncated() -> None:
    ex, _, effects, _ = await make_executor()

    def boom(args: Any) -> Any:
        raise ValueError("x" * 5000)

    ex._backends.tools.register("lookup", boom)  # type: ignore[union-attr]  # noqa: SLF001
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Failed) and len(out.error) < 400


async def test_action_ids_are_unique_and_resume_from_state() -> None:
    ex, rec, effects, _ = await make_executor()
    for _ in range(3):
        await ex.run(ToolCall(name="lookup"), pid=PID)
    ids = [g.action_id for g in rec.state.gate_decisions]
    assert ids == ["act_000001", "act_000002", "act_000003"]
    from helpers import identity, recording_backends

    ex2 = ActionExecutor(
        gate=ScriptedGate(), recorder=rec, identity=identity(), backends=recording_backends(effects)
    )
    await ex2.run(ToolCall(name="lookup"), pid=PID)
    assert rec.state.gate_decisions[-1].action_id == "act_000004"


async def test_cancellation_during_perform_records_no_result() -> None:
    ex, rec, _, _ = await make_executor()
    started = asyncio.Event()

    async def hang(args: Any) -> Any:
        started.set()
        await asyncio.sleep(30)

    ex._backends.tools.register("lookup", hang)  # type: ignore[union-attr]  # noqa: SLF001
    task = asyncio.create_task(ex.run(ToolCall(name="lookup"), pid=PID))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert rec.state.tool_calls == ()  # never claims a result that did not happen
    assert not in_executor()


# ---- model call as an action --------------------------------------------------------------------


async def test_model_call_runs_through_gate_and_logs_a_summary() -> None:
    ex, rec, effects, gate = await make_executor()
    out = await ex.run(SAMPLES[ModelCall](), pid=PID)
    assert isinstance(out, Completed) and out.result.text == "model says hi"
    req = gate.requests[0]
    assert req.enforcement_point.value == "model_call"
    assert req.context["args"]["provider"] == "openai"
    assert req.context["args"]["messages"][1]["content"].startswith("patient SSN")
    summary = rec.state.model_calls[-1]
    assert (summary.provider, summary.input_tokens, summary.output_tokens) == ("openai", 10, 5)
    assert summary.cost_micro_usd == 75  # 10*2.5/1e6 + 5*10/1e6 USD
    assert len(effects.transport.calls) == 1
    assert rec.state.tool_calls == ()


async def test_model_call_data_egress_redaction_reaches_the_provider() -> None:
    gate = ScriptedGate(
        GateDecision(
            Decision.ALLOW_WITH_REDACTION,
            "phi",
            redact_fields=("args.messages.1.content", "result.text"),
        )
    )
    ex, rec, effects, _ = await make_executor(gate)
    out = await ex.run(SAMPLES[ModelCall](), pid=PID)
    assert isinstance(out, Completed)
    sent = effects.transport.calls[0].body.decode()
    assert "111-22-3333" not in sent and "[REDACTED]" in sent and "be brief" in sent
    assert out.result.text == "[REDACTED]"


async def test_model_call_redaction_cannot_change_message_structure() -> None:
    gate = ScriptedGate(
        GateDecision(Decision.ALLOW_WITH_REDACTION, "x", redact_fields=("args.messages",))
    )
    ex, _, effects, _ = await make_executor(gate)
    out = await ex.run(SAMPLES[ModelCall](), pid=PID)
    # replacing the whole list by a string breaks the structure: fail closed
    assert isinstance(out, Denied) and out.reason == "redaction_failed" and effects.total() == 0


async def test_model_failure_is_a_failed_outcome_with_sanitized_error() -> None:
    effects = Effects()
    effects.transport.responses = [
        (401, {"error": {"type": "invalid_api_key", "message": "sk-test-secret-123"}})
    ]
    ex, rec, _, _ = await make_executor(effects=effects)
    out = await ex.run(SAMPLES[ModelCall](), pid=PID)
    assert isinstance(out, Failed) and "sk-test-secret-123" not in out.error
    assert (
        rec.state.tool_calls[-1].enforcement_point == "model_call"
        and not rec.state.tool_calls[-1].ok
    )


# ---- registry and serialisation ----------------------------------------------------------------


def test_registry_lists_every_concrete_action_and_no_abstract_ones() -> None:
    concrete = {t.__name__ for t in all_action_types()}
    assert concrete == {
        "ToolCall",
        "McpCall",
        "CodeRunAction",
        "BrowserExec",
        "MessageSend",
        "SttOpen",
        "TtsSynthesize",
        "VoiceCall",
        "MemoryWrite",
        "MemoryRead",
        "ModelCall",
    }
    assert {t for t in all_action_types()} == set(SAMPLES)
    eps = {t.enforcement_point for t in all_action_types()}
    assert len(eps) == 7  # one enforcement point per action type, all seven covered


@pytest.mark.parametrize("make", list(SAMPLES.values()), ids=[t.__name__ for t in SAMPLES])
def test_action_spec_roundtrip(make: Any) -> None:
    action = make()
    spec = json.loads(json.dumps(action.to_spec()))
    assert action_from_spec(spec) == action


def test_action_from_unknown_spec_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown action type"):
        action_from_spec({"type": "RmRf", "fields": {}})
    assert isinstance(allow(), GateDecision)
