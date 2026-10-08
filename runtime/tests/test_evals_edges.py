"""Edge paths of the eval runner: cancellation, backstops, helper failures."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from axis_runtime.evals import graders as graders_mod
from axis_runtime.evals import judge_backend as jb
from axis_runtime.evals import runner as runner_mod
from axis_runtime.evals.graders import grade_deterministic
from axis_runtime.evals.isolation import RandomIds
from axis_runtime.evals.jsonschema_lite import validate
from axis_runtime.evals.judge import JudgeConfig, JudgeUnavailable
from axis_runtime.evals.redact import names_in, redact_value
from axis_runtime.evals.runner import CaseRunner, RunnerConfig
from axis_runtime.evals.trace import trace_from_events
from axis_runtime.evals.types import CaseTrace, EvalCase, WireError
from axis_runtime.events import CorruptLogError
from axis_runtime.process import Signal
from axis_runtime.run import run_agent
from conftest import TENANT, ScriptedGate, allow
from evals_helpers import FnTransport, SeqIds, det, make_base_deps, make_manifest, text_body


def test_random_ids_are_fresh_and_well_formed() -> None:
    ids = RandomIds()
    runs = {ids.run_id() for _ in range(50)}
    traces = {ids.trace_id() for _ in range(50)}
    assert len(runs) == len(traces) == 50
    assert all(r.startswith("run_") and len(r) == 28 for r in runs) and all(
        len(t) == 32 for t in traces
    )


async def test_an_oserror_while_setting_up_a_case_is_retried_as_infrastructure() -> None:
    transport = FnTransport(lambda m, n: text_body("ok"))
    good = make_base_deps(transport, ScriptedGate(allow()))
    calls = {"n": 0}

    def flaky() -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("connection refused")
        return good()

    r = CaseRunner(flaky, tenant_id=TENANT, config=RunnerConfig(max_infra_retries=1), ids=SeqIds())
    out = await r.run_case(make_manifest(), EvalCase("c1", "hi"), run_seed=1, eval_run_id="e")
    assert out.status == "completed" and out.attempts == 2


async def test_the_backstop_kills_a_run_that_outlives_its_own_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FnTransport(lambda m, n: text_body("ok"))
    deps = make_base_deps(transport, ScriptedGate(allow()))()
    real = await run_agent(make_manifest(), "hi", deps)
    killed = asyncio.Event()

    class Handle:
        calls = 0

        async def result(self) -> Any:
            Handle.calls += 1
            if Handle.calls == 1:
                await asyncio.sleep(30)  # never ends by itself
            return real

        async def signal(self, sig: Signal, message: str | None = None) -> None:
            assert sig is Signal.KILL
            killed.set()

    async def fake_start(manifest: Any, text: str, d: Any) -> Any:
        d.log = deps.log
        return Handle()

    monkeypatch.setattr(runner_mod, "start_agent", fake_start)

    r = CaseRunner(
        make_base_deps(transport, ScriptedGate(allow())),
        tenant_id=TENANT,
        config=RunnerConfig(case_timeout_seconds=0.05),
        ids=SeqIds(),
    )
    # the backstop fires `timeout + 1.0` s in: run the case in a task and wait for the kill
    task = asyncio.create_task(
        r.run_case(make_manifest(), EvalCase("c1", "hi"), run_seed=1, eval_run_id="e")
    )
    await asyncio.wait_for(killed.wait(), 5)
    out = await asyncio.wait_for(task, 5)
    assert out.case.id == "c1" and Handle.calls == 2


async def test_judge_backend_maps_every_failure_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = jb.RunPathJudgeBackend(
        make_base_deps(FnTransport(lambda m, n: text_body("{}")), ScriptedGate(allow())),
        tenant_id=TENANT,
    )
    cfg = JudgeConfig("openai", "gpt-4o", "rubric")

    async def raises_timeout(*a: Any, **k: Any) -> Any:
        raise TimeoutError

    async def raises_other(*a: Any, **k: Any) -> Any:
        raise RuntimeError("boom with sk-secret")

    async def cancelled(*a: Any, **k: Any) -> Any:
        raise asyncio.CancelledError

    monkeypatch.setattr(jb, "run_agent", raises_timeout)
    with pytest.raises(JudgeUnavailable, match="timeout"):
        await backend.ask(system="s", user="u", config=cfg, seed=1)
    monkeypatch.setattr(jb, "run_agent", raises_other)
    with pytest.raises(JudgeUnavailable) as ei:
        await backend.ask(system="s", user="u", config=cfg, seed=1)
    assert ei.value.reason == "RuntimeError" and "secret" not in str(ei.value)
    monkeypatch.setattr(jb, "run_agent", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await backend.ask(system="s", user="u", config=cfg, seed=1)


def test_a_grader_that_crashes_is_an_error_grade(monkeypatch: pytest.MonkeyPatch) -> None:
    def crash(*a: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setitem(graders_mod._DETERMINISTIC, "exact", crash)  # noqa: SLF001
    g = grade_deterministic(
        det("g", "exact", value="x"), EvalCase("c", "q"), CaseTrace("r", "t", "completed", "x")
    )
    assert (g.status, g.score, g.detail) == ("error", 0.0, "grader_failed:RuntimeError")


def test_redaction_walks_structures_and_learns_names() -> None:
    doc = {"a": ["SSN 123-45-6789", {"b": "keep"}], "n": 3}
    out = redact_value(doc, phi=True)
    assert out == {"a": ["[REDACTED]", {"b": "keep"}], "n": 3}
    assert names_in("my name is Jane Doe") == ["Jane", "Doe"]
    assert (
        redact_value("thanks Jane", phi=True, names=names_in("my name is Jane Doe"))
        == "thanks [REDACTED]"
    )
    assert redact_value(["Jane"], phi=False, names=["Jane"]) == ["Jane"]


def test_trace_from_events_needs_a_real_log() -> None:
    with pytest.raises(CorruptLogError):
        trace_from_events([])


def test_schema_error_paths_and_non_finite_numbers() -> None:
    assert validate({"items": {"type": "integer"}, "type": "array"}, [1, "x"])
    assert validate({"type": "object", "additionalProperties": False}, {"a": 1})
    with pytest.raises(WireError):
        from axis_runtime.evals.types import Suite  # noqa: PLC0415

        Suite.from_wire(
            {
                "ref": "s@1",
                "dataset_ref": "d@1",
                "graders": [{"id": "g", "kind": "human", "weight": float("inf")}],
                "pass_threshold": 0.5,
            }
        )
