"""Online sampler: deterministic outcome-blind selection, hourly cap, redaction before grading and
persisting, containment of failures, tenant isolation, and the architecture rule that it imports
nothing from the decision path."""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import random
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from axis_runtime.evals.grading import GradingEngine
from axis_runtime.evals.sampler import (
    CompletedRun,
    OnlineSampler,
    completed_run_from_events,
    is_selected,
    sample_position,
)
from axis_runtime.evals.types import CaseTrace, Grade, GraderSpec, OnlineConfig
from axis_runtime.events import CorruptLogError
from axis_runtime.run import run_agent
from conftest import TENANT, FakeClock, ScriptedGate, allow
from evals_helpers import FakeHub, FnTransport, det, make_base_deps, make_manifest, text_body

CFG = OnlineConfig("claims-triage", "refunds@1.0.0", 1.0, 100)
SRC = Path(__file__).resolve().parents[1] / "src" / "axis_runtime"


def completed(
    i: int,
    *,
    hour: int = 10,
    output: str | None = "It is $5.",
    phi: bool = False,
    tenant: str = TENANT,
    blueprint: str = "claims-triage",
) -> CompletedRun:
    return CompletedRun(
        tenant_id=tenant,
        run_id=f"run_{i:06d}",
        blueprint=blueprint,
        version="1.0.0",
        content_hash="a" * 64,
        completed_at=f"2026-01-01T{hour:02d}:{i % 60:02d}:00.000Z",
        trace=CaseTrace(f"run_{i:06d}", "t" * 32, "completed", output),
        phi=phi,
    )


class Reader:
    def __init__(self, runs: list[CompletedRun] | Exception) -> None:
        self.runs = runs
        self.calls: list[dict[str, Any]] = []

    async def completed_runs(
        self, *, tenant_id: str, blueprint: str, since: str, limit: int
    ) -> list[CompletedRun]:
        self.calls.append(
            {"tenant_id": tenant_id, "blueprint": blueprint, "since": since, "limit": limit}
        )
        if isinstance(self.runs, Exception):
            raise self.runs
        return list(self.runs)


class SpyGrader:
    def __init__(self) -> None:
        self.seen: list[tuple[CaseTrace, Any]] = []
        self.gate = asyncio.Event()
        self.gate.set()
        self.fail = False

    async def grade_case(
        self, graders: Any, case: Any, trace: CaseTrace, *, seed: int, phi: bool
    ) -> list[Grade]:
        await self.gate.wait()
        if self.fail:
            raise RuntimeError("judge exploded")
        self.seen.append((trace, case))
        return [Grade(g.id, g.kind, "scored", 1.0) for g in graders]


GRADERS = (det("ok", "contains", values=["$5"]),)


def sampler(
    runs: list[CompletedRun] | Exception,
    *,
    config: OnlineConfig = CFG,
    grader: Any = None,
    sink: FakeHub | None = None,
    **kw: Any,
) -> tuple[OnlineSampler, FakeHub, SpyGrader | Any]:
    hub = sink or FakeHub()
    g = grader or SpyGrader()
    s = OnlineSampler(
        config,
        TENANT,
        Reader(runs),
        g,
        GRADERS,
        hub,
        "runner-1",
        clock=kw.pop("clock", FakeClock()),
        **kw,
    )
    return s, hub, g


# ---- selection ------------------------------------------------------------------------------------


def test_sampling_is_a_pure_function_of_run_id_and_salt() -> None:
    ids = [f"run_{i:06d}" for i in range(20000)]
    pos = [sample_position(i, "s@1") for i in ids]
    assert pos == [sample_position(i, "s@1") for i in ids] and all(0 <= p < 1 for p in pos)
    picked = {i for i in ids if is_selected(i, 0.1, "s@1")}
    assert 0.085 * len(ids) < len(picked) < 0.115 * len(ids)
    assert {i for i in ids if is_selected(i, 0.2, "s@1")} >= picked  # a higher rate only adds runs
    other = {i for i in ids if is_selected(i, 0.1, "other@1")}
    assert other != picked and len(picked & other) < 0.03 * len(ids)  # salts decorrelate suites
    assert not any(is_selected(i, 0.0, "s@1") for i in ids[:2000]) and all(
        is_selected(i, 1.0, "s@1") for i in ids[:2000]
    )


async def test_selection_ignores_outcomes_tenant_data_and_arrival_order() -> None:
    rng = random.Random(3)
    base = [completed(i) for i in range(400)]
    varied = [
        dataclasses.replace(
            r,
            trace=dataclasses.replace(
                r.trace,
                exit_reason=rng.choice(["completed", "failed", "policy_denied"]),
                output=rng.choice([None, "x", "bad answer"]),
            ),
        )
        for r in base
    ]
    cfg = dataclasses.replace(CFG, rate=0.25)
    a, _, _ = sampler(base, config=cfg)
    b, _, _ = sampler(list(reversed(varied)), config=cfg)
    assert {r.run_id for r in a.select(base)} == {
        r.run_id for r in b.select(list(reversed(varied)))
    }


def test_hourly_cap_keeps_the_lowest_positions_and_is_order_independent() -> None:
    runs = [completed(i, hour=10) for i in range(200)] + [
        completed(i + 1000, hour=11) for i in range(200)
    ]
    cfg = dataclasses.replace(CFG, rate=1.0, max_per_hour=5)
    s1, _, _ = sampler(runs, config=cfg)
    s2, _, _ = sampler(runs, config=cfg)
    got1 = s1.select(runs)
    shuffled = random.Random(1).sample(runs, len(runs))
    got2 = s2.select(shuffled)
    assert len(got1) == 10 and {r.run_id for r in got1} == {r.run_id for r in got2}
    for hour in ("T10", "T11"):
        in_hour = [r for r in runs if hour in r.completed_at]
        want = sorted(in_hour, key=lambda r: (sample_position(r.run_id, CFG.suite_ref), r.run_id))[
            :5
        ]
        assert {r.run_id for r in want} == {r.run_id for r in got1 if hour in r.completed_at}
    assert s1.stats.capped == 390
    # a later batch in the same hour sees the hour already full
    assert s1.select([completed(5000, hour=10)]) == []
    assert len(s1.select([completed(5001, hour=12)])) == 1


async def test_zero_cap_and_zero_rate_sample_nothing() -> None:
    for cfg in (dataclasses.replace(CFG, max_per_hour=0), dataclasses.replace(CFG, rate=0.0)):
        s, hub, _ = sampler([completed(i) for i in range(20)], config=cfg)
        assert await s.poll_once() == 0
        await s.drain()
        assert hub.online_results == []


# ---- grading, redaction, containment --------------------------------------------------------------


async def test_polls_grade_selected_runs_and_post_online_results() -> None:
    s, hub, spy = sampler([completed(i) for i in range(5)])
    assert await s.poll_once() == 5
    await s.drain()
    assert len(hub.online_results) == 5 and s.stats.posted == 5
    p = hub.online_results[0]
    from test_evals_suite import WIRE  # noqa: PLC0415

    assert sorted(p) == WIRE["online_result_keys"]
    assert (
        p["mode"] == "online"
        and p["suite_ref"] == "refunds@1.0.0"
        and p["source_run_id"].startswith("run_")
    )
    assert p["blueprint"] == {"name": "claims-triage", "version": "1.0.0", "content_hash": "a" * 64}
    assert (
        p["status"] == "complete"
        and p["score"] == 1.0
        and p["provenance"]["sampling"]["rate"] == 1.0
    )
    # the same runs are not graded twice
    assert await s.poll_once() == 0
    assert len(hub.online_results) == 5


async def test_polling_does_not_wait_for_the_grader() -> None:
    s, hub, spy = sampler([completed(1)])
    spy.gate.clear()
    assert await asyncio.wait_for(s.poll_once(), 1) == 1  # returned while grading is blocked
    assert hub.online_results == []
    spy.gate.set()
    await s.drain()
    assert len(hub.online_results) == 1


async def test_phi_is_redacted_before_grading_and_before_persisting() -> None:
    raw = "Patient Jane Doe, SSN 123-45-6789, call 555-123-4567, key sk-abcdefghijklmnop1234"
    run = dataclasses.replace(completed(1, output=raw, phi=True), input_text="my name is Jane Doe")
    s, hub, spy = sampler([run])
    await s.poll_once()
    await s.drain()
    graded_trace, graded_case = spy.seen[0]
    stored = str(hub.online_results[0])
    for needle in ("123-45-6789", "555-123-4567", "sk-abcdefghijklmnop1234"):
        assert needle not in (graded_trace.output or "") and needle not in stored
    assert "Jane" not in str(graded_case.input) and "Jane" not in stored
    assert hub.online_results[0]["provenance"]["sampling"]["redacted_phi"] is True
    # a non-PHI run keeps its text but never a credential
    s2, hub2, spy2 = sampler([completed(2, output=raw)])
    await s2.poll_once()
    await s2.drain()
    assert (
        "123-45-6789" in spy2.seen[0][0].output
        and "sk-abcdefghijklmnop1234" not in spy2.seen[0][0].output
    )
    s3, _, spy3 = sampler(
        [completed(3, output=raw)], config=dataclasses.replace(CFG, redaction="always")
    )
    await s3.poll_once()
    await s3.drain()
    assert "123-45-6789" not in spy3.seen[0][0].output


async def test_other_tenants_and_blueprints_are_ignored() -> None:
    runs = [
        completed(1),
        completed(2, tenant="22222222-2222-4222-8222-222222222222"),
        completed(3, blueprint="other"),
    ]
    s, hub, _ = sampler(runs)
    assert await s.poll_once() == 1
    await s.drain()
    assert [p["source_run_id"] for p in hub.online_results] == ["run_000001"]
    assert s.stats.seen == 1
    assert (
        s.reader.calls[0]["tenant_id"] == TENANT
        and s.reader.calls[0]["blueprint"] == "claims-triage"
    )  # type: ignore[attr-defined]


async def test_failures_are_contained_and_counted() -> None:
    s, hub, spy = sampler([completed(1), completed(2)])
    spy.fail = True
    assert await s.poll_once() == 2
    await s.drain()
    assert s.stats.failed == 2 and hub.online_results == []
    s2, hub2, _ = sampler([completed(1)], sink=FakeHub(fail_online=True))
    await s2.poll_once()
    await s2.drain()
    assert s2.stats.failed == 1
    s3, _, _ = sampler(RuntimeError("log store down"))
    assert await s3.poll_once() == 0 and s3.stats.reader_errors == 1
    bad = dataclasses.replace(completed(1), run_id="not a valid id!")
    s5, hub5, _ = sampler([bad])
    await s5.poll_once()
    await s5.drain()
    assert s5.stats.skipped == 1 and hub5.online_results == []


async def test_human_graders_online_produce_pending_results_with_review_tasks() -> None:
    graders = (GraderSpec("review", "human", 1.0, {"rubric": "ok?"}),)
    hub = FakeHub()
    s = OnlineSampler(
        CFG,
        TENANT,
        Reader([completed(1)]),
        GradingEngine(),
        graders,
        hub,
        "runner-1",
        clock=FakeClock(),
    )
    await s.poll_once()
    await s.drain()
    (p,) = hub.online_results
    assert (
        p["status"] == "pending_human"
        and p["score"] is None
        and p["review_tasks"][0]["grader_id"] == "review"
    )


async def test_cursor_advances_and_lookback_is_used_first() -> None:
    s, _, _ = sampler([completed(1, hour=9), completed(2, hour=11)], lookback=timedelta(hours=2))
    first_since = s._cursor  # noqa: SLF001
    await s.poll_once()
    await s.drain()
    assert s._cursor == "2026-01-01T11:02:00.000Z" and s._cursor > first_since  # noqa: SLF001


# ---- from a real run's log ------------------------------------------------------------------------


async def real_run_events(tenant: str = TENANT) -> list[Any]:
    base = make_base_deps(FnTransport(lambda m, n: text_body("It is $5.")), ScriptedGate(allow()))
    deps = base()
    manifest = make_manifest(
        blueprint={"name": "claims-triage", "version": "1.0.0", "content_hash": "d" * 64}
    )
    result = await run_agent(manifest, "refund?", deps)
    assert result.status == "completed"
    return await deps.log.read(result.run_id)


async def test_a_completed_run_is_read_from_its_log_and_graded() -> None:
    events = await real_run_events()
    run = completed_run_from_events(events, tenant_id=TENANT)
    assert (
        run.blueprint == "claims-triage" and run.version == "1.0.0" and run.content_hash == "d" * 64
    )
    assert (
        run.trace.output == "It is $5."
        and run.trace.exit_reason == "completed"
        and run.completed_at == events[-1].ts
    )
    assert (
        run.trace.gate_decisions[0].enforcement_point == "model_call" and run.trace.latency_ms >= 0
    )
    hub = FakeHub()
    s = OnlineSampler(
        CFG, TENANT, Reader([run]), GradingEngine(), GRADERS, hub, "r", clock=FakeClock()
    )
    await s.poll_once()
    await s.drain()
    assert hub.online_results[0]["score"] == 1.0


async def test_log_reading_rejects_tampering_other_tenants_and_unfinished_runs() -> None:
    events = await real_run_events()
    with pytest.raises(ValueError, match="another tenant"):
        completed_run_from_events(events, tenant_id="22222222-2222-4222-8222-222222222222")
    forged = list(events)
    forged[3] = dataclasses.replace(
        forged[3], data={**forged[3].data, "decision": "ALLOW", "reason": "forged"}
    )
    with pytest.raises(CorruptLogError):
        completed_run_from_events(forged, tenant_id=TENANT)
    with pytest.raises(ValueError, match="not finished"):
        completed_run_from_events(events[:2], tenant_id=TENANT)


# ---- architecture ---------------------------------------------------------------------------------

FORBIDDEN = (
    "axis_runtime.gate",
    "axis_runtime.executor",
    "axis_runtime.run",
    "axis_runtime.actions",
    "axis_runtime.guard",
    "axis_runtime.approvals",
    "axis_runtime.tools",
    "axis_runtime.runserver",
    "axis_runtime.models",
    "axis_runtime.nexus",
    "axis_runtime.tki",
    "axis_runtime.temporal",
    "axis_runtime.channels",
    "axis_runtime.memory",
    "axis_runtime.mcp",
    "axis_runtime.sandbox",
    "axis_runtime.browser",
    "axis_runtime.voice.gateway",
    "axis_runtime.voice.session",
)


def _file(module: str) -> Path | None:
    if module == "axis_runtime":
        return SRC / "__init__.py"
    rel = Path(*module.split(".")[1:])
    for cand in (SRC / rel.with_suffix(".py"), SRC / rel / "__init__.py"):
        if cand.is_file():
            return cand
    return None


def _module_level_imports(tree: ast.AST) -> list[str]:
    """Modules imported when the module is executed: not those inside function bodies (lazy) and
    not under ``if TYPE_CHECKING``."""
    out: list[str] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            return
        if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.dump(node.test):
            for child in node.orelse:
                visit(child)
            return
        if isinstance(node, ast.Import):
            out.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.append(node.module)
            out.extend(f"{node.module}.{a.name}" for a in node.names)
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return out


def import_closure(module: str) -> set[str]:
    """Every axis_runtime module executed by importing ``module``: its imports (transitively) and
    the ``__init__`` of every parent package."""
    seen: set[str] = set()
    todo = [module]
    while todo:
        mod = todo.pop()
        if mod in seen or not (mod == "axis_runtime" or mod.startswith("axis_runtime.")):
            continue
        parts = mod.split(".")
        for i in range(1, len(parts) + 1):  # parent packages run first
            parent = ".".join(parts[:i])
            if parent not in seen:
                path = _file(parent)
                if path is None:
                    continue
                seen.add(parent)
                todo += _module_level_imports(ast.parse(path.read_text()))
    return seen


def forbidden_in(closure: set[str]) -> list[str]:
    return sorted(m for m in closure if any(m == f or m.startswith(f + ".") for f in FORBIDDEN))


def test_the_closure_walker_sees_what_it_should() -> None:
    assert "axis_runtime.gate" in import_closure("axis_runtime.executor")
    assert "axis_runtime.models.gateway" in import_closure(
        "axis_runtime.models.types"
    )  # via models/__init__
    assert forbidden_in(import_closure("axis_runtime.evals.runner"))


def test_the_online_sampler_imports_nothing_from_the_decision_path() -> None:
    assert forbidden_in(import_closure("axis_runtime.evals.sampler")) == []


@pytest.mark.parametrize(
    "module",
    [
        "types",
        "aggregation",
        "graders",
        "jsonschema_lite",
        "judge",
        "grading",
        "redact",
        "trace",
        "hubclient",
    ],
)
def test_pure_eval_modules_stay_off_the_decision_path(module: str) -> None:
    assert forbidden_in(import_closure(f"axis_runtime.evals.{module}")) == []


def test_only_the_run_start_modules_reach_the_gate_and_the_run_loop() -> None:
    reaching = []
    for path in sorted((SRC / "evals").glob("*.py")):
        name = path.stem
        if name != "__init__" and forbidden_in(import_closure(f"axis_runtime.evals.{name}")):
            reaching.append(name)
    assert reaching == ["isolation", "judge_backend", "runner", "suite", "worker"]


def test_the_sampler_source_has_no_write_capable_calls() -> None:
    tree = ast.parse((SRC / "evals" / "sampler.py").read_text())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
    }
    assert not names & {
        "start_agent",
        "run_agent",
        "RunDeps",
        "GateClient",
        "evaluate",
        "signal",
        "deliver",
        "perform",
    }
