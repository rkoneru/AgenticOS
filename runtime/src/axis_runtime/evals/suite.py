"""Execute one queued eval run end to end and build the submission.

refuse (stale/mismatched inputs) -> run every case through the real run path -> grade -> aggregate
-> payload with per-case results and provenance. Scores come from executed graders only; the hub
recomputes the aggregate from the per-case grades with the same algorithm and rejects a payload
whose reported numbers differ.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from axis_runtime.evals.aggregation import Aggregate, aggregate
from axis_runtime.evals.grading import GradingEngine, ReviewTask, pending_tasks
from axis_runtime.evals.hubclient import RunnerIdentity
from axis_runtime.evals.isolation import EvalModePolicy, IdSource
from axis_runtime.evals.judge import JudgeBackend, JudgeGrader
from axis_runtime.evals.redact import redact_text
from axis_runtime.evals.runner import CaseOutcome, CaseRunner, RunnerConfig
from axis_runtime.evals.trace import trace_wire
from axis_runtime.evals.types import (
    AGGREGATION_VERSION,
    RUNNER_VERSION,
    Dataset,
    Grade,
    QueuedRun,
    Suite,
)
from axis_runtime.events import Clock, SystemClock, format_ts
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.run import RunDeps

MAX_PERSISTED_OUTPUT_CHARS = 4000


class RunRefused(RuntimeError):  # noqa: N818 - a refusal, reported to the hub as a failed run
    """The run's inputs do not match what the hub queued (stale blueprint, wrong tenant, altered
    dataset). Nothing is executed; the hub records a failed run, which the release gate treats as
    a block."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Execution:
    payload: dict[str, Any]
    aggregate: Aggregate
    review_tasks: list[ReviewTask]
    outcomes: list[CaseOutcome]
    grades: dict[str, list[Grade]]


def runner_config(suite: Suite) -> RunnerConfig:
    s = suite.settings
    base = RunnerConfig()

    def num(key: str, default: Any) -> Any:
        v = s.get(key, default)
        return default if isinstance(v, bool) or not isinstance(v, int | float) else v

    return RunnerConfig(
        concurrency=int(num("concurrency", base.concurrency)),
        case_timeout_seconds=float(num("case_timeout_seconds", base.case_timeout_seconds)),
        max_infra_retries=int(num("max_infra_retries", base.max_infra_retries)),
        max_tokens=num("max_tokens", None),
        max_cost_usd=num("max_cost_usd", None),
        max_tool_calls=num("max_tool_calls", None),
    )


def eval_policy(suite: Suite) -> EvalModePolicy:
    allowed = suite.settings.get("allow_sandboxed_targets") or []
    if not isinstance(allowed, list):
        allowed = []
    return EvalModePolicy(frozenset(a for a in allowed if isinstance(a, str)))


def _usd(micro: int) -> str:
    return str(Decimal(micro) / Decimal(1_000_000))


class SuiteExecutor:
    def __init__(
        self,
        *,
        base_deps: Callable[[], RunDeps],
        tenant_id: str,
        identity: RunnerIdentity,
        judge_backend: JudgeBackend | None = None,
        ids: IdSource | None = None,
        clock: Clock | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        nonce: Callable[[], str] | None = None,
    ) -> None:
        self._base_deps = base_deps
        self._tenant_id = tenant_id
        self._identity = identity
        self._judge_backend = judge_backend
        self._ids = ids
        self._clock = clock or SystemClock()
        self._monotonic = monotonic
        self._nonce = nonce

    def check_inputs(
        self, run: QueuedRun, suite: Suite, dataset: Dataset, manifest: RuntimeManifest
    ) -> None:
        if run.tenant_id != self._tenant_id:
            raise RunRefused("tenant_mismatch")
        if run.suite_ref != suite.ref or suite.dataset_ref != dataset.ref:
            raise RunRefused("suite_or_dataset_mismatch")
        bp = run.blueprint
        if (manifest.name, manifest.version) != (bp.name, bp.version):
            raise RunRefused("blueprint_mismatch")
        if manifest.content_hash != bp.content_hash:
            raise RunRefused(
                "blueprint_hash_mismatch"
            )  # stale: the manifest is not what was queued
        if dataset.computed_hash() != dataset.version_hash:
            raise RunRefused(
                "dataset_hash_mismatch"
            )  # the hub served different cases than it signed

    async def execute(
        self, run: QueuedRun, suite: Suite, dataset: Dataset, manifest: RuntimeManifest
    ) -> Execution:
        self.check_inputs(run, suite, dataset, manifest)
        started = format_ts(self._clock.now())
        runner = CaseRunner(
            self._base_deps,
            tenant_id=self._tenant_id,
            policy=eval_policy(suite),
            config=runner_config(suite),
            ids=self._ids,
            monotonic=self._monotonic,
        )
        judge = (
            None
            if self._judge_backend is None
            else JudgeGrader(self._judge_backend, **({"nonce": self._nonce} if self._nonce else {}))
        )
        engine = GradingEngine(judge)
        outcomes = await runner.run_all(
            manifest, dataset.cases, run_seed=run.seed, eval_run_id=run.id
        )
        grades: dict[str, list[Grade]] = {}
        tasks: list[ReviewTask] = []
        for o in outcomes:
            if o.trace is None:
                grades[o.case.id] = []
                continue
            gs = await engine.grade_case(
                suite.graders, o.case, o.trace, seed=o.seed, phi=dataset.phi
            )
            grades[o.case.id] = gs
            tasks += pending_tasks(suite.graders, o.case, o.trace, gs, phi=dataset.phi)
        errored = {o.case.id for o in outcomes if o.trace is None}
        agg = aggregate(
            suite.graders,
            {cid: {g.grader_id: g for g in gs} for cid, gs in grades.items()},
            pass_threshold=suite.pass_threshold,
            min_case_score=suite.min_case_score,
            errored=errored,
        )
        finished = format_ts(self._clock.now())
        payload = self._payload(
            run, suite, dataset, manifest, outcomes, grades, agg, started, finished
        )
        return Execution(payload, agg, tasks, outcomes, grades)

    def _payload(
        self,
        run: QueuedRun,
        suite: Suite,
        dataset: Dataset,
        manifest: RuntimeManifest,
        outcomes: Sequence[CaseOutcome],
        grades: Mapping[str, Sequence[Grade]],
        agg: Aggregate,
        started: str,
        finished: str,
    ) -> dict[str, Any]:
        agent_micro = judge_micro = tokens = judge_tokens = 0
        models: set[str] = set()
        judges: dict[str, Any] = {}
        cases: list[dict[str, Any]] = []
        for o in outcomes:
            t = o.trace
            if t is not None:
                agent_micro += t.cost_micro_usd
                tokens += t.tokens
                models |= {f"{m.provider}/{m.model}" for m in t.model_calls}
            for g in grades[o.case.id]:
                judge_micro += int(g.provenance.get("judge_cost_micro_usd", 0))
                judge_tokens += int(g.provenance.get("judge_tokens", 0))
                if "judge" in g.provenance:
                    judges[g.grader_id] = g.provenance["judge"]
                    models |= set(g.provenance["judge"].get("models", []))
            cases.append(
                {
                    "case_id": o.case.id,
                    "status": o.status,
                    "attempts": o.attempts,
                    "seed": o.seed,
                    "error": o.error,
                    "score": agg.per_case.get(o.case.id),
                    "output": None
                    if t is None or t.output is None
                    else redact_text(t.output, phi=dataset.phi)[:MAX_PERSISTED_OUTPUT_CHARS],
                    "grades": [g.to_wire() for g in grades[o.case.id]],
                    "trace": None if t is None else trace_wire(t),
                }
            )
        status = "pending_human" if agg.status == "pending_human" else "completed"
        return {
            "runner_id": self._identity.runner_id,
            "run_id": run.id,
            "mode": run.mode,
            "status": status,
            "suite_ref": suite.ref,
            "blueprint": run.blueprint.to_wire(),
            "started_at": started,
            "finished_at": finished,
            "scores": agg.to_wire(),
            "case_results": cases,
            "cost": {
                "agent_usd": _usd(agent_micro),
                "judge_usd": _usd(judge_micro),
                "total_usd": _usd(agent_micro + judge_micro),
                "tokens": tokens,
                "judge_tokens": judge_tokens,
            },
            "provenance": {
                "runner_version": RUNNER_VERSION,
                "runner_id": self._identity.runner_id,
                "aggregation_version": AGGREGATION_VERSION,
                "seed": run.seed,
                "model_ids": sorted(models),
                "blueprint_content_hash": manifest.content_hash,
                "dataset_ref": dataset.ref,
                "dataset_version_hash": dataset.version_hash,
                "suite_ref": suite.ref,
                "judges": judges,
                "eval_mode": {"allow_sandboxed": sorted(eval_policy(suite).allow_sandboxed)},
            },
        }
