"""Online sampler: grade a deterministic sample of COMPLETED production runs, off the decision path.

* READ-ONLY. It reads finished runs through an injected ``RunLogReader`` (the run log / audit
  rows) and writes only to the hub. It imports nothing from the gate, the executor, the run loop,
  the actions or the model layer (architecture test), so it has no way to block, allow, alter or
  slow a production action; results never feed back into any decision.
* DETERMINISTIC selection by hash of the run id (salted per suite): the same run is always in or
  out for a given rate, whatever its outcome, so sampling cannot be biased toward (or away from)
  failures. ``max_per_hour`` then caps the selected runs per hour bucket, lowest hash first.
* REDACTED before grading and before anything is persisted: credentials always, PHI when the run
  is PHI or the configuration asks for it.
* ASYNCHRONOUS and failure-contained: a grader, reader or hub failure is counted and logged; it
  never raises into the caller and never touches the run that was sampled.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Protocol

from axis_runtime.evals.aggregation import aggregate
from axis_runtime.evals.grading import CaseGrader, pending_tasks
from axis_runtime.evals.redact import redact_text, redact_value
from axis_runtime.evals.trace import trace_from_events, trace_wire
from axis_runtime.evals.types import (
    ID_RE,
    RUNNER_VERSION,
    CaseTrace,
    EvalCase,
    GraderSpec,
    OnlineConfig,
)
from axis_runtime.events import Clock, CorruptLogError, RunEvent, SystemClock, format_ts

log = logging.getLogger("axis_runtime.evals.sampler")

MAX_PERSISTED_OUTPUT_CHARS = 4000


def sample_position(run_id: str, salt: str) -> float:
    """A stable value in [0, 1) derived ONLY from the run id and the salt. Nothing about the run's
    outcome, tenant data or timing goes in."""
    digest = hashlib.sha256(f"axis-eval-sample:v1:{salt}:{run_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def is_selected(run_id: str, rate: float, salt: str) -> bool:
    return sample_position(run_id, salt) < rate


@dataclass(frozen=True)
class CompletedRun:
    """A finished production run as the reader exposes it. ``input_text`` is whatever the log
    kept (the run log stores only an input hash, so it is usually ``None``)."""

    tenant_id: str
    run_id: str
    blueprint: str
    version: str
    content_hash: str
    completed_at: str
    trace: CaseTrace
    phi: bool = False
    input_text: str | None = None


class RunLogReader(Protocol):
    async def completed_runs(
        self, *, tenant_id: str, blueprint: str, since: str, limit: int
    ) -> list[CompletedRun]:
        """Runs of the tenant and blueprint that ended at or after ``since``, oldest first."""
        ...


class ResultSink(Protocol):
    async def post_online_results(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


def completed_run_from_events(
    events: Sequence[RunEvent], *, tenant_id: str, phi: bool = False
) -> CompletedRun:
    """Fold a stored run log (verifying its hash chain) into a ``CompletedRun``. Raises
    ``CorruptLogError`` for a tampered log, ``ValueError`` for a run that is not finished or that
    belongs to another tenant."""
    trace = trace_from_events(events)
    first = events[0]
    if first.data.get("tenant_id") != tenant_id:
        raise ValueError("run belongs to another tenant")
    if trace.exit_reason == "running":
        raise ValueError("run is not finished")
    return CompletedRun(
        tenant_id=tenant_id,
        run_id=first.run_id,
        blueprint=str(first.data.get("blueprint", "")),
        version=str(first.data.get("version", "")),
        content_hash=str(first.data.get("content_hash", "")),
        completed_at=events[-1].ts,
        trace=trace,
        phi=phi,
    )


@dataclass
class SamplerStats:
    seen: int = 0
    selected: int = 0
    capped: int = 0
    skipped: int = 0
    posted: int = 0
    failed: int = 0
    reader_errors: int = 0


@dataclass
class OnlineSampler:
    config: OnlineConfig
    tenant_id: str
    reader: RunLogReader
    grader: CaseGrader
    graders: Sequence[GraderSpec]
    sink: ResultSink
    runner_id: str
    clock: Clock = field(default_factory=SystemClock)
    concurrency: int = 2
    batch: int = 100
    lookback: timedelta = timedelta(hours=1)
    stats: SamplerStats = field(default_factory=SamplerStats)

    def __post_init__(self) -> None:
        self._seen: set[str] = set()
        self._hour_counts: dict[str, int] = {}
        self._cursor = format_ts(self.clock.now() - self.lookback)
        self._sem = asyncio.Semaphore(self.concurrency)
        self._tasks: set[asyncio.Task[None]] = set()

    # ---- selection (pure given the batch) --------------------------------------------------
    def select(self, runs: Sequence[CompletedRun]) -> list[CompletedRun]:
        """The runs of this batch to grade: sampled, not seen before, within the hourly cap."""
        salt = self.config.suite_ref
        fresh = [r for r in runs if r.run_id not in self._seen]
        picked = [r for r in fresh if is_selected(r.run_id, self.config.rate, salt)]
        picked.sort(key=lambda r: (sample_position(r.run_id, salt), r.run_id))
        out: list[CompletedRun] = []
        for r in picked:
            bucket = r.completed_at[:13]  # YYYY-MM-DDTHH
            if self._hour_counts.get(bucket, 0) >= self.config.max_per_hour:
                self.stats.capped += 1
                continue
            self._hour_counts[bucket] = self._hour_counts.get(bucket, 0) + 1
            out.append(r)
        return out

    # ---- redaction + payload ---------------------------------------------------------------
    def _phi(self, run: CompletedRun) -> bool:
        return run.phi or self.config.redaction == "always"

    def redacted(self, run: CompletedRun) -> tuple[CaseTrace, EvalCase]:
        phi = self._phi(run)
        out = run.trace.output
        trace = dataclasses.replace(
            run.trace, output=None if out is None else redact_text(out, phi=phi)
        )
        case = EvalCase(
            id=run.run_id,
            input=redact_value(run.input_text, phi=phi) if run.input_text is not None else "",
            metadata={"source": "online"},
        )
        return trace, case

    async def _grade_and_post(self, run: CompletedRun) -> None:
        async with self._sem:
            try:
                if not ID_RE.match(run.run_id):
                    self.stats.skipped += 1
                    return
                trace, case = self.redacted(run)
                phi = self._phi(run)
                seed = int.from_bytes(hashlib.sha256(run.run_id.encode()).digest()[:4], "big")
                grades = await self.grader.grade_case(
                    self.graders, case, trace, seed=seed & 0x7FFFFFFF, phi=phi
                )
                agg = aggregate(
                    self.graders,
                    {case.id: {g.grader_id: g for g in grades}},
                    pass_threshold=0.0,
                )
                tasks = pending_tasks(self.graders, case, trace, grades, phi=phi)
                payload = {
                    "mode": "online",
                    "runner_id": self.runner_id,
                    "suite_ref": self.config.suite_ref,
                    "source_run_id": run.run_id,
                    "blueprint": {
                        "name": run.blueprint,
                        "version": run.version,
                        "content_hash": run.content_hash,
                    },
                    "completed_at": run.completed_at,
                    "sampled_at": format_ts(self.clock.now()),
                    "status": agg.status,
                    "score": agg.per_case.get(case.id),
                    "grades": [g.to_wire() for g in grades],
                    "output": None
                    if trace.output is None
                    else trace.output[:MAX_PERSISTED_OUTPUT_CHARS],
                    "trace": trace_wire(trace),
                    "review_tasks": [t.to_wire() for t in tasks],
                    "provenance": {
                        "runner_version": RUNNER_VERSION,
                        "sampling": {
                            "rate": self.config.rate,
                            "max_per_hour": self.config.max_per_hour,
                            "redaction": self.config.redaction,
                            "redacted_phi": phi,
                        },
                    },
                }
                await self.sink.post_online_results(payload)
                self.stats.posted += 1
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - sampling must never affect anything else
                self.stats.failed += 1
                log.warning("online grading failed for run %s", run.run_id, exc_info=True)

    # ---- loop ------------------------------------------------------------------------------
    async def poll_once(self) -> int:
        """Read new completed runs, select, and start grading them in the background. Returns the
        number selected. Never raises."""
        try:
            runs = await self.reader.completed_runs(
                tenant_id=self.tenant_id,
                blueprint=self.config.blueprint,
                since=self._cursor,
                limit=self.batch,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            self.stats.reader_errors += 1
            log.warning("run log read failed", exc_info=True)
            return 0
        runs = [
            r
            for r in runs
            if r.tenant_id == self.tenant_id and r.blueprint == self.config.blueprint
        ]
        self.stats.seen += len(runs)
        chosen = self.select(runs)
        self._seen.update(r.run_id for r in runs)
        if runs:
            self._cursor = max(self._cursor, max(r.completed_at for r in runs))
        self.stats.selected += len(chosen)
        for r in chosen:
            task = asyncio.create_task(self._grade_and_post(r))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        return len(chosen)

    async def drain(self) -> None:
        """Wait for the grading started so far (tests, shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)


__all__ = [
    "CompletedRun",
    "CorruptLogError",
    "OnlineSampler",
    "ResultSink",
    "RunLogReader",
    "SamplerStats",
    "completed_run_from_events",
    "is_selected",
    "sample_position",
]
