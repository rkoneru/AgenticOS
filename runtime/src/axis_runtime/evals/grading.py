"""Grading engine: dispatch a suite's graders over one (case, trace).

Deterministic graders are pure; model graders go through a ``JudgeGrader`` (whose backend is the
gated ModelGateway path); human graders produce a ``pending`` grade and a review task. This module
has no run-path imports so the online sampler can use it without reaching decision code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from axis_runtime.evals.graders import grade_deterministic
from axis_runtime.evals.judge import JudgeGrader, with_phi
from axis_runtime.evals.redact import names_in, redact_text, redact_value
from axis_runtime.evals.types import CaseTrace, EvalCase, Grade, GraderSpec


class CaseGrader(Protocol):
    """What the runner and the online sampler need: grade one case with the suite's graders."""

    async def grade_case(
        self,
        graders: Sequence[GraderSpec],
        case: EvalCase,
        trace: CaseTrace,
        *,
        seed: int,
        phi: bool,
    ) -> list[Grade]: ...


@dataclass(frozen=True)
class ReviewTask:
    """What a human reviewer sees. Redacted before it leaves the runner."""

    case_id: str
    grader_id: str
    rubric: str
    input: Any
    output: str | None
    expected: Any = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "grader_id": self.grader_id,
            "rubric": self.rubric,
            "input": self.input,
            "output": self.output,
            "expected": self.expected,
        }


def review_task(spec: GraderSpec, case: EvalCase, trace: CaseTrace, *, phi: bool) -> ReviewTask:
    cfg = spec.config
    names = names_in(case.input_text) if phi else []
    return ReviewTask(
        case_id=case.id,
        grader_id=spec.id,
        rubric=redact_text(str(cfg.get("rubric", "")), phi=phi),
        input=redact_value(case.input, phi=phi, names=names),
        output=None if trace.output is None else redact_text(trace.output, phi=phi, names=names),
        expected=redact_value(case.expected, phi=phi, names=names)
        if cfg.get("include_expected")
        else None,
    )


class GradingEngine:
    def __init__(self, judge: JudgeGrader | None = None) -> None:
        self._judge = judge

    async def grade_case(
        self,
        graders: Sequence[GraderSpec],
        case: EvalCase,
        trace: CaseTrace,
        *,
        seed: int,
        phi: bool,
    ) -> list[Grade]:
        out: list[Grade] = []
        for spec in graders:
            if spec.kind == "deterministic":
                out.append(grade_deterministic(spec, case, trace))
            elif spec.kind == "model":
                if self._judge is None:
                    out.append(Grade(spec.id, "model", "ungraded", 0.0, "no_judge_backend"))
                else:
                    out.append(await self._judge.grade(with_phi(spec, phi), case, trace, seed=seed))
            else:
                out.append(Grade(spec.id, "human", "pending", 0.0, "awaiting_human_review"))
        return out


def pending_tasks(
    graders: Sequence[GraderSpec],
    case: EvalCase,
    trace: CaseTrace,
    grades: Sequence[Grade],
    *,
    phi: bool,
) -> list[ReviewTask]:
    by_id: Mapping[str, GraderSpec] = {g.id: g for g in graders}
    return [
        review_task(by_id[g.grader_id], case, trace, phi=phi)
        for g in grades
        if g.status == "pending"
    ]
