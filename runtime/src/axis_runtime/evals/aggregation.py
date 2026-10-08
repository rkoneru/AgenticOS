"""Score aggregation, implemented ONCE (docs/spec/evals-runner.md section 6).

The hub recomputes the same numbers from the per-case grades and refuses a run whose reported
scores differ; both sides load ``runtime/tests/fixtures/eval-aggregation-vectors.json``. Every
step is plain IEEE-754 double arithmetic in a fixed order so a TypeScript port produces
bit-identical results:

* cases are visited in ascending case id (ASCII, see ``types.ID_RE``), graders in suite order;
* a grade that is not ``scored`` (ungraded, error, missing) counts as 0.0 (fail closed), never as
  "excluded": a judge that cannot answer must not raise the mean by shrinking the denominator;
* a case whose run never produced a trace (infrastructure failure after retries) is listed in
  ``errored``: it scores 0 everywhere AND the run cannot pass (``errored_cases`` failure);
* ``pending`` (a human grade is outstanding) makes the whole aggregate ``pending_human``;
* outputs are rounded half-up to 6 decimals with ``floor(x * 1e6 + 0.5) / 1e6``.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from axis_runtime.evals.types import ID_RE, Grade, GraderSpec

SCALE = 1_000_000.0


def r6(x: float) -> float:
    """Round a value in [0, 1] half-up to 6 decimals (``Math.floor(x * 1e6 + 0.5) / 1e6``)."""
    return int(min(1.0, max(0.0, x)) * SCALE + 0.5) / SCALE


class AggregationError(ValueError):
    """The inputs cannot be aggregated (duplicate ids, unknown grader, no graders)."""


@dataclass(frozen=True)
class Aggregate:
    status: Literal["complete", "pending_human"]
    overall: float | None
    per_grader: Mapping[str, float] = field(default_factory=dict)
    per_case: Mapping[str, float] = field(default_factory=dict)
    passed: bool | None = None
    failures: tuple[str, ...] = ()
    ungraded: int = 0

    def to_wire(self) -> dict[str, object]:
        return {
            "status": self.status,
            "overall": self.overall,
            "per_grader": dict(self.per_grader),
            "per_case": dict(self.per_case),
            "passed": self.passed,
            "failures": list(self.failures),
            "ungraded": self.ungraded,
        }


def _valid_score(grade: Grade) -> float | None:
    """The grade's score when it counts, ``None`` when it counts as 0.0."""
    if grade.status != "scored":
        return None
    s = grade.score
    if isinstance(s, bool) or not isinstance(s, int | float) or s != s or not 0.0 <= s <= 1.0:
        return None
    return float(s)


def aggregate(
    graders: Sequence[GraderSpec],
    grades: Mapping[str, Mapping[str, Grade]],
    *,
    pass_threshold: float,
    min_case_score: float | None = None,
    errored: Collection[str] = frozenset(),
) -> Aggregate:
    """``grades[case_id][grader_id]`` -> ``Aggregate``.

    A missing (case, grader) cell counts as ungraded (0.0). A grader id in ``grades`` that the suite
    does not declare is an error: a result set that does not match its suite is never summarised."""
    if not graders:
        raise AggregationError("a suite needs at least one grader")
    ids = [g.id for g in graders]
    if len(set(ids)) != len(ids):
        raise AggregationError("duplicate grader id")
    for case_id, row in grades.items():
        if not ID_RE.match(case_id):
            raise AggregationError("invalid case id")
        unknown = set(row) - set(ids)
        if unknown:
            raise AggregationError("grade for a grader the suite does not declare")
    case_ids = sorted(grades)
    if not set(errored) <= set(grades):
        raise AggregationError("errored case is not in the results")

    if any(row[g].status == "pending" for row in grades.values() for g in row):
        return Aggregate("pending_human", None)

    total_weight = 0.0
    for g in graders:
        total_weight += g.weight

    ungraded = 0
    per_case_raw: dict[str, float] = {}
    sums = dict.fromkeys(ids, 0.0)
    for case_id in case_ids:
        weighted = 0.0
        for g in graders:
            cell = grades[case_id].get(g.id)
            s = None if cell is None else _valid_score(cell)
            if s is None:
                ungraded += 1
                s = 0.0
            weighted += g.weight * s
            sums[g.id] += s
        per_case_raw[case_id] = weighted / total_weight

    n = len(case_ids)
    failures: list[str] = []
    if n == 0:
        return Aggregate("complete", 0.0, dict.fromkeys(ids, 0.0), {}, False, ("no_cases",), 0)

    per_grader_raw = {gid: sums[gid] / n for gid in ids}
    overall_sum = 0.0
    for g in graders:
        overall_sum += g.weight * per_grader_raw[g.id]
    overall = r6(overall_sum / total_weight)
    per_grader = {gid: r6(v) for gid, v in per_grader_raw.items()}
    per_case = {cid: r6(v) for cid, v in per_case_raw.items()}

    if overall < pass_threshold:
        failures.append("below_pass_threshold")
    if min_case_score is not None:
        low = [cid for cid in case_ids if per_case[cid] < min_case_score]
        if low:
            failures.append(f"min_case_score:{','.join(low[:5])}")
    for g in graders:
        if g.min_mean is not None and per_grader[g.id] < g.min_mean:
            failures.append(f"grader_min_mean:{g.id}")
    if errored:
        failures.append(f"errored_cases:{','.join(sorted(errored)[:5])}")
    return Aggregate(
        "complete", overall, per_grader, per_case, not failures, tuple(failures), ungraded
    )
