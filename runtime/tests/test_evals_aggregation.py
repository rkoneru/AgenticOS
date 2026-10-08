"""Aggregation: the shared vectors, the algorithm's invariants (randomised property tests with a
fixed seed), and refusal of malformed result sets."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
from axis_runtime.evals.aggregation import AggregationError, aggregate, r6
from axis_runtime.evals.types import Grade, GraderSpec

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "eval-aggregation-vectors.json").read_text()
)["vectors"]


def grader(g: dict[str, Any]) -> GraderSpec:
    return GraderSpec(g["id"], "deterministic", float(g["weight"]), {}, g.get("min_mean"))


def grades_of(cases: dict[str, dict[str, dict[str, Any]]]) -> dict[str, dict[str, Grade]]:
    return {
        cid: {
            gid: Grade(gid, "deterministic", cell["status"], float(cell["score"]))
            for gid, cell in row.items()
        }
        for cid, row in cases.items()
    }


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_shared_vectors(vec: dict[str, Any]) -> None:
    suite = vec["suite"]
    agg = aggregate(
        [grader(g) for g in suite["graders"]],
        grades_of(vec["cases"]),
        pass_threshold=suite["pass_threshold"],
        min_case_score=suite["min_case_score"],
        errored=vec["errored"],
    )
    exp = vec["expected"]
    assert agg.to_wire() == exp


def test_vectors_cover_the_rules() -> None:
    names = " ".join(v["name"] for v in VECTORS)
    for needle in ("weights", "min_case_score", "ungraded", "pending", "errored", "no cases"):
        assert needle in names


def test_r6_rounds_half_up_and_clamps() -> None:
    assert r6(0.0) == 0.0 and r6(1.0) == 1.0
    assert r6(0.1234564) == 0.123456
    assert r6(0.1234568) == 0.123457
    assert r6(-3) == 0.0 and r6(9) == 1.0


def _random_case(rng: random.Random, graders: list[str]) -> dict[str, Grade]:
    row = {}
    for gid in graders:
        r = rng.random()
        if r < 0.1:
            continue  # missing cell
        status = "scored" if r < 0.8 else rng.choice(["ungraded", "error"])
        row[gid] = Grade(gid, "deterministic", status, rng.choice([0.0, 1.0, rng.random()]))
    return row


def test_properties_of_random_result_sets() -> None:
    rng = random.Random(20260101)
    for _ in range(300):
        ng = rng.randint(1, 4)
        specs = [
            GraderSpec(f"g{i}", "deterministic", rng.choice([1, 2, 0.5, 3])) for i in range(ng)
        ]
        ids = [s.id for s in specs]
        grades = {f"c{i:02d}": _random_case(rng, ids) for i in range(rng.randint(1, 8))}
        a = aggregate(specs, grades, pass_threshold=0.5)
        # bounded
        assert a.overall is not None and 0.0 <= a.overall <= 1.0
        assert all(0.0 <= v <= 1.0 for v in [*a.per_case.values(), *a.per_grader.values()])
        # order independence: shuffling the case rows changes nothing
        shuffled = dict(rng.sample(list(grades.items()), len(grades)))
        assert aggregate(specs, shuffled, pass_threshold=0.5) == a
        # the overall is the weighted mean of the per-grader means (within rounding)
        w = sum(s.weight for s in specs)
        expect = sum(s.weight * a.per_grader[s.id] for s in specs) / w
        assert abs(a.overall - expect) < 2e-6
        # turning any non-scored/missing cell into a perfect score never lowers the result;
        # replacing any score by 0 never raises it
        cid = rng.choice(list(grades))
        gid = rng.choice(ids)
        worse = {**grades, cid: {**grades[cid], gid: Grade(gid, "deterministic", "scored", 0.0)}}
        assert aggregate(specs, worse, pass_threshold=0.5).overall <= a.overall  # type: ignore[operator]
        better = {**grades, cid: {**grades[cid], gid: Grade(gid, "deterministic", "scored", 1.0)}}
        assert aggregate(specs, better, pass_threshold=0.5).overall >= a.overall  # type: ignore[operator]


def test_a_failing_status_never_scores_better_than_zero() -> None:
    spec = [GraderSpec("g", "deterministic")]
    for status in ("ungraded", "error"):
        row = {"a": {"g": Grade("g", "deterministic", status, 1.0)}}  # type: ignore[arg-type]
        agg = aggregate(spec, row, pass_threshold=0.1)
        assert agg.overall == 0.0 and agg.passed is False and agg.ungraded == 1


def test_scores_that_are_not_numbers_in_range_count_as_zero() -> None:
    spec = [GraderSpec("g", "deterministic")]
    for bad in (float("nan"), float("inf"), -0.1, 1.1, True):
        row = {"a": {"g": Grade("g", "deterministic", "scored", bad)}}  # type: ignore[arg-type]
        assert aggregate(spec, row, pass_threshold=0.1).overall == 0.0


def test_malformed_result_sets_are_refused() -> None:
    g = GraderSpec("g", "deterministic")
    ok = {"a": {"g": Grade("g", "deterministic", "scored", 1.0)}}
    with pytest.raises(AggregationError):
        aggregate([], ok, pass_threshold=0.5)
    with pytest.raises(AggregationError):
        aggregate([g, g], ok, pass_threshold=0.5)
    with pytest.raises(AggregationError):
        aggregate([g], {"a": {"other": Grade("other", "deterministic", "scored", 1.0)}}, pass_threshold=0.5)
    with pytest.raises(AggregationError):
        aggregate([g], {"bad id!": {}}, pass_threshold=0.5)
    with pytest.raises(AggregationError):
        aggregate([g], ok, pass_threshold=0.5, errored=["zzz"])


def test_threshold_is_inclusive() -> None:
    g = [GraderSpec("g", "deterministic")]
    rows = {
        "a": {"g": Grade("g", "deterministic", "scored", 1.0)},
        "b": {"g": Grade("g", "deterministic", "scored", 0.0)},
    }
    assert aggregate(g, rows, pass_threshold=0.5).passed is True
    assert aggregate(g, rows, pass_threshold=0.500001).passed is False
