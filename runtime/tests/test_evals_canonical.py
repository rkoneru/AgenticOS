"""Canonical JSON parity with the Eval Hub (services/eval-hub/src/canonical.ts): the same vectors run on both sides."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from axis_runtime.evals.types import canonical, js_number

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "eval-canonical-vectors.json").read_text()
)["vectors"]


@pytest.mark.parametrize("v", VECTORS, ids=[v["json"][:30] for v in VECTORS])
def test_shared_vectors(v: dict[str, str]) -> None:
    assert canonical(json.loads(v["json"])) == v["canonical"]


def test_integral_floats_hash_like_integers() -> None:
    assert canonical({"n": 1.0}) == canonical({"n": 1})


def test_non_finite_and_foreign_types_are_refused() -> None:
    for bad in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            canonical(bad)
    with pytest.raises(TypeError):
        canonical({1: 2})
    with pytest.raises(TypeError):
        canonical(object())


def test_js_number_beyond_safe_integers_goes_through_a_double() -> None:
    assert js_number(2**53 + 2) == "9007199254740994"
    assert js_number(10**22) == "1e+22"
