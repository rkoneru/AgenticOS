import pytest
from axis_runtime import FAIL_CLOSED_DECISION, Decision, coerce_decision


def test_fail_closed_is_deny() -> None:
    assert FAIL_CLOSED_DECISION is Decision.DENY


@pytest.mark.parametrize("d", list(Decision))
def test_known_values_round_trip(d: Decision) -> None:
    assert coerce_decision(d.value) is d


@pytest.mark.parametrize("v", [None, 1, "allow", "", {}])
def test_unknown_values_deny(v: object) -> None:
    assert coerce_decision(v) is Decision.DENY
