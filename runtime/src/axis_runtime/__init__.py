"""AXIS agent runtime."""

from axis_runtime._decision import FAIL_CLOSED_DECISION, Decision, coerce_decision

__version__ = "0.0.0"

__all__ = [
    "FAIL_CLOSED_DECISION",
    "Decision",
    "__version__",
    "all_action_types",
    "coerce_decision",
]


def all_action_types() -> tuple[type, ...]:
    """Every concrete ``Action`` subclass currently defined (used by the bypass guard)."""
    from axis_runtime.actions import all_action_types as _all

    return _all()
