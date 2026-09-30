"""Gate decision outcomes (kept in a leaf module so every other module can import it)."""

from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"


FAIL_CLOSED_DECISION = Decision.DENY


def coerce_decision(value: object) -> Decision:
    """Coerce an untrusted value to a Decision; anything unknown fails closed to DENY."""
    if isinstance(value, str):
        try:
            return Decision(value)
        except ValueError:
            return FAIL_CLOSED_DECISION
    return FAIL_CLOSED_DECISION
