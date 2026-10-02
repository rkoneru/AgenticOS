"""Credential handling: secrets never reach repr(), str(), logs, pickles or exception messages."""

from __future__ import annotations

import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"

_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_API_KEY_HEADER = re.compile(r"(x-axis-api-key[\"']?\s*[:=]\s*[\"']?)[^\s\"',}]+", re.IGNORECASE)


class Secret:
    """Holds a credential; only :meth:`reveal` returns it."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    def __str__(self) -> str:
        return REDACTED

    def __reduce__(self) -> tuple[type[Secret], tuple[str]]:
        # copy/pickle must not carry the credential
        return (Secret, (REDACTED,))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(REDACTED)


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Remove known secret values and credential-shaped substrings from free text."""
    out = text
    for s in secrets:
        if len(s) >= 4:
            out = out.replace(s, REDACTED)
    out = _BEARER.sub(f"Bearer {REDACTED}", out)
    return _API_KEY_HEADER.sub(rf"\g<1>{REDACTED}", out)
