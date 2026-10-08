"""Redaction applied BEFORE anything is graded by a model or persisted by the hub.

Two layers, both heuristic (docs/NEEDS.md): a credential scrubber that always runs (a judge prompt
or a stored case result must never carry a key, whatever the dataset's PHI flag says), and the
voice pipeline's PHI redactor for PHI data (``dataset.phi``, a PHI blueprint, or a sampling
configuration asking for it). ``redact_value`` walks JSON so a structured input is covered too.
"""

from __future__ import annotations

import re
from typing import Any

from axis_runtime.voice.phi import REDACTED, redact_transcript

_SECRETS = tuple(
    re.compile(p)
    for p in (
        r"\bsk-[A-Za-z0-9_-]{16,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*\S{6,}",
    )
)


def scrub_secrets(text: str) -> str:
    for pattern in _SECRETS:
        text = pattern.sub(REDACTED, text)
    return text


def redact_text(text: str, *, phi: bool) -> str:
    """Credentials always; PHI patterns when ``phi``."""
    out = scrub_secrets(text)
    return redact_transcript(out) if phi else out


def redact_value(value: Any, *, phi: bool) -> Any:
    """``value`` with every string redacted (dict keys are kept: they are schema, not data)."""
    if isinstance(value, str):
        return redact_text(value, phi=phi)
    if isinstance(value, list):
        return [redact_value(v, phi=phi) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v, phi=phi) for k, v in value.items()}
    return value
