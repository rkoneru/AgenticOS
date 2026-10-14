"""Free-text PHI net for the run log (Phase 9; NEEDS #363).

A PHI run (``manifest.phi``) persists its event log. Policy redaction paths
(``ALLOW_WITH_REDACTION``) only cover what a tenant named; a tool result, a tool error that
echoes its arguments or the agent's final output can still carry SSN-, MRN-, phone- or
email-shaped free text. ``scrub_event_data`` is applied by ``RunRecorder.record`` BEFORE the
event is sealed, so neither the log, a replay nor the exported trace holds the raw value (the
live agent turn still sees it in memory).

It is the same heuristic net as the voice transcript and the eval hub
(``voice.phi.redact_transcript``: fullwidth digits, zero-width characters, labelled identifiers,
SSN/phone/email shapes, plus credential scrubbing). A net, not proof (docs/NEEDS.md).
Structural values (ids, hashes, versions) are never touched, so a sealed event stays foldable.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

#: keys whose values are identifiers, hashes, versions or enumerations: structure, never free text
_STRUCTURAL_KEYS = frozenset(
    {
        "id",
        "pid",
        "ppid",
        "run_id",
        "trace_id",
        "span_id",
        "action_id",
        "audit_event_id",
        "approval_id",
        "policy_version",
        "enforcement_point",
        "action",
        "decision",
        "name",
        "agent",
        "blueprint",
        "version",
        "from",
        "to",
        "trigger",
        "signal",
        "provider",
        "model",
        "finish_reason",
        "exit_reason",
        "tenant_id",
    }
)
_STRUCTURAL_SUFFIXES = ("_id", "_ids", "_hash", "_sha256", "_at", "_version")
_OPAQUE = re.compile(r"^[0-9a-fA-F-]{16,}$")  # uuid / hex digest


def _structural(key: str, value: str) -> bool:
    return (
        key in _STRUCTURAL_KEYS or key.endswith(_STRUCTURAL_SUFFIXES) or bool(_OPAQUE.match(value))
    )


def _scrub(value: Any, key: str) -> Any:
    if isinstance(value, str):
        if _structural(key, value):
            return value
        from axis_runtime.evals.redact import redact_text

        return redact_text(value, phi=True)
    if isinstance(value, list):
        return [_scrub(v, key) for v in value]
    if isinstance(value, Mapping):
        return {k: _scrub(v, str(k)) for k, v in value.items()}
    return value


def scrub_event_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """``data`` with every free-text string redacted (dict keys are schema and are kept)."""
    return {k: _scrub(v, str(k)) for k, v in data.items()}
