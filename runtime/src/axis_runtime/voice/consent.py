"""Recording / transcription consent for voice calls.

A call that is transcribed (every call here: the transcript is the audit record) must tell the
caller first when the agent's manifest declares a transparency notice (``risk.transparency_notice``)
or the tenant's policy requires it.  Three ways to ask:

* ``NOTICE`` - play the notice; staying on the line afterwards is the consent.
* ``DTMF`` - play the notice and require a keypress (``accept_digit``) within ``timeout_ms``.
* ``SPEECH`` - play the notice and require a spoken yes (STT runs, nothing is kept until yes).

When consent is required the session REFUSES to continue without it: the notice must have been
played completely, and with DTMF/SPEECH an accept must have been heard.  Nothing the caller says
before that reaches the transcript, the agent or the audit trail (NOTICE and DTMF never even open
STT).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

DEFAULT_NOTICE = (
    "This call is with an automated assistant and will be transcribed. "
    "If you do not wish to continue, please hang up now."
)


class ConsentMode(StrEnum):
    NONE = "none"
    NOTICE = "notice"
    DTMF = "dtmf"
    SPEECH = "speech"


class ConsentConfigError(ValueError):
    """The consent configuration cannot satisfy a requirement (fail closed: the call is refused)."""


@dataclass(frozen=True)
class ConsentPolicy:
    mode: ConsentMode = ConsentMode.NONE
    notice: str = ""
    required: bool = False
    accept_digit: str = "1"
    decline_digit: str = "2"
    accept_phrases: tuple[str, ...] = (
        "yes",
        "i agree",
        "i consent",
        "okay",
        "ok",
        "sure",
        "go ahead",
    )
    decline_phrases: tuple[str, ...] = ("no", "i do not", "i don't", "stop", "hang up")
    timeout_ms: int = 15_000

    def __post_init__(self) -> None:
        if self.required and self.mode is ConsentMode.NONE:
            raise ConsentConfigError("consent is required but the mode is none")
        if self.mode is not ConsentMode.NONE and not self.notice.strip():
            raise ConsentConfigError("a consent mode needs a non-empty notice")
        if self.timeout_ms < 1:
            raise ConsentConfigError("consent timeout must be positive")

    @property
    def interactive(self) -> bool:
        return self.mode in (ConsentMode.DTMF, ConsentMode.SPEECH)


def resolve_consent(
    *,
    manifest_notice: str | None,
    tenant_requires: bool = False,
    configured: ConsentPolicy | None = None,
) -> ConsentPolicy:
    """The effective policy.  It is REQUIRED when the manifest carries a transparency notice, the
    tenant requires it, or the operator configured it as required; a required policy can be made
    stricter (DTMF/SPEECH) but never switched off, and its notice falls back to the manifest's, then
    the default text."""
    cfg = configured or ConsentPolicy()
    required = bool(manifest_notice and manifest_notice.strip()) or tenant_requires or cfg.required
    mode = cfg.mode
    if required and mode is ConsentMode.NONE:
        mode = ConsentMode.NOTICE
    if not required and mode is ConsentMode.NONE:
        return ConsentPolicy()
    notice = cfg.notice.strip() or (manifest_notice or "").strip() or DEFAULT_NOTICE
    return ConsentPolicy(
        mode=mode,
        notice=notice,
        required=required,
        accept_digit=cfg.accept_digit,
        decline_digit=cfg.decline_digit,
        accept_phrases=cfg.accept_phrases,
        decline_phrases=cfg.decline_phrases,
        timeout_ms=cfg.timeout_ms,
    )


def _norm(text: str) -> str:
    return re.sub(r"[^a-z' ]+", " ", text.lower()).strip()


def classify_consent_speech(text: str, policy: ConsentPolicy) -> str | None:
    """``accept`` / ``decline`` / None (unclear).  A sentence with both an accept and a decline
    phrase is unclear: only an unambiguous answer grants consent."""
    t = f" {_norm(text)} "
    accept = any(f" {_norm(p)} " in t for p in policy.accept_phrases)
    decline = any(f" {_norm(p)} " in t for p in policy.decline_phrases)
    if accept and decline:
        return None
    if decline:
        return "decline"
    if accept:
        return "accept"
    return None
