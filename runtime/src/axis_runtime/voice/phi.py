"""Transcript redaction for PHI tenants.

A heuristic net, not a guarantee (docs/NEEDS.md): it removes what a phone call usually carries that
identifies a person (numbers spoken as digits or as words, e-mail addresses, dates, street
addresses, labelled identifiers, "my name is ...") and drops invisible characters that could hide
text from the patterns.  It runs BEFORE persistence, so neither the run log nor the transcript the
session keeps holds the raw text; the raw text exists only in memory for the live agent turn.

``PhiMode.OMIT`` is the strict alternative: nothing but the hash and length of the redacted text is
stored.
"""

from __future__ import annotations

import re
from enum import StrEnum

REDACTED = "[REDACTED]"

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿­]")
_DIGIT_WORDS = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine|double|triple)"
_MONTH = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|"
    r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
)
_STREET = r"(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|boulevard|blvd|court|ct|way|place|pl)"

_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # labelled identifiers: "member id is AB12345", "MRN: 123"
        r"\b(?:mrn|medical record(?: number)?|member id|policy(?: number| no)?|account(?: number)?|"
        r"insurance id|patient id|claim(?: number)?|ssn|social(?: security(?: number)?)?)\b"
        r"\s*(?:is|number|no\.?|:|#)?\s*[A-Za-z0-9][A-Za-z0-9\- ]{2,24}",
        # e-mail, written and spoken
        r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
        r"\b[\w.+-]+\s+at\s+[\w-]+(?:\s+dot\s+[\w-]+)*\s+dot\s+(?:com|org|net|edu|gov|io|co)\b",
        # dates: 3/4/1980, 1980-03-04, March 3rd 1980, 3rd of March
        r"\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b",
        r"\b\d{4}-\d{2}-\d{2}\b",
        rf"\b{_MONTH}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+\d{{2,4}})?\b",
        rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH}\b(?:,?\s+\d{{2,4}})?",
        # street addresses
        rf"\b\d{{1,6}}\s+(?:[A-Za-z0-9']+\s+){{1,4}}{_STREET}\b\.?",
        # "my name is Jane Q Public"
        r"\b(?:my name is|my name's|i am|i'm|this is|name is|speaking with)\s+"
        r"[A-Za-z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,3}",
        # digit runs: phone / SSN / card / MRN, with separators; also Unicode digits
        r"\+?\d(?:[\d\s().-]{4,}\d)",
        r"\b\d{5,}\b",
        # digits spoken as words (5 or more in a row)
        rf"(?:\b{_DIGIT_WORDS}\b[\s,.-]*){{5,}}",
    )
)


class PhiMode(StrEnum):
    REDACT = "redact"
    OMIT = "omit"


def redact_transcript(text: str) -> str:
    """``text`` with the sensitive spans replaced by ``[REDACTED]`` (idempotent)."""
    out = _INVISIBLE.sub("", text)
    for pattern in _PATTERNS:
        out = pattern.sub(REDACTED, out)
    out = re.sub(r"(?:\[REDACTED\][\s,.-]*){2,}", REDACTED + " ", out)
    return out.strip()
