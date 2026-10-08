"""PHI canary (runtime half): the same PHI-shaped values the TypeScript harness writes (services/data-governance/src/phi-canary.ts)
must not survive the runtime's PHI-mode redaction, including obfuscated variants. Voice transcript and eval-trace paths."""

from __future__ import annotations

import re
import unicodedata

import pytest

from axis_runtime.evals.redact import redact_value
from axis_runtime.voice.phi import redact_transcript

CANARIES = [
    ("patient ssn 123-45-6789 on file", "123456789"),
    ("ssn 234 56 7890 given verbally", "234567890"),
    ("ssn １３５-７９-２４６８ typed", "135792468"),
    ("ssn 246-80-13​57 pasted", "246801357"),
    ("ssn 357.91.2468 scanned", "357912468"),
    ("social security number 468013579", "468013579"),
    ("chart MRN: 99887766 reviewed", "99887766"),
    ("contact zelda.canary@clinic-example.org today", "zelda.canary@clinic-example.org"),
    ("mail zelda+rx@clinic-example.org", "zelda+rx@clinic-example.org"),
    ("call (415) 555-0134 after noon", "4155550134"),
    ("call +1 415 555 0177", "4155550177"),
]


def leaks(text: str, core: str) -> bool:
    t = "".join(c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf").lower()
    if not core.isdigit():
        return core in t
    return re.search(r"[\s.\-()]*".join(core), t) is not None


@pytest.mark.parametrize(("text", "core"), CANARIES)
def test_voice_transcript_redaction(text: str, core: str) -> None:
    assert not leaks(redact_transcript(text), core)


@pytest.mark.parametrize(("text", "core"), CANARIES)
def test_eval_value_redaction_in_phi_mode(text: str, core: str) -> None:
    out = redact_value({"input": text, "nested": [text], "trace": {"say": text}}, phi=True)
    assert not leaks(repr(out), core)


def test_introduced_name_is_removed_later_in_the_call() -> None:
    first = "my name is Zelda Quentin Canary"
    from axis_runtime.voice.phi import learn_names

    names = learn_names(first)
    assert names
    assert "zelda" not in redact_transcript("Thanks Zelda, one moment", names).lower()


def test_without_phi_mode_nothing_is_redacted_but_secrets_are() -> None:
    out = redact_value("ssn 123-45-6789 api_key=abcdef123456", phi=False)
    assert "123-45-6789" in out
    assert "abcdef123456" not in out
