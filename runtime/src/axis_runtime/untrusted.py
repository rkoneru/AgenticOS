"""Quoting for end-user text that is placed into an agent prompt.

Customer chat messages and caller speech are DATA. Two things make quoted data dangerous in a
prompt: a fence the text can close (``<<<`` / ``>>>``) and line structure the text can forge (a
newline followed by ``Agent: ...`` or ``SYSTEM: ...`` reads as another speaker). ``one_line``
removes both for text quoted inline (conversation history); ``defang_fence`` is for the fenced
current message, whose line structure is kept.
"""

from __future__ import annotations

FENCE = ("<<<", ">>>")


def defang_fence(text: str) -> str:
    """The text cannot close the fence it is quoted in."""
    for mark in FENCE:
        text = text.replace(mark, " ".join(mark))
    return text


def one_line(text: str, *, max_chars: int = 2000) -> str:
    """Collapse all whitespace (newlines, tabs, Unicode line separators) to single spaces, defang
    the fence, and cap the length."""
    return defang_fence(" ".join(text.split()))[:max_chars]
