"""Sentence chunking of a streaming agent reply for TTS.

Speaking starts at the first complete sentence instead of after the whole reply.  Rules: split after
``. ? !`` (and a newline) when followed by whitespace or the end of input; never after a known
abbreviation, an initial, or inside a number (``3.5``); merge fragments shorter than ``min_chars``
into the next one; and cut an over-long sentence at the last comma or space before ``max_chars`` so
playback is never starved by a run-on.
"""

from __future__ import annotations

import re

_ABBREVIATIONS = frozenset(
    {
        "mr",
        "mrs",
        "ms",
        "dr",
        "prof",
        "sr",
        "jr",
        "st",
        "vs",
        "etc",
        "e.g",
        "i.e",
        "no",
        "inc",
        "ltd",
    }
)
_END = re.compile(r"[.?!]+[\"')\]]*$")


class SentenceChunker:
    def __init__(self, *, min_chars: int = 12, max_chars: int = 240) -> None:
        if min_chars < 1 or max_chars < min_chars:
            raise ValueError("need 1 <= min_chars <= max_chars")
        self.min_chars = min_chars
        self.max_chars = max_chars
        self._buf = ""
        self._carry = ""

    def feed(self, delta: str) -> list[str]:
        self._buf += delta
        out: list[str] = []
        while True:
            cut = self._find_cut(final=False)
            if cut is None:
                break
            sentence, self._buf = self._buf[:cut].strip(), self._buf[cut:].lstrip()
            if sentence:
                self._emit(sentence, out)
        return out

    def flush(self) -> list[str]:
        out: list[str] = []
        while self._buf.strip():
            cut = self._find_cut(final=True)
            if cut is None:
                cut = len(self._buf)
            sentence, self._buf = self._buf[:cut].strip(), self._buf[cut:].lstrip()
            if sentence:
                self._emit(sentence, out)
        self._buf = ""
        if self._carry:
            out.append(self._carry)
            self._carry = ""
        return out

    def _emit(self, sentence: str, out: list[str]) -> None:
        """A fragment shorter than ``min_chars`` waits and joins the next sentence."""
        joined = f"{self._carry} {sentence}".strip() if self._carry else sentence
        if len(joined) < self.min_chars:
            self._carry = joined
        else:
            self._carry = ""
            out.append(joined)

    # ---- internals -----------------------------------------------------------------------
    def _find_cut(self, *, final: bool) -> int | None:
        buf = self._buf
        for i, ch in enumerate(buf):
            if ch == "\n" and buf[:i].strip():
                return i + 1
            if ch not in ".?!":
                continue
            j = i + 1
            while j < len(buf) and buf[j] in ".?!\"')]":
                j += 1
            at_end = j >= len(buf)
            if at_end and not final and "." in buf[i:j]:
                return None  # cannot tell "3." from "3.5" yet: wait for more text
            if not at_end and not buf[j].isspace():
                continue  # inside a token: 3.5, a.b, example.com
            if not self._is_boundary(buf[:j]):
                continue
            return j
        if len(buf) > self.max_chars:
            return self._force_cut()
        return None

    def _is_boundary(self, head: str) -> bool:
        if not _END.search(head):
            return False
        word = head.rstrip(".?!\"')]").rsplit(None, 1)[-1].lower() if head.strip() else ""
        if head.rstrip().endswith(("?", "!")):
            return True
        if word in _ABBREVIATIONS:
            return False
        return not (len(word) == 1 and word.isalpha())  # an initial: "J. Smith"

    def _force_cut(self) -> int:
        window = self._buf[: self.max_chars]
        for sep in (", ", "; ", " "):
            idx = window.rfind(sep)
            if idx >= self.min_chars:
                return idx + len(sep)
        return self.max_chars


_MARKDOWN = re.compile(r"[*_`#>~|]+")
_URL = re.compile(r"https?://\S+")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁠﻿]")


def speakable(text: str) -> str:
    """``text`` as it should be sent to TTS: no markup, links, control or invisible characters."""
    out = _URL.sub("link", text)
    out = _CONTROL.sub("", out)
    out = _MARKDOWN.sub("", out)
    return re.sub(r"\s+", " ", out).strip()
