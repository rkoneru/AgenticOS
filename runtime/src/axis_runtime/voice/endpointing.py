"""Turn detection: when has the caller finished speaking?

A pure state machine over STT events and a millisecond clock (no timers of its own): the session
asks ``deadline_ms`` when to look again and calls ``poll`` at that time.  The silence needed depends
on what was said, so a sentence that clearly ended answers sooner than one that trails off:

* text ending in ``. ? !``                     -> ``terminal_silence_ms``
* text ending in ``, ; : ...`` or a dangling
  conjunction / filler (``and``, ``but``, ``um``) -> ``incomplete_silence_ms``
* anything else                                 -> ``silence_ms``

A turn is also forced to end after ``max_utterance_ms`` of continuous activity so a noisy line
cannot hold the floor forever.  Silence is measured on the voice clock from the last ACTIVITY (an
STT event with text, or a provider speech-start), not from audio timestamps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from axis_runtime.voice.types import SttEvent, SttEventKind

_DANGLING = frozenset(
    {
        "and",
        "but",
        "or",
        "so",
        "because",
        "if",
        "then",
        "um",
        "uh",
        "umm",
        "uhh",
        "er",
        "like",
        "the",
        "a",
        "an",
        "to",
        "of",
        "my",
        "is",
    }
)
_WORD = re.compile(r"[A-Za-z']+")


@dataclass(frozen=True)
class EndpointingConfig:
    silence_ms: int = 700
    terminal_silence_ms: int = 350
    incomplete_silence_ms: int = 1200
    max_utterance_ms: int = 30_000
    min_chars: int = 1

    def __post_init__(self) -> None:
        if min(self.silence_ms, self.terminal_silence_ms, self.incomplete_silence_ms) < 0:
            raise ValueError("endpointing silences must be >= 0")
        if self.max_utterance_ms < 1 or self.min_chars < 1:
            raise ValueError("max_utterance_ms and min_chars must be >= 1")


def classify(text: str) -> str:
    """``terminal`` | ``incomplete`` | ``neutral`` for the text so far."""
    stripped = text.rstrip()
    if not stripped:
        return "neutral"
    if stripped.endswith(("...", "…")):
        return "incomplete"
    if stripped[-1] in ".?!":
        return "terminal"
    if stripped[-1] in ",;:-":
        return "incomplete"
    words = _WORD.findall(stripped)
    if words and words[-1].lower() in _DANGLING:
        return "incomplete"
    return "neutral"


class TurnDetector:
    def __init__(self, config: EndpointingConfig | None = None) -> None:
        self.config = config or EndpointingConfig()
        self.reset()

    def reset(self) -> None:
        self._committed: list[str] = []
        self._partial = ""
        self._started_ms: int | None = None
        self._last_activity_ms: int | None = None
        self._first_ts_ms: int | None = None

    # ---- input ---------------------------------------------------------------------------
    def on_stt(self, event: SttEvent, now_ms: int) -> None:
        text = event.text.strip()
        if event.kind is SttEventKind.SPEECH_START:
            self._activity(now_ms, event.ts_ms)
            return
        if not text:
            return  # an empty hypothesis is not speech
        self._activity(now_ms, event.ts_ms)
        if event.kind is SttEventKind.FINAL:
            self._committed.append(text)
            self._partial = ""
        else:
            self._partial = text

    def _activity(self, now_ms: int, ts_ms: int) -> None:
        if self._started_ms is None:
            self._started_ms = now_ms
            self._first_ts_ms = ts_ms
        self._last_activity_ms = now_ms

    # ---- state ---------------------------------------------------------------------------
    @property
    def text(self) -> str:
        parts = [*self._committed, self._partial] if self._partial else list(self._committed)
        return " ".join(parts).strip()

    @property
    def active(self) -> bool:
        return self._started_ms is not None

    @property
    def started_ms(self) -> int | None:
        return self._started_ms

    @property
    def first_ts_ms(self) -> int | None:
        return self._first_ts_ms

    @property
    def last_activity_ms(self) -> int | None:
        return self._last_activity_ms

    def silence_needed_ms(self) -> int:
        cfg = self.config
        kind = classify(self.text)
        if kind == "terminal":
            return cfg.terminal_silence_ms
        if kind == "incomplete":
            return cfg.incomplete_silence_ms
        return cfg.silence_ms

    def deadline_ms(self) -> int | None:
        """Clock time at which the turn ends if nothing else is heard (None: nothing to end)."""
        if self._last_activity_ms is None or self._started_ms is None:
            return None
        quiet = self._last_activity_ms + self.silence_needed_ms()
        return min(quiet, self._started_ms + self.config.max_utterance_ms)

    def poll(self, now_ms: int) -> str | None:
        """The finished utterance (and reset) if the turn is over at ``now_ms``, else None."""
        deadline = self.deadline_ms()
        if deadline is None or now_ms < deadline:
            return None
        text = self.text
        if len(text) < self.config.min_chars:
            # activity without words (a provider speech-start, then nothing): not a turn
            self.reset()
            return None
        self.reset()
        return text
