"""Incremental Server-Sent Events parser (WHATWG HTML section 9.2)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SseEvent:
    event: str
    data: str
    id: str


class SseParser:
    """Feed decoded text in arbitrary chunks; get the events each chunk completes.

    ``retry`` (ms) and ``last_event_id`` persist across events, as the specification requires.
    """

    def __init__(self) -> None:
        self.last_event_id = ""
        self.retry: int | None = None
        self._buf = ""
        self._started = False
        self._skip_lf = False
        self._data: list[str] = []
        self._event = ""
        self._pending_id: str | None = None

    def push(self, chunk: str) -> list[SseEvent]:
        text = self._buf + chunk
        self._buf = ""
        if not self._started and text:
            self._started = True
            if text[0] == "﻿":
                text = text[1:]
        out: list[SseEvent] = []
        start = 0
        for i, c in enumerate(text):
            if self._skip_lf:
                self._skip_lf = False
                if c == "\n":
                    start = i + 1  # LF half of a CRLF whose CR ended the previous line
                    continue
            if c not in "\r\n":
                continue
            line = text[start:i]
            start = i + 1
            if c == "\r":
                self._skip_lf = True
            ev = self._line(line)
            if ev is not None:
                out.append(ev)
        self._buf = text[start:]
        return out

    def end(self) -> None:
        """End of stream: an unterminated final event is discarded."""
        self._buf = ""
        self._skip_lf = False
        self._data = []
        self._event = ""
        self._pending_id = None

    def _line(self, line: str) -> SseEvent | None:
        if line == "":
            if self._pending_id is not None:
                self.last_event_id = self._pending_id
            self._pending_id = None
            had_data = bool(self._data)
            ev = SseEvent(self._event or "message", "\n".join(self._data), self.last_event_id)
            self._data = []
            self._event = ""
            return ev if had_data else None
        if line.startswith(":"):
            return None
        name, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if name == "data":
            self._data.append(value)
        elif name == "event":
            self._event = value
        elif name == "id":
            if "\0" not in value:
                self._pending_id = value
        elif name == "retry" and value.isascii() and value.isdigit():
            self.retry = int(value)
        return None
