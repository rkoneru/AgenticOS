"""Deterministic STT / TTS fakes (no audio, no network).

``ScriptedStt`` reads its transcript from the audio itself: a frame whose payload starts with
``MAGIC`` carries a JSON directive (``partial`` / ``final`` / ``speech_start`` plus the text) which
the fake turns into the matching ``SttEvent`` after ``latency_ms`` of clock time; any other frame
is plain "audio" and produces nothing.  ``caller_script`` builds such frames from plain text, so a
whole phone call is a list of frames with timestamps.

``FakeTts`` emits identifiable chunks (``TTS|<request>|<n>``) paced by nothing but the transport's
playout buffer, with a configurable first-byte delay, and records cancellations.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from axis_runtime.voice.clock import VoiceClock
from axis_runtime.voice.types import (
    AudioFrame,
    SttConfig,
    SttEvent,
    SttEventKind,
    TtsChunk,
    TtsConfig,
)

MAGIC = b"AXIS-STT\x00"
_END = object()


def directive_frame(
    kind: SttEventKind, text: str = "", *, ts_ms: int = 0, seq: int = 0, end_ms: int | None = None
) -> AudioFrame:
    body = json.dumps({"k": kind.value, "t": text, "e": end_ms}, separators=(",", ":"))
    return AudioFrame(MAGIC + body.encode(), ts_ms=ts_ms, seq=seq)


def plain_frame(ts_ms: int, seq: int = 0, duration_ms: int = 20) -> AudioFrame:
    return AudioFrame(b"\x00" * (duration_ms * 16), ts_ms=ts_ms, seq=seq, duration_ms=duration_ms)


def caller_script(text: str, *, start_ms: int = 0, word_ms: int = 250) -> list[AudioFrame]:
    """Frames for a caller saying ``text``: one growing PARTIAL per word, then a FINAL."""
    words = text.split()
    frames: list[AudioFrame] = []
    for i in range(1, len(words) + 1):
        frames.append(
            directive_frame(
                SttEventKind.PARTIAL,
                " ".join(words[:i]),
                ts_ms=start_ms + (i - 1) * word_ms,
                seq=len(frames),
            )
        )
    if words:
        end = start_ms + len(words) * word_ms
        frames.append(
            directive_frame(
                SttEventKind.FINAL, text.strip(), ts_ms=start_ms, seq=len(frames), end_ms=end
            )
        )
    return frames


def decode_directive(frame: AudioFrame) -> SttEvent | None:
    if not frame.data.startswith(MAGIC):
        return None
    try:
        raw = json.loads(frame.data[len(MAGIC) :])
        return SttEvent(
            SttEventKind(raw["k"]),
            str(raw.get("t", "")),
            ts_ms=frame.ts_ms,
            end_ms=raw.get("e"),
        )
    except (ValueError, KeyError, TypeError):
        return None


class ScriptedSttStream:
    def __init__(self, clock: VoiceClock, latency_ms: int) -> None:
        self._clock = clock
        self._latency = latency_ms
        self._queue: asyncio.Queue[tuple[int, SttEvent | object]] = asyncio.Queue()
        self.frames: list[AudioFrame] = []
        self.finished = False
        self.closed = False

    async def send_audio(self, frame: AudioFrame) -> None:
        if self.closed:
            raise ConnectionError("stt stream closed")
        self.frames.append(frame)
        event = decode_directive(frame)
        if event is not None:
            self._queue.put_nowait((self._clock.now_ms() + self._latency, event))

    async def events(self) -> AsyncIterator[SttEvent]:
        while True:
            ready_at, item = await self._queue.get()
            if item is _END:
                return
            wait = ready_at - self._clock.now_ms()
            if wait > 0:
                await self._clock.sleep_ms(wait)
            if isinstance(item, SttEvent):
                yield item

    async def finish(self) -> None:
        self.finished = True
        self._queue.put_nowait((0, _END))

    async def aclose(self) -> None:
        self.closed = True
        self._queue.put_nowait((0, _END))


@dataclass
class FakeSttProvider:
    clock: VoiceClock
    latency_ms: int = 0
    fail_open: Exception | None = None
    opens: list[SttConfig] = field(default_factory=list)
    streams: list[ScriptedSttStream] = field(default_factory=list)

    async def start(self, config: SttConfig) -> ScriptedSttStream:
        if self.fail_open is not None:
            raise self.fail_open
        self.opens.append(config)
        stream = ScriptedSttStream(self.clock, self.latency_ms)
        self.streams.append(stream)
        return stream


class FakeTtsStream:
    def __init__(self, provider: FakeTtsProvider, index: int, text: str) -> None:
        self._p = provider
        self.index = index
        self.text = text
        self.cancelled = False
        self.emitted = 0

    async def chunks(self) -> AsyncIterator[TtsChunk]:
        p = self._p
        if p.first_byte_ms:
            await p.clock.sleep_ms(p.first_byte_ms)
        total_ms = max(p.chunk_ms, p.ms_per_char * len(self.text))
        n_chunks = -(-total_ms // p.chunk_ms)
        for n in range(n_chunks):
            if self.cancelled:
                return
            dur = min(p.chunk_ms, total_ms - n * p.chunk_ms)
            through = None
            if p.report_chars:
                through = min(len(self.text), round(len(self.text) * (n + 1) / n_chunks))
            self.emitted += 1
            yield TtsChunk(f"TTS|{self.index}|{n}".encode(), dur, through)

    async def cancel(self) -> None:
        if not self.cancelled:
            self.cancelled = True
            self._p.cancelled.append(self.index)


@dataclass
class FakeTtsProvider:
    clock: VoiceClock
    ms_per_char: int = 60
    chunk_ms: int = 100
    first_byte_ms: int = 40
    report_chars: bool = False
    fail_on: str | None = None  # substring of the text that makes synthesize raise
    requests: list[str] = field(default_factory=list)
    configs: list[TtsConfig] = field(default_factory=list)
    streams: list[FakeTtsStream] = field(default_factory=list)
    cancelled: list[int] = field(default_factory=list)

    async def synthesize(self, text: str, config: TtsConfig) -> FakeTtsStream:
        if self.fail_on is not None and self.fail_on in text:
            raise ConnectionError("tts unavailable")
        self.requests.append(text)
        self.configs.append(config)
        stream = FakeTtsStream(self, len(self.requests) - 1, text)
        self.streams.append(stream)
        return stream

    @staticmethod
    def parse(audio: bytes) -> tuple[int, int]:
        _, req, n = audio.decode().split("|")
        return int(req), int(n)
