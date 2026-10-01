"""The seams of the voice pipeline.

``SttProvider`` / ``TtsProvider`` are what the session talks to.  The production implementations
(``gated.GatedSttProvider`` / ``gated.GatedTtsProvider``) run every open through the
ActionExecutor and the ModelGateway's speech plane; the deterministic ``fakes`` implement them
directly (they make no network call, so there is nothing to gate).  ``AudioTransport`` is the
SIP/WebRTC gateway seam.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol, runtime_checkable

from axis_runtime.voice.types import (
    AudioFrame,
    CallInfo,
    SttConfig,
    SttEvent,
    TransportEvent,
    TtsChunk,
    TtsConfig,
)


class SttStream(Protocol):
    """One live recognition session: audio chunks in, transcript events out."""

    async def send_audio(self, frame: AudioFrame) -> None: ...

    def events(self) -> AsyncIterator[SttEvent]:
        """Transcript events in arrival order; ends when the stream is finished or closed."""
        ...

    async def finish(self) -> None:
        """No more audio will come: flush pending hypotheses."""
        ...

    async def aclose(self) -> None: ...


class SttProvider(Protocol):
    async def open(self, config: SttConfig) -> SttStream: ...


@runtime_checkable
class TtsStream(Protocol):
    """Audio for one synthesis request.  ``cancel`` is idempotent and stops the provider call."""

    def chunks(self) -> AsyncIterator[TtsChunk]: ...

    async def cancel(self) -> None: ...


class TtsProvider(Protocol):
    async def synthesize(self, text: str, config: TtsConfig) -> TtsStream: ...


class AudioTransport(Protocol):
    """The SIP/WebRTC gateway seam for ONE call: frames and DTMF in, paced audio out.

    ``send_audio`` returns once the chunk is accepted into the playout buffer and blocks while the
    buffer is full (backpressure from real time).  ``clear_output`` drops everything not yet played
    (the Twilio ``clear`` / RTP flush) and returns how many milliseconds were discarded.
    """

    info: CallInfo

    def events(self) -> AsyncIterator[TransportEvent]: ...

    async def send_audio(self, data: bytes, duration_ms: int) -> None: ...

    def queued_ms(self) -> int: ...

    async def clear_output(self) -> int: ...

    async def hangup(self, reason: str) -> None: ...
