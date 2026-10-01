"""Transcript and call-event persistence through the run log.

``TranscriptWriter`` is the ONLY place voice text reaches storage.  Redaction happens here, before
an event is built (so there is no code path that persists raw PHI text), and audio is never stored:
only its SHA-256 and length.  Events are appended with ``RunRecorder.record``, i.e. the run's own
hash-chained, replayable log (docs/spec/voice.md; mirroring them into the audit chain is NEEDS).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from axis_runtime.events import EventType, RunRecorder
from axis_runtime.voice.phi import PhiMode, redact_transcript
from axis_runtime.voice.types import StageMetrics, TurnRole, VoiceTurn


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TranscriptWriter:
    def __init__(
        self,
        recorder: RunRecorder,
        pid: str,
        call_id: str,
        *,
        phi: bool = False,
        phi_mode: PhiMode = PhiMode.REDACT,
    ) -> None:
        self._rec = recorder
        self._pid = pid
        self.call_id = call_id
        self.phi = phi
        self.phi_mode = phi_mode
        #: What was persisted (redacted in PHI mode), in order.  Never holds raw PHI text.
        self.turns: list[VoiceTurn] = []

    def persisted_text(self, text: str) -> str:
        """The form of ``text`` that may be stored under the current PHI setting."""
        if not self.phi:
            return text
        if self.phi_mode is PhiMode.OMIT:
            return ""
        return redact_transcript(text)

    async def add_turn(
        self, turn: VoiceTurn, *, audio_sha256: str | None = None, audio_bytes: int = 0
    ) -> None:
        text = self.persisted_text(turn.text)
        stored = VoiceTurn(
            turn.turn,
            turn.role,
            text,
            turn.start_ms,
            turn.end_ms,
            turn.truncated,
            "",  # the intended text is never kept: only its length (below)
        )
        self.turns.append(stored)
        await self._rec.record(
            EventType.VOICE_TURN,
            self._pid,
            {
                "call_id": self.call_id,
                "turn": turn.turn,
                "role": turn.role.value,
                "text": text,
                "redacted": self.phi,
                "truncated": turn.truncated,
                "start_ms": turn.start_ms,
                "end_ms": turn.end_ms,
                "text_sha256": _sha(text),
                "text_chars": len(text),
                "audio_sha256": audio_sha256,
                "audio_bytes": audio_bytes,
                "intended_chars": len(turn.intended_text or turn.text)
                if turn.role is TurnRole.AGENT
                else 0,
            },
        )

    async def call_event(
        self,
        phase: str,
        *,
        reason: str | None = None,
        duration_ms: int | None = None,
        detail: Mapping[str, str | int | bool | None] | None = None,
    ) -> None:
        await self._rec.record(
            EventType.VOICE_CALL,
            self._pid,
            {
                "call_id": self.call_id,
                "phase": phase,
                "reason": reason,
                "duration_ms": duration_ms,
                "detail": dict(detail or {}),
            },
        )

    async def stage(self, turn: int, stage: str, latency_ms: int) -> None:
        await self._rec.record(
            EventType.VOICE_STAGE,
            self._pid,
            {"call_id": self.call_id, "turn": turn, "stage": stage, "latency_ms": latency_ms},
        )

    async def metrics(self, m: StageMetrics) -> None:
        """One ``voice_stage`` event per measured stage of a turn."""
        pairs = (
            ("stt", m.stt_ms),
            ("endpoint", m.endpoint_silence_ms),
            ("agent", m.agent_first_ms),
            ("tts", m.tts_first_byte_ms),
            ("response", m.response_ms),
            ("perceived", m.perceived_ms),
        )
        for stage, value in pairs:
            if value is not None:
                await self.stage(m.turn, stage, value)
