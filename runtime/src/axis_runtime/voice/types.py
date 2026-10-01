"""Plain data types of the voice pipeline (no behaviour, no IO)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


@dataclass(frozen=True)
class AudioFrame:
    """One slice of caller audio (or, for the fakes, a script directive riding in ``data``)."""

    data: bytes
    ts_ms: int  # capture time on the call timeline (ms since the call connected)
    seq: int = 0
    duration_ms: int = 20
    sample_rate: int = 8000
    encoding: str = "pcm_s16le"


class SttEventKind(StrEnum):
    PARTIAL = "partial"  # interim hypothesis; may be revised
    FINAL = "final"  # the provider committed this segment
    SPEECH_START = "speech_start"  # voice activity began (provider VAD), no text yet


@dataclass(frozen=True)
class SttEvent:
    kind: SttEventKind
    text: str = ""
    ts_ms: int = 0  # audio timestamp the event refers to (start of the speech it reports)
    end_ms: int | None = None
    confidence: float | None = None


@dataclass(frozen=True)
class SttConfig:
    language: str = "en-US"
    sample_rate: int = 8000
    encoding: str = "pcm_s16le"
    interim_results: bool = True


@dataclass(frozen=True)
class TtsConfig:
    voice: str = ""
    language: str = "en-US"
    sample_rate: int = 8000
    encoding: str = "pcm_s16le"


@dataclass(frozen=True)
class TtsChunk:
    audio: bytes
    duration_ms: int
    #: Characters of the requested text the provider says are covered once this chunk has played
    #: (alignment data). Most providers give none; the session then estimates from durations.
    chars_through: int | None = None


@dataclass(frozen=True)
class CallInfo:
    call_id: str
    direction: Direction
    from_number: str = ""
    to_number: str = ""
    tenant_id: str = ""


@dataclass(frozen=True)
class Connected:
    info: CallInfo


@dataclass(frozen=True)
class Frame:
    frame: AudioFrame


@dataclass(frozen=True)
class Dtmf:
    digit: str
    ts_ms: int = 0


@dataclass(frozen=True)
class Hangup:
    reason: str = "caller_hangup"


TransportEvent = Connected | Frame | Dtmf | Hangup


class TurnRole(StrEnum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"  # notices, greetings and prompts the pipeline itself speaks
    DTMF = "dtmf"


@dataclass(frozen=True)
class VoiceTurn:
    """One transcript turn.  ``text`` is what was SAID (for an interrupted agent turn: what was
    actually spoken before the barge-in); ``intended_text`` is what the agent wanted to say."""

    turn: int
    role: TurnRole
    text: str
    start_ms: int
    end_ms: int
    truncated: bool = False
    intended_text: str = ""


@dataclass
class StageMetrics:
    """Latency of one user turn through the pipeline, in milliseconds on the voice clock."""

    turn: int
    endpoint_silence_ms: int = 0  # silence waited before the turn was declared over
    stt_ms: int = 0  # first speech activity -> utterance finalised
    agent_first_ms: int | None = None  # utterance finalised -> first agent text
    agent_total_ms: int | None = None  # utterance finalised -> agent finished
    tts_first_byte_ms: int | None = None  # first sentence handed to TTS -> first audio sent
    response_ms: int | None = None  # utterance finalised -> first audio out
    perceived_ms: int | None = None  # end of caller speech -> first audio out
    extra: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class CallSummary:
    call_id: str
    reason: str
    duration_ms: int
    turns: int
    barge_ins: int
    frames_dropped: int
    consent_granted: bool | None  # None: no consent step was required
    metrics: tuple[StageMetrics, ...] = ()
    barge_in_latencies_ms: tuple[int, ...] = ()
