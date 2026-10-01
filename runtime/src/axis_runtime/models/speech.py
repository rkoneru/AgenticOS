"""Speech plane of the ModelGateway: streaming STT and TTS through the same guarded door as chat.

Invariant 5 says only the ModelGateway talks to model providers.  STT and TTS vendors ARE model
providers (they receive the caller's voice and the agent's words), so they are reached the same way:

* ``ModelGateway.open_stt`` / ``ModelGateway.synthesize`` refuse to run unless the ActionExecutor is
  performing a gated ``SttOpen`` / ``TtsSynthesize`` action (the same tripwire as ``complete``);
* keys are the tenant's own (``SecretStore``; platform keys only where the tenant policy allows and
  never to a custom endpoint), endpoint overrides pass the SSRF guard, and a per-(tenant, provider,
  endpoint) circuit breaker applies;
* the vendor wire formats live in ``speech_vendors``; the byte-level transports are injected: the
  existing HTTP ``Transport`` for TTS and a ``WsTransport`` for streaming STT.

What the gate sees is decided per call, not per audio frame: opening an STT stream is ONE gated
action for the stream (the audio that flows afterwards is covered by it), and every TTS request is a
gated action carrying the text to be spoken.  See docs/spec/voice.md and ADR 0015.

Not built (docs/NEEDS.md): a real WebSocket transport (the seam is ``WsTransport``), retries and
fallbacks for speech, cost accounting for audio seconds / characters, resampling.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from typing import ClassVar, Protocol

from axis_runtime.models.adapters.base import (
    _STATUS_KIND,
    HttpCall,
    StreamHandle,
    _retry_after,
)
from axis_runtime.models.secrets import Secret, scrub
from axis_runtime.models.types import ErrorKind, ModelError
from axis_runtime.voice.clock import VoiceClock
from axis_runtime.voice.types import AudioFrame, SttEvent, TtsChunk

# ---- requests -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class SttRequest:
    tenant_id: str
    provider: str
    model: str
    language: str = "en-US"
    sample_rate: int = 8000
    encoding: str = "pcm_s16le"
    key_label: str = "default"
    endpoint: str | None = None
    interim_results: bool = True


@dataclass(frozen=True)
class TtsRequest:
    tenant_id: str
    provider: str
    model: str
    text: str
    voice: str = ""
    language: str = "en-US"
    sample_rate: int = 8000
    encoding: str = "pcm_s16le"
    key_label: str = "default"
    endpoint: str | None = None


# ---- transports ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class WsConnectSpec:
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    init_messages: tuple[str | bytes, ...] = ()
    timeout: float = 10.0


class WsConnection(Protocol):
    async def send(self, data: str | bytes) -> None: ...

    def messages(self) -> AsyncIterator[str | bytes]:
        """Messages from the vendor until the connection closes."""
        ...

    async def close(self) -> None: ...


class WsTransport(Protocol):
    """Opens a WebSocket.  The only place a real implementation would touch the network; none ships
    (docs/NEEDS.md), tests inject a fake."""

    async def connect(self, spec: WsConnectSpec) -> WsConnection: ...


# ---- adapters -----------------------------------------------------------------------------------


class SttAdapter(ABC):
    provider: ClassVar[str]
    default_endpoint: ClassVar[str]
    auth_optional: ClassVar[bool] = False

    @abstractmethod
    def connect_spec(self, req: SttRequest, secret: Secret | None, base_url: str) -> WsConnectSpec:
        """URL, headers and opening messages for a streaming session."""

    def encode_audio(self, frame: AudioFrame) -> str | bytes:
        return frame.data

    def finish_message(self) -> str | bytes | None:
        return None

    @abstractmethod
    def parse(self, message: str | bytes) -> list[SttEvent]:
        """Vendor message -> events.  Raises ``ModelError`` for a vendor error message."""


class TtsAdapter(ABC):
    provider: ClassVar[str]
    default_endpoint: ClassVar[str]
    auth_optional: ClassVar[bool] = False

    @abstractmethod
    def output_format(self, req: TtsRequest) -> tuple[str, int]:
        """``(encoding, sample_rate)`` of the audio the vendor call produces for ``req``."""

    @abstractmethod
    def build(self, req: TtsRequest, secret: Secret | None, base_url: str) -> HttpCall: ...

    def classify(
        self, status: int, headers: Mapping[str, str], body: bytes, secret: Secret | None
    ) -> ModelError:
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        code = ""
        if isinstance(data, dict):
            err = data.get("error", data.get("detail", data))
            if isinstance(err, dict):
                for key in ("type", "code", "status"):
                    if isinstance(err.get(key), str):
                        code = str(err[key])[:64]
                        break
        code = scrub(code, secret)
        kind = _STATUS_KIND.get(status)
        if kind is None:
            kind = ErrorKind.SERVER if status >= 500 else ErrorKind.UNKNOWN
        return ModelError(
            kind,
            self.provider,
            f"http {status}" + (f" {code}" if code else ""),
            status=status,
            retry_after=_retry_after(headers),
        )


# ---- live sessions ------------------------------------------------------------------------------


class SttSession:
    """SttStream over a vendor connection.  Event timestamps are mapped onto the voice clock: a
    vendor offset (ms since the stream started) becomes ``origin_ms + offset``."""

    def __init__(
        self,
        conn: WsConnection,
        adapter: SttAdapter,
        *,
        clock: VoiceClock | None,
        secret: Secret | None,
    ) -> None:
        self._conn = conn
        self._adapter = adapter
        self._clock = clock
        self._secret = secret
        self._origin = clock.now_ms() if clock is not None else 0
        self._closed = False

    async def send_audio(self, frame: AudioFrame) -> None:
        if self._closed:
            raise ModelError(ErrorKind.NETWORK, self._adapter.provider, "stream closed")
        try:
            await self._conn.send(self._adapter.encode_audio(frame))
        except ModelError:
            raise
        except Exception as exc:
            raise ModelError(
                ErrorKind.NETWORK, self._adapter.provider, type(exc).__name__
            ) from None

    async def events(self) -> AsyncIterator[SttEvent]:
        provider = self._adapter.provider
        try:
            async for message in self._conn.messages():
                for event in self._adapter.parse(message):
                    yield self._stamp(event)
        except ModelError as err:
            raise ModelError(err.kind, provider, scrub(err.detail, self._secret)) from None
        except Exception as exc:
            raise ModelError(ErrorKind.NETWORK, provider, type(exc).__name__) from None

    def _stamp(self, event: SttEvent) -> SttEvent:
        arrival = self._clock.now_ms() if self._clock is not None else 0
        ts = self._origin + event.ts_ms if event.ts_ms > 0 else arrival
        end = None if event.end_ms is None else self._origin + event.end_ms
        return SttEvent(event.kind, event.text, ts, end, event.confidence)

    async def finish(self) -> None:
        msg = self._adapter.finish_message()
        if msg is not None and not self._closed:
            await self._conn.send(msg)

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._conn.close()


class TtsSession:
    """TtsStream over a streaming HTTP response.  ``cancel`` closes the response (the vendor stops
    generating when the connection drops)."""

    def __init__(
        self,
        cm: AbstractAsyncContextManager[StreamHandle],
        handle: StreamHandle,
        *,
        encoding: str,
        sample_rate: int,
        provider: str,
    ) -> None:
        self._cm = cm
        self._handle = handle
        self._encoding = encoding
        self._rate = sample_rate
        self._provider = provider
        self._closed = False
        self._carry = b""

    def _duration_ms(self, n_bytes: int) -> int:
        per_sample = 1 if self._encoding in ("mulaw", "alaw") else 2
        return round(n_bytes / per_sample / self._rate * 1000)

    async def chunks(self) -> AsyncIterator[TtsChunk]:
        sample = 1 if self._encoding in ("mulaw", "alaw") else 2
        try:
            async for raw in self._handle.aiter_bytes():
                if self._closed:
                    return
                data = self._carry + raw
                usable = len(data) - len(data) % sample
                self._carry = data[usable:]
                if usable:
                    yield TtsChunk(data[:usable], max(1, self._duration_ms(usable)))
        except ModelError:
            raise
        except Exception as exc:
            if self._closed:
                return
            raise ModelError(ErrorKind.NETWORK, self._provider, type(exc).__name__) from None
        finally:
            await self.cancel()

    async def cancel(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._cm.__aexit__(None, None, None)
        except Exception:  # noqa: BLE001 - closing a response that already failed
            return


def open_error(provider: str, exc: Exception) -> ModelError:
    if isinstance(exc, ModelError):
        return exc
    return ModelError(ErrorKind.NETWORK, provider, type(exc).__name__)


__all__ = [
    "SttAdapter",
    "SttRequest",
    "SttSession",
    "TtsAdapter",
    "TtsRequest",
    "TtsSession",
    "WsConnectSpec",
    "WsConnection",
    "WsTransport",
    "open_error",
]
