"""Vendor wire formats for the speech plane: two streaming STT and two streaming TTS vendors.

PROTOTYPE: written from the vendors' public documentation and exercised only against fake
transports (no real credentials, no live call: docs/NEEDS.md).  Each adapter is pure: it builds a
URL / headers / body and parses vendor messages; the bytes move over the injected transports.

STT   Deepgram live streaming   (WebSocket, ``Authorization: Token <key>``)
      AssemblyAI streaming v3   (WebSocket, ``Authorization: <key>``)
TTS   ElevenLabs text-to-speech  (HTTP streaming, ``xi-api-key``)
      OpenAI audio/speech        (HTTP streaming, bearer key; fixed 24 kHz PCM)

Endpointing stays OUR job (``voice.endpointing``): vendor-side endpointing is switched off where the
vendor lets us.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar
from urllib.parse import quote, urlencode

from axis_runtime.models.adapters.base import HttpCall
from axis_runtime.models.secrets import Secret
from axis_runtime.models.speech import (
    SttAdapter,
    SttRequest,
    TtsAdapter,
    TtsRequest,
    WsConnectSpec,
)
from axis_runtime.models.types import ErrorKind, ModelError
from axis_runtime.voice.types import SttEvent, SttEventKind


def _need(secret: Secret | None, provider: str) -> str:
    if secret is None:
        raise ModelError(ErrorKind.NO_CREDENTIALS, provider, "no api key")
    return secret.reveal()


def _json(message: str | bytes) -> dict[str, Any] | None:
    if isinstance(message, bytes):
        try:
            message = message.decode("utf-8")
        except UnicodeDecodeError:
            return None
    try:
        data = json.loads(message)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _ms(seconds: Any) -> int:
    try:
        return max(0, round(float(seconds) * 1000))
    except (TypeError, ValueError):
        return 0


# ---- STT ----------------------------------------------------------------------------------------


class DeepgramStt(SttAdapter):
    provider: ClassVar[str] = "deepgram"
    default_endpoint: ClassVar[str] = "wss://api.deepgram.com/v1/listen"
    _ENCODINGS: ClassVar[dict[str, str]] = {"pcm_s16le": "linear16", "mulaw": "mulaw"}

    def connect_spec(self, req: SttRequest, secret: Secret | None, base_url: str) -> WsConnectSpec:
        encoding = self._ENCODINGS.get(req.encoding)
        if encoding is None:
            raise ModelError(ErrorKind.INVALID_REQUEST, self.provider, "unsupported encoding")
        query = {
            "model": req.model,
            "language": req.language,
            "encoding": encoding,
            "sample_rate": str(req.sample_rate),
            "channels": "1",
            "interim_results": "true" if req.interim_results else "false",
            "punctuate": "true",
            "vad_events": "true",
            "endpointing": "false",  # turn-taking is decided by the session
        }
        return WsConnectSpec(
            f"{base_url}?{urlencode(query)}",
            {"Authorization": f"Token {_need(secret, self.provider)}"},
        )

    def finish_message(self) -> str:
        return json.dumps({"type": "CloseStream"})

    def parse(self, message: str | bytes) -> list[SttEvent]:
        data = _json(message)
        if data is None:
            return []
        kind = data.get("type")
        if kind == "Results":
            alts = (data.get("channel") or {}).get("alternatives") or [{}]
            text = str(alts[0].get("transcript") or "").strip()
            is_final = bool(data.get("is_final"))
            if not text and not is_final:
                return []
            start = _ms(data.get("start"))
            end = start + _ms(data.get("duration"))
            conf = alts[0].get("confidence")
            return [
                SttEvent(
                    SttEventKind.FINAL if is_final else SttEventKind.PARTIAL,
                    text,
                    start,
                    end,
                    float(conf) if isinstance(conf, int | float) else None,
                )
            ]
        if kind == "SpeechStarted":
            return [SttEvent(SttEventKind.SPEECH_START, "", _ms(data.get("timestamp")))]
        if kind in ("Error", "error") or "err_code" in data:
            raise ModelError(
                ErrorKind.SERVER, self.provider, str(data.get("err_code", "error"))[:64]
            )
        return []  # Metadata, UtteranceEnd, ...


class AssemblyAiStt(SttAdapter):
    provider: ClassVar[str] = "assemblyai"
    default_endpoint: ClassVar[str] = "wss://streaming.assemblyai.com/v3/ws"
    _ENCODINGS: ClassVar[dict[str, str]] = {"pcm_s16le": "pcm_s16le", "mulaw": "pcm_mulaw"}

    def connect_spec(self, req: SttRequest, secret: Secret | None, base_url: str) -> WsConnectSpec:
        encoding = self._ENCODINGS.get(req.encoding)
        if encoding is None:
            raise ModelError(ErrorKind.INVALID_REQUEST, self.provider, "unsupported encoding")
        query = {
            "sample_rate": str(req.sample_rate),
            "encoding": encoding,
            "format_turns": "true",
        }
        return WsConnectSpec(
            f"{base_url}?{urlencode(query)}", {"Authorization": _need(secret, self.provider)}
        )

    def finish_message(self) -> str:
        return json.dumps({"type": "Terminate"})

    def parse(self, message: str | bytes) -> list[SttEvent]:
        data = _json(message)
        if data is None:
            return []
        kind = data.get("type")
        if kind == "Turn":
            text = str(data.get("transcript") or "").strip()
            if not text:
                return []
            words = data.get("words") or []
            first = words[0] if words and isinstance(words[0], dict) else {}
            last = words[-1] if words and isinstance(words[-1], dict) else {}
            # with format_turns the formatted copy of a finished turn is the FINAL
            final = bool(data.get("end_of_turn")) and bool(data.get("turn_is_formatted"))
            return [
                SttEvent(
                    SttEventKind.FINAL if final else SttEventKind.PARTIAL,
                    text,
                    int(first.get("start") or 0),
                    int(last["end"]) if "end" in last else None,
                )
            ]
        if kind in ("Error", "error") or "error" in data:
            raise ModelError(ErrorKind.SERVER, self.provider, "vendor error")
        return []  # Begin, Termination, ...


# ---- TTS ----------------------------------------------------------------------------------------


class ElevenLabsTts(TtsAdapter):
    provider: ClassVar[str] = "elevenlabs"
    default_endpoint: ClassVar[str] = "https://api.elevenlabs.io"
    _FORMATS: ClassVar[dict[tuple[str, int], str]] = {
        ("pcm_s16le", 8000): "pcm_8000",
        ("pcm_s16le", 16000): "pcm_16000",
        ("pcm_s16le", 22050): "pcm_22050",
        ("pcm_s16le", 24000): "pcm_24000",
        ("pcm_s16le", 44100): "pcm_44100",
        ("mulaw", 8000): "ulaw_8000",
    }

    def output_format(self, req: TtsRequest) -> tuple[str, int]:
        if (req.encoding, req.sample_rate) not in self._FORMATS:
            raise ModelError(ErrorKind.INVALID_REQUEST, self.provider, "unsupported audio format")
        return req.encoding, req.sample_rate

    def build(self, req: TtsRequest, secret: Secret | None, base_url: str) -> HttpCall:
        fmt = self._FORMATS.get((req.encoding, req.sample_rate))
        if fmt is None:
            raise ModelError(ErrorKind.INVALID_REQUEST, self.provider, "unsupported audio format")
        if not req.voice:
            raise ModelError(ErrorKind.INVALID_REQUEST, self.provider, "a voice id is required")
        url = (
            f"{base_url.rstrip('/')}/v1/text-to-speech/{quote(req.voice, safe='')}/stream"
            f"?output_format={fmt}"
        )
        body = json.dumps({"text": req.text, "model_id": req.model}).encode("utf-8")
        headers = {
            "xi-api-key": _need(secret, self.provider),
            "content-type": "application/json",
            "accept": "audio/*",
        }
        return HttpCall("POST", url, headers, body)


class OpenAiTts(TtsAdapter):
    provider: ClassVar[str] = "openai-tts"
    default_endpoint: ClassVar[str] = "https://api.openai.com"
    _RATE = 24000  # the PCM the API returns is fixed: 24 kHz, 16-bit, mono

    def output_format(self, req: TtsRequest) -> tuple[str, int]:
        if (req.encoding, req.sample_rate) != ("pcm_s16le", self._RATE):
            raise ModelError(
                ErrorKind.INVALID_REQUEST,
                self.provider,
                "this vendor only produces 24 kHz pcm_s16le; resampling is not built",
            )
        return req.encoding, req.sample_rate

    def build(self, req: TtsRequest, secret: Secret | None, base_url: str) -> HttpCall:
        self.output_format(req)
        body = json.dumps(
            {
                "model": req.model,
                "input": req.text,
                "voice": req.voice or "alloy",
                "response_format": "pcm",
            }
        ).encode("utf-8")
        headers = {
            "authorization": f"Bearer {_need(secret, self.provider)}",
            "content-type": "application/json",
        }
        return HttpCall("POST", f"{base_url.rstrip('/')}/v1/audio/speech", headers, body)


def default_stt_adapters() -> dict[str, SttAdapter]:
    adapters: list[SttAdapter] = [DeepgramStt(), AssemblyAiStt()]
    return {a.provider: a for a in adapters}


def default_tts_adapters() -> dict[str, TtsAdapter]:
    adapters: list[TtsAdapter] = [ElevenLabsTts(), OpenAiTts()]
    return {a.provider: a for a in adapters}
