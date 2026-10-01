"""Speech plane: gated STT/TTS through the executor + ModelGateway, vendor adapters, SSRF, keys."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.actions import Backends, SttOpen, TtsSynthesize
from axis_runtime.executor import ActionExecutor
from axis_runtime.gate import GateDecision
from axis_runtime.guard import DirectExecutionError
from axis_runtime.models import InMemorySecretStore, ModelError, ModelGateway
from axis_runtime.models.adapters.base import HttpCall, HttpResponse, StreamHandle
from axis_runtime.models.speech import SttRequest, TtsRequest, WsConnectSpec
from axis_runtime.models.speech_vendors import (
    AssemblyAiStt,
    DeepgramStt,
    ElevenLabsTts,
    OpenAiTts,
    default_stt_adapters,
    default_tts_adapters,
)
from axis_runtime.models.types import ErrorKind
from axis_runtime.voice.clock import ManualVoiceClock
from axis_runtime.voice.errors import SpeechDeniedError, SpeechUnavailableError
from axis_runtime.voice.gated import GatedSttProvider, GatedTtsProvider
from axis_runtime.voice.types import AudioFrame, SttConfig, SttEventKind, TtsConfig
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny
from helpers import PID, identity, running_recorder

KEYS = {
    (TENANT, "deepgram", "default"): "dg-secret-key",
    (TENANT, "assemblyai", "default"): "aai-secret-key",
    (TENANT, "elevenlabs", "default"): "el-secret-key",
    (TENANT, "openai-tts", "default"): "oa-secret-key",
}


class FakeWsConn:
    def __init__(self, incoming: list[str | bytes]) -> None:
        self.sent: list[str | bytes] = []
        self.incoming = incoming
        self.closed = False

    async def send(self, data: str | bytes) -> None:
        self.sent.append(data)

    async def messages(self) -> AsyncIterator[str | bytes]:
        for m in self.incoming:
            yield m

    async def close(self) -> None:
        self.closed = True


@dataclass
class FakeWs:
    incoming: list[str | bytes] = field(default_factory=list)
    fail: Exception | None = None
    specs: list[WsConnectSpec] = field(default_factory=list)
    conns: list[FakeWsConn] = field(default_factory=list)

    async def connect(self, spec: WsConnectSpec) -> FakeWsConn:
        self.specs.append(spec)
        if self.fail is not None:
            raise self.fail
        conn = FakeWsConn(self.incoming)
        self.conns.append(conn)
        return conn


class _Handle:
    def __init__(self, status: int, chunks: list[bytes], body: bytes = b"") -> None:
        self.status, self.headers = status, {}
        self._chunks, self._body = chunks, body

    async def read(self) -> bytes:
        return self._body

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for c in self._chunks:
            yield c


@dataclass
class StreamTransport:
    status: int = 200
    chunks: list[bytes] = field(default_factory=lambda: [b"\x01\x02" * 80])
    body: bytes = b""
    calls: list[HttpCall] = field(default_factory=list)
    exits: int = 0

    async def send(self, call: HttpCall) -> HttpResponse:  # pragma: no cover
        raise NotImplementedError

    @asynccontextmanager
    async def stream(self, call: HttpCall) -> AsyncIterator[StreamHandle]:
        self.calls.append(call)
        try:
            yield _Handle(self.status, self.chunks, self.body)  # type: ignore[misc]
        finally:
            self.exits += 1


async def _public(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def gateway(
    ws: FakeWs | None = None, http: StreamTransport | None = None, **kw: Any
) -> ModelGateway:
    return ModelGateway(
        kw.pop("secrets", InMemorySecretStore(KEYS)),
        transport=http or StreamTransport(),
        clock=FakeClock(),
        resolver=_public,
        stt_adapters=default_stt_adapters(),
        tts_adapters=default_tts_adapters(),
        ws_transport=ws or FakeWs(),
        voice_clock=ManualVoiceClock(),
        **kw,
    )


async def executor(gw: ModelGateway, gate: Any = None) -> tuple[ActionExecutor, ScriptedGate]:
    gate = gate or ScriptedGate()
    rec = await running_recorder(FakeClock())
    ex = ActionExecutor(
        gate=gate, recorder=rec, identity=identity(), backends=Backends(models=gw), gate_timeout=0.5
    )
    return ex, gate


# ---- the guard ----------------------------------------------------------------------------------


async def test_speech_methods_refuse_to_run_outside_the_executor() -> None:
    gw = gateway()
    with pytest.raises(DirectExecutionError):
        await gw.open_stt(SttRequest(TENANT, "deepgram", "nova-2"))
    with pytest.raises(DirectExecutionError):
        await gw.synthesize(TtsRequest(TENANT, "elevenlabs", "m", "hi", "v"))


async def test_deny_opens_nothing_and_becomes_speech_denied() -> None:
    ws, http = FakeWs(), StreamTransport()
    ex, gate = await executor(gateway(ws, http), ScriptedGate(deny("no speech")))
    stt = GatedSttProvider(ex, PID, tenant_id=TENANT, provider="deepgram", model="nova-2")
    tts = GatedTtsProvider(ex, PID, tenant_id=TENANT, provider="elevenlabs", model="m")
    with pytest.raises(SpeechDeniedError):
        await stt.start(SttConfig())
    with pytest.raises(SpeechDeniedError):
        await tts.synthesize("hello", TtsConfig(voice="v"))
    assert ws.specs == [] and http.calls == []
    assert [r.enforcement_point.value for r in gate.requests] == ["model_call", "model_call"]


async def test_gate_error_and_approval_are_denials_too() -> None:
    class Boom:
        async def evaluate(self, r: Any) -> GateDecision:
            raise RuntimeError("down")

    ws = FakeWs()
    ex, _ = await executor(gateway(ws), Boom())
    stt = GatedSttProvider(ex, PID, tenant_id=TENANT, provider="deepgram", model="nova-2")
    with pytest.raises(SpeechDeniedError):
        await stt.start(SttConfig())
    ex2, _ = await executor(
        gateway(ws), ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="a1"))
    )
    stt2 = GatedSttProvider(ex2, PID, tenant_id=TENANT, provider="deepgram", model="nova-2")
    with pytest.raises(SpeechDeniedError):
        await stt2.start(SttConfig())
    assert ws.specs == []


async def test_gate_sees_the_text_and_never_audio() -> None:
    ex, gate = await executor(gateway())
    tts = GatedTtsProvider(ex, PID, tenant_id=TENANT, provider="elevenlabs", model="m")
    await tts.synthesize("Your balance is five dollars.", TtsConfig(voice="v"))
    req = gate.requests[0]
    assert req.context["args"]["text"] == "Your balance is five dollars."
    assert req.context["args"]["modality"] == "tts" and req.context["tool"]["kind"] == "model"
    stt = GatedSttProvider(
        ex, PID, tenant_id=TENANT, provider="deepgram", model="nova-2", consent_established=True
    )
    await stt.start(SttConfig())
    assert gate.requests[1].context["args"]["consent_established"] is True


async def test_redaction_rewrites_the_text_that_leaves() -> None:
    http = StreamTransport()
    gate = ScriptedGate(
        GateDecision(Decision.ALLOW_WITH_REDACTION, "phi", redact_fields=("args.text",))
    )
    ex, _ = await executor(gateway(None, http), gate)
    tts = GatedTtsProvider(ex, PID, tenant_id=TENANT, provider="elevenlabs", model="m")
    await tts.synthesize("SSN 111-22-3333", TtsConfig(voice="v"))
    assert "111-22-3333" not in http.calls[0].body.decode()
    assert "[REDACTED]" in http.calls[0].body.decode()


async def test_results_are_audited_without_the_text() -> None:
    gw = gateway()
    rec = await running_recorder(FakeClock())
    ex = ActionExecutor(
        gate=ScriptedGate(), recorder=rec, identity=identity(), backends=Backends(models=gw)
    )
    await ex.run(
        TtsSynthesize(
            tenant_id=TENANT, provider="elevenlabs", model="m", text="secret words", voice="v"
        ),
        pid=PID,
    )
    blob = json.dumps(rec.state.tool_calls[-1].result)
    assert "secret words" not in blob and "text_sha256" in blob


# ---- STT over the fake websocket ----------------------------------------------------------------


async def test_deepgram_session_end_to_end() -> None:
    ws = FakeWs(
        [
            json.dumps({"type": "SpeechStarted", "timestamp": 0.5}),
            json.dumps(
                {
                    "type": "Results",
                    "is_final": False,
                    "start": 0.5,
                    "duration": 0.4,
                    "channel": {"alternatives": [{"transcript": "hello", "confidence": 0.9}]},
                }
            ),
            json.dumps(
                {
                    "type": "Results",
                    "is_final": True,
                    "start": 0.5,
                    "duration": 1.0,
                    "channel": {"alternatives": [{"transcript": "hello there"}]},
                }
            ),
            json.dumps(
                {
                    "type": "Results",
                    "is_final": False,
                    "channel": {"alternatives": [{"transcript": ""}]},
                }
            ),
            json.dumps({"type": "Metadata"}),
            b"binary-ignored",
            "not json",
        ]
    )
    ex, _ = await executor(gateway(ws))
    stt = GatedSttProvider(ex, PID, tenant_id=TENANT, provider="deepgram", model="nova-2")
    stream = await stt.start(SttConfig(sample_rate=16000))
    spec = ws.specs[0]
    assert spec.url.startswith("wss://api.deepgram.com/v1/listen?")
    assert "sample_rate=16000" in spec.url and "endpointing=false" in spec.url
    assert spec.headers == {"Authorization": "Token dg-secret-key"}
    await stream.send_audio(AudioFrame(b"\x00\x01", ts_ms=1))
    assert ws.conns[0].sent == [b"\x00\x01"]
    events = [e async for e in stream.events()]
    assert [(e.kind, e.text) for e in events] == [
        (SttEventKind.SPEECH_START, ""),
        (SttEventKind.PARTIAL, "hello"),
        (SttEventKind.FINAL, "hello there"),
    ]
    assert events[1].ts_ms == 500 and events[2].end_ms == 1500
    await stream.finish()
    assert json.loads(ws.conns[0].sent[-1]) == {"type": "CloseStream"}
    await stream.aclose()
    await stream.aclose()
    assert ws.conns[0].closed
    with pytest.raises(ModelError):
        await stream.send_audio(AudioFrame(b"x", ts_ms=2))


async def test_assemblyai_turns() -> None:
    ws = FakeWs(
        [
            json.dumps({"type": "Begin", "id": "x"}),
            json.dumps(
                {
                    "type": "Turn",
                    "transcript": "hi th",
                    "end_of_turn": False,
                    "words": [{"start": 100, "end": 200}],
                }
            ),
            json.dumps(
                {
                    "type": "Turn",
                    "transcript": "hi there",
                    "end_of_turn": True,
                    "turn_is_formatted": False,
                }
            ),
            json.dumps(
                {
                    "type": "Turn",
                    "transcript": "Hi there.",
                    "end_of_turn": True,
                    "turn_is_formatted": True,
                    "words": [{"start": 100, "end": 900}],
                }
            ),
            json.dumps({"type": "Turn", "transcript": ""}),
        ]
    )
    ex, _ = await executor(gateway(ws))
    stt = GatedSttProvider(ex, PID, tenant_id=TENANT, provider="assemblyai", model="u3")
    stream = await stt.start(SttConfig(encoding="mulaw"))
    assert "encoding=pcm_mulaw" in ws.specs[0].url
    assert ws.specs[0].headers == {"Authorization": "aai-secret-key"}
    events = [e async for e in stream.events()]
    assert [(e.kind.value, e.text) for e in events] == [
        ("partial", "hi th"),
        ("partial", "hi there"),
        ("final", "Hi there."),
    ]
    assert events[0].ts_ms == 100 and events[2].end_ms == 900
    await stream.finish()
    assert json.loads(ws.conns[0].sent[-1]) == {"type": "Terminate"}


@pytest.mark.parametrize("provider", ["deepgram", "assemblyai"])
async def test_vendor_error_messages_and_bad_encodings(provider: str) -> None:
    msg = {"type": "Error", "err_code": "BAD", "error": "x"}
    ws = FakeWs([json.dumps(msg)])
    ex, _ = await executor(gateway(ws))
    stt = GatedSttProvider(ex, PID, tenant_id=TENANT, provider=provider, model="m")
    stream = await stt.start(SttConfig())
    with pytest.raises(ModelError):
        _ = [e async for e in stream.events()]
    with pytest.raises(SpeechUnavailableError):
        await stt.start(SttConfig(encoding="opus"))


async def test_stt_failures_map_to_unavailable_and_trip_the_breaker() -> None:
    ws = FakeWs(fail=ConnectionError("refused dg-secret-key"))
    gw = gateway(ws, breaker_threshold=2)
    ex, _ = await executor(gw)
    stt = GatedSttProvider(ex, PID, tenant_id=TENANT, provider="deepgram", model="nova-2")
    for _ in range(2):
        with pytest.raises(SpeechUnavailableError) as ei:
            await stt.start(SttConfig())
        assert "dg-secret-key" not in str(ei.value)
    n = len(ws.specs)
    with pytest.raises(SpeechUnavailableError) as ei:
        await stt.start(SttConfig())
    assert "circuit" in str(ei.value) and len(ws.specs) == n


async def test_missing_key_unknown_provider_and_no_transport() -> None:
    ex, _ = await executor(gateway(secrets=InMemorySecretStore({})))
    stt = GatedSttProvider(ex, PID, tenant_id=TENANT, provider="deepgram", model="m")
    with pytest.raises(SpeechUnavailableError) as ei:
        await stt.start(SttConfig())
    assert "no_credentials" in str(ei.value)
    ex, _ = await executor(gateway())
    with pytest.raises(SpeechUnavailableError):
        await GatedSttProvider(ex, PID, tenant_id=TENANT, provider="nope", model="m").start(
            SttConfig()
        )
    with pytest.raises(SpeechUnavailableError):
        await GatedTtsProvider(ex, PID, tenant_id=TENANT, provider="nope", model="m").synthesize(
            "x", TtsConfig()
        )
    gw = ModelGateway(
        InMemorySecretStore(KEYS), stt_adapters=default_stt_adapters(), resolver=_public
    )
    ex, _ = await executor(gw)
    with pytest.raises(SpeechUnavailableError) as ei2:
        await GatedSttProvider(ex, PID, tenant_id=TENANT, provider="deepgram", model="m").start(
            SttConfig()
        )
    assert "websocket" in str(ei2.value)


async def test_endpoint_override_is_ssrf_checked_and_never_gets_a_platform_key() -> None:
    ws = FakeWs()
    ex, _ = await executor(gateway(ws))
    for bad in (
        "wss://localhost/v1",
        "wss://127.0.0.1/x",
        "ws://example.com/x",
        "wss://u:p@example.com/",
    ):
        stt = GatedSttProvider(
            ex, PID, tenant_id=TENANT, provider="deepgram", model="m", endpoint=bad
        )
        with pytest.raises(SpeechUnavailableError):
            await stt.start(SttConfig())
    assert ws.specs == []
    ok = GatedSttProvider(
        ex,
        PID,
        tenant_id=TENANT,
        provider="deepgram",
        model="m",
        endpoint="wss://stt.example.com/listen",
    )
    await ok.start(SttConfig())
    assert ws.specs[0].url.startswith("wss://stt.example.com/listen?")
    # platform key + custom endpoint is refused
    platform = InMemorySecretStore({("_platform", "deepgram", "default"): "platform-key"})
    from axis_runtime.models import TenantModelPolicy

    gw = gateway(
        ws,
        secrets=InMemorySecretStore({}),
        platform_secrets=platform,
        tenant_policy=lambda t: TenantModelPolicy(allow_platform_keys=True),
    )
    ex, _ = await executor(gw)
    custom = GatedSttProvider(
        ex,
        PID,
        tenant_id=TENANT,
        provider="deepgram",
        model="m",
        endpoint="wss://stt.example.com/x",
    )
    with pytest.raises(SpeechUnavailableError) as ei:
        await custom.start(SttConfig())
    assert "platform keys never go" in str(ei.value)
    plain = GatedSttProvider(ex, PID, tenant_id=TENANT, provider="deepgram", model="m")
    await plain.start(SttConfig())
    assert ws.specs[-1].headers == {"Authorization": "Token platform-key"}


async def test_stt_timestamps_are_mapped_onto_the_voice_clock() -> None:
    clock = ManualVoiceClock()
    await clock.advance(1000)
    ws = FakeWs(
        [
            json.dumps(
                {
                    "type": "Results",
                    "is_final": False,
                    "start": 0.2,
                    "duration": 0.1,
                    "channel": {"alternatives": [{"transcript": "yo"}]},
                }
            ),
            json.dumps({"type": "SpeechStarted"}),
        ]
    )
    gw = gateway(ws)
    gw._voice_clock = clock  # noqa: SLF001
    ex, _ = await executor(gw)
    stream = await GatedSttProvider(
        ex, PID, tenant_id=TENANT, provider="deepgram", model="m"
    ).start(SttConfig())
    events = [e async for e in stream.events()]
    assert events[0].ts_ms == 1200
    assert events[1].ts_ms == 1000  # no vendor time: stamped at arrival


# ---- TTS over fake HTTP streaming ---------------------------------------------------------------


async def test_elevenlabs_request_and_chunk_durations() -> None:
    http = StreamTransport(chunks=[b"\x00" * 160, b"\x00" * 33, b"\x00" * 7])
    ex, _ = await executor(gateway(None, http))
    tts = GatedTtsProvider(
        ex, PID, tenant_id=TENANT, provider="elevenlabs", model="eleven_turbo_v2_5"
    )
    stream = await tts.synthesize("hi there", TtsConfig(voice="voice/1", sample_rate=8000))
    call = http.calls[0]
    assert (
        call.url
        == "https://api.elevenlabs.io/v1/text-to-speech/voice%2F1/stream?output_format=pcm_8000"
    )
    assert call.headers["xi-api-key"] == "el-secret-key"
    assert json.loads(call.body) == {"text": "hi there", "model_id": "eleven_turbo_v2_5"}
    chunks = [c async for c in stream.chunks()]
    assert [c.duration_ms for c in chunks] == [10, 2, 1]  # odd bytes carry over; never 0 ms
    assert http.exits == 1


async def test_mulaw_durations_and_unsupported_formats() -> None:
    http = StreamTransport(chunks=[b"\x7f" * 160])
    ex, _ = await executor(gateway(None, http))
    tts = GatedTtsProvider(ex, PID, tenant_id=TENANT, provider="elevenlabs", model="m")
    stream = await tts.synthesize("x", TtsConfig(voice="v", encoding="mulaw", sample_rate=8000))
    assert [c.duration_ms async for c in stream.chunks()] == [20]
    assert "ulaw_8000" in http.calls[0].url
    for cfg in (TtsConfig(voice="v", sample_rate=12345), TtsConfig(voice="")):
        with pytest.raises(SpeechUnavailableError):
            await tts.synthesize("x", cfg)


async def test_openai_tts_is_fixed_24k_pcm() -> None:
    http = StreamTransport(chunks=[b"\x00" * 4800])
    ex, _ = await executor(gateway(None, http))
    tts = GatedTtsProvider(
        ex, PID, tenant_id=TENANT, provider="openai-tts", model="gpt-4o-mini-tts"
    )
    stream = await tts.synthesize("hello", TtsConfig(sample_rate=24000))
    body = json.loads(http.calls[0].body)
    assert body == {
        "model": "gpt-4o-mini-tts",
        "input": "hello",
        "voice": "alloy",
        "response_format": "pcm",
    }
    assert http.calls[0].headers["authorization"] == "Bearer oa-secret-key"
    assert [c.duration_ms async for c in stream.chunks()] == [100]
    with pytest.raises(SpeechUnavailableError) as ei:
        await tts.synthesize("hello", TtsConfig(sample_rate=8000))
    assert "resampling" in str(ei.value)


async def test_cancel_closes_the_vendor_response_once() -> None:
    http = StreamTransport(chunks=[b"\x00" * 160] * 5)
    ex, _ = await executor(gateway(None, http))
    tts = GatedTtsProvider(ex, PID, tenant_id=TENANT, provider="elevenlabs", model="m")
    stream = await tts.synthesize("long text", TtsConfig(voice="v"))
    it = stream.chunks().__aiter__()
    await it.__anext__()
    await stream.cancel()
    await stream.cancel()
    assert http.exits == 1
    assert [c async for c in stream.chunks()] == []


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (401, ErrorKind.AUTH),
        (429, ErrorKind.RATE_LIMIT),
        (400, ErrorKind.INVALID_REQUEST),
        (503, ErrorKind.SERVER),
        (418, ErrorKind.UNKNOWN),
    ],
)
async def test_tts_http_errors_are_classified_and_scrubbed(status: int, kind: ErrorKind) -> None:
    body = json.dumps({"detail": {"status": "el-secret-key bad"}}).encode()
    http = StreamTransport(status=status, body=body)
    gw = gateway(None, http)
    rec = await running_recorder(FakeClock())
    ex = ActionExecutor(
        gate=ScriptedGate(), recorder=rec, identity=identity(), backends=Backends(models=gw)
    )
    out = await ex.run(
        TtsSynthesize(tenant_id=TENANT, provider="elevenlabs", model="m", text="x", voice="v"),
        pid=PID,
    )
    assert "el-secret-key" not in str(out) and kind.value in str(out)
    assert http.exits == 1


async def test_tts_transport_failure_is_a_network_error() -> None:
    class Broken(StreamTransport):
        @asynccontextmanager
        async def stream(self, call: HttpCall) -> AsyncIterator[StreamHandle]:
            raise OSError("down")
            yield  # pragma: no cover

    ex, _ = await executor(gateway(None, Broken()))
    tts = GatedTtsProvider(ex, PID, tenant_id=TENANT, provider="elevenlabs", model="m")
    with pytest.raises(SpeechUnavailableError):
        await tts.synthesize("x", TtsConfig(voice="v"))


async def test_tts_midstream_failure_surfaces_as_model_error() -> None:
    class Dies(_Handle):
        async def aiter_bytes(self) -> AsyncIterator[bytes]:
            yield b"\x00\x00"
            raise OSError("reset")

    class T(StreamTransport):
        @asynccontextmanager
        async def stream(self, call: HttpCall) -> AsyncIterator[StreamHandle]:
            yield Dies(200, [])  # type: ignore[misc]

    ex, _ = await executor(gateway(None, T()))
    stream = await GatedTtsProvider(
        ex, PID, tenant_id=TENANT, provider="elevenlabs", model="m"
    ).synthesize("x", TtsConfig(voice="v"))
    got = []
    with pytest.raises(ModelError):
        async for c in stream.chunks():
            got.append(c)
    assert len(got) == 1


def test_adapter_registries() -> None:
    assert set(default_stt_adapters()) == {"deepgram", "assemblyai"}
    assert set(default_tts_adapters()) == {"elevenlabs", "openai-tts"}
    assert isinstance(DeepgramStt(), DeepgramStt) and AssemblyAiStt and ElevenLabsTts and OpenAiTts


async def test_action_specs_round_trip_and_names() -> None:
    from axis_runtime.actions import action_from_spec

    a = TtsSynthesize(tenant_id=TENANT, provider="elevenlabs", model="m", text="hi", voice="v")
    assert action_from_spec(a.to_spec()) == a and a.name == "tts:elevenlabs/m"
    s = SttOpen(tenant_id=TENANT, provider="deepgram", model="nova-2")
    assert action_from_spec(s.to_spec()) == s and s.name == "stt:deepgram/nova-2"
    with pytest.raises(ValueError):
        a.with_args({"text": None})
    assert s.with_args({}) is s and s.redact_result("r", ["x"]) == "r"
    _ = allow, Mapping
