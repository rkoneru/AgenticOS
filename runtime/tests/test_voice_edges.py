"""Failure paths of the session: pumps that die, cancelled sessions, TTS dying mid-sentence."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from axis_runtime.process import ExitReason, ProcessState
from axis_runtime.voice.callrun import end_call_run
from axis_runtime.voice.fakes import FakeTtsStream
from axis_runtime.voice.session import VoiceSessionConfig
from axis_runtime.voice.types import AudioFrame, Frame, SttConfig, SttEvent, TtsChunk
from voice_helpers import make_rig


async def test_stt_audio_send_failure_ends_the_call() -> None:
    rig = await make_rig()
    await rig.start()

    async def boom(frame: AudioFrame) -> None:
        raise ConnectionError("stt gone")

    rig.stt.streams[0].send_audio = boom  # type: ignore[method-assign]
    await rig.transport.push(Frame(AudioFrame(b"\x00", ts_ms=1)))
    await rig.advance(50)
    assert (await rig.finish()).reason == "stt_audio_failed"


async def test_stt_event_stream_failure_ends_the_call() -> None:
    rig = await make_rig()

    async def start(config: SttConfig):  # type: ignore[no-untyped-def]
        stream = await orig(config)

        async def events() -> AsyncIterator[SttEvent]:
            raise ConnectionError("ws reset")
            yield  # pragma: no cover

        stream.events = events  # type: ignore[method-assign]
        return stream

    orig = rig.stt.start
    rig.stt.start = start  # type: ignore[method-assign]
    await rig.start()
    await rig.advance(50)
    assert (await rig.finish()).reason == "stt_failed"


async def test_transport_failure_ends_the_call() -> None:
    rig = await make_rig()

    async def events():  # type: ignore[no-untyped-def]
        raise ConnectionError("rtp lost")
        yield  # pragma: no cover

    rig.transport.events = events  # type: ignore[method-assign]
    await rig.start()
    await rig.advance(50)
    assert (await rig.finish()).reason == "transport_failed"


async def test_externally_cancelled_session_cleans_up_and_records_the_end() -> None:
    rig = await make_rig()
    await rig.start()
    assert rig.task is not None
    rig.task.cancel()
    try:
        await rig.task
    except asyncio.CancelledError:
        pass
    ended = [c for c in rig.state.voice_calls if c.phase == "ended"]
    assert ended and ended[0].reason == "cancelled"
    assert rig.transport.hung_up == "cancelled"


async def test_unexpected_exception_is_reported_not_raised() -> None:
    rig = await make_rig()

    async def broken(*a, **k):  # type: ignore[no-untyped-def]
        raise RuntimeError("bug")

    rig.session._dispatch = broken  # type: ignore[method-assign]  # noqa: SLF001
    await rig.start()
    await rig.caller.press("1")
    await rig.advance(10)
    assert (await rig.finish()).reason == "error:RuntimeError"


async def test_tts_dying_mid_sentence_records_the_partial_and_continues() -> None:
    rig = await make_rig()
    orig = FakeTtsStream.chunks

    async def dying(self: FakeTtsStream) -> AsyncIterator[TtsChunk]:
        n = 0
        async for c in orig(self):
            yield c
            n += 1
            if n == 3:
                raise ConnectionError("vendor reset")

    FakeTtsStream.chunks = dying  # type: ignore[method-assign]
    try:
        rig.agent.replies = ["This is a fairly long sentence that will be cut by a vendor error."]
        await rig.start()
        await rig.say("hello there how are you")
        await rig.advance(4000)
    finally:
        FakeTtsStream.chunks = orig  # type: ignore[method-assign]
    turns = rig.agent_turns()
    assert turns and 0 < len(turns[0][0]) < 60
    assert (await rig.finish()).reason == "caller_hangup"


async def test_farewell_grace_ends_the_call_even_if_speech_is_stuck() -> None:
    rig = await make_rig(
        config=VoiceSessionConfig(
            max_call_ms=1000, farewell_grace_ms=500, idle_prompt_text=None, idle_timeout_ms=60_000
        ),
        capacity_ms=100,
    )
    rig.tts.ms_per_char = 5000  # the farewell would take minutes to play
    await rig.start()
    await rig.advance(1100)
    await rig.advance(600)
    assert (await rig.finish()).reason == "max_duration"


async def test_hangup_during_consent_notice_without_agent_records_nothing_spoken() -> None:
    from axis_runtime.voice.consent import ConsentMode, ConsentPolicy, resolve_consent

    policy = resolve_consent(
        manifest_notice="Recorded.",
        configured=ConsentPolicy(mode=ConsentMode.NOTICE, notice="Recorded."),
    )
    rig = await make_rig(consent=policy)
    await rig.start()
    await rig.advance(50)
    await rig.caller.hangup()
    await rig.finish()
    assert rig.state.voice_turns == ()


async def test_end_call_run_terminates_once() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.finish()
    await end_call_run(rig.rec, rig.pid, reason=ExitReason.FAILED, detail="x")
    await end_call_run(rig.rec, rig.pid)  # idempotent
    info = rig.state.processes[rig.pid]
    assert info.state is ProcessState.TERMINATED and info.exit_reason is ExitReason.FAILED
