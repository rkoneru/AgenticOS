"""VoiceSession: turn-taking, barge-in, DTMF, timeouts, metrics, backpressure (virtual time)."""

from __future__ import annotations

import json

import pytest
from axis_runtime.events import EventType
from axis_runtime.voice.clock import ManualVoiceClock
from axis_runtime.voice.endpointing import EndpointingConfig
from axis_runtime.voice.errors import SpeechDeniedError
from axis_runtime.voice.fakes import FakeSttProvider, FakeTtsProvider
from axis_runtime.voice.session import BargeInConfig, DtmfConfig, VoiceSessionConfig
from axis_runtime.voice.types import AudioFrame, Frame
from voice_helpers import make_rig

LONG = "I can look that up for you right now. Your claim was filed on Monday. It is under review."


def _cfg(**over: object) -> VoiceSessionConfig:
    return VoiceSessionConfig(**over)  # type: ignore[arg-type]


# ---- basic turn -------------------------------------------------------------------------------


async def test_one_turn_is_spoken_in_full_and_recorded() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.say("hello there how are you")
    await rig.advance(4000)
    assert rig.user_turns() == ["hello there how are you"]
    assert rig.agent_turns() == [("Sure, I can help with that.", False)]
    assert rig.agent.requests[0].utterance == "hello there how are you"
    assert rig.tts.requests == ["Sure, I can help with that."]
    summary = await rig.finish()
    assert summary.reason == "caller_hangup" and summary.turns == 1 and summary.barge_ins == 0
    assert rig.transport.heard_ms() == 27 * 60 + 0  # all of it was played


async def test_history_is_passed_to_the_next_turn() -> None:
    rig = await make_rig(agent=None)
    await rig.start()
    await rig.say("first question please")
    await rig.advance(4000)
    await rig.say("and a second one")
    await rig.advance(4000)
    second = rig.agent.requests[1]
    assert [t.text for t in second.history] == [
        "first question please",
        "Sure, I can help with that.",
    ]
    await rig.finish()


async def test_late_final_of_the_same_utterance_is_not_a_second_turn() -> None:
    rig = await make_rig(config=_cfg(endpointing=EndpointingConfig(silence_ms=300)))
    await rig.start()
    # the caller's partials end, silence endpointing fires, THEN the provider's final arrives
    from axis_runtime.voice.fakes import directive_frame
    from axis_runtime.voice.types import SttEventKind

    async def push(kind: SttEventKind, text: str, ts: int) -> None:
        await rig.transport.push(Frame(directive_frame(kind, text, ts_ms=ts)))

    await push(SttEventKind.PARTIAL, "my claim number", 10)
    await rig.advance(500)
    assert rig.user_turns() == ["my claim number"]
    await push(SttEventKind.FINAL, "my claim number", 10)  # late final of the same speech
    await rig.advance(5000)
    assert rig.user_turns() == ["my claim number"] and rig.agent.started == 1
    await rig.finish()


# ---- barge-in ---------------------------------------------------------------------------------


async def _start_long_reply(**rig_kw: object):  # type: ignore[no-untyped-def]
    from axis_runtime.voice.clock import ManualVoiceClock

    rig = await make_rig(**rig_kw)  # type: ignore[arg-type]
    rig.agent.replies = [LONG]
    await rig.start()
    await rig.say("what is the status of my claim")
    await rig.advance(1000)  # silence + first bytes: the agent is now speaking
    assert rig.transport.queued_ms() > 0
    assert isinstance(rig.clock, ManualVoiceClock)
    return rig


async def test_barge_in_stops_playback_within_the_bound_and_records_spoken_text() -> None:
    rig = await _start_long_reply(stt_latency_ms=80)
    played_before = rig.transport.heard_ms()
    speech_at = rig.clock.now_ms()
    await rig.say("wait that is not what i asked", word_ms=100)
    await rig.advance(10)
    # playback was flushed: the buffer is empty and nothing more is queued
    assert rig.transport.queued_ms() == 0
    assert len(rig.transport.clear_at) == 1
    # the caller started speaking at `speech_at`; the first partial ("wait") reached the session
    # 80 ms later, and the playout buffer was flushed in that same instant: the audio stopped
    # within STT latency of the first word (the bound), and the session measured the same figure
    assert rig.transport.clear_at[0] - speech_at <= 80
    assert rig.session.barge_in_latencies_ms == [rig.transport.clear_at[0] - speech_at]
    truncated = [t for t in rig.state.voice_turns if t.role == "agent"]
    assert len(truncated) == 1 and truncated[0].truncated is True
    assert truncated[0].text and len(truncated[0].text) < len(LONG)
    assert LONG.startswith(truncated[0].text)
    assert truncated[0].intended_chars == len(LONG)
    # what was heard equals what was recorded as spoken (within one chunk of rounding)
    heard = rig.transport.heard_ms()
    assert heard >= played_before and heard < 60 * len(LONG)
    assert rig.tts.cancelled, "the in-flight synthesis was cancelled"
    await rig.finish()


async def test_barge_in_cancels_the_in_flight_agent_turn_and_the_next_turn_sees_the_cut() -> None:
    rig = await _start_long_reply()
    await rig.say("hold on a second please", word_ms=100)
    await rig.advance(3000)
    assert rig.agent.started == 2
    second = rig.agent.requests[1]
    assert second.utterance == "hold on a second please"
    assert any(t.truncated for t in second.history if t.role == "agent")
    await rig.finish()


async def test_barge_in_during_thinking_cancels_the_agent() -> None:
    rig = await make_rig()
    rig.agent.think_ms = 5000
    await rig.start()
    await rig.say("what is my balance today")
    await rig.advance(900)  # endpoint fired, the agent is thinking
    assert rig.agent.started == 1 and rig.agent.cancelled == 0
    await rig.say("actually never mind that", word_ms=100)
    await rig.advance(50)
    assert rig.agent.cancelled == 1
    assert rig.tts.requests == [], "nothing was synthesised for the cancelled turn"
    spoken = rig.agent_turns()
    assert spoken == [("", True)]
    await rig.finish()


async def test_one_word_noise_does_not_interrupt() -> None:
    rig = await _start_long_reply()
    await rig.say("mm", word_ms=100)
    await rig.advance(100)
    assert rig.transport.queued_ms() > 0 and rig.session.barge_in_latencies_ms == []
    await rig.advance(6000)
    assert rig.agent_turns() == [(LONG, False)]
    await rig.finish()


async def test_keyword_interrupts_with_a_single_word() -> None:
    rig = await _start_long_reply()
    await rig.say("stop", word_ms=100)
    await rig.advance(10)
    assert rig.transport.queued_ms() == 0 and len(rig.session.barge_in_latencies_ms) == 1
    await rig.finish()


async def test_barge_in_disabled_lets_the_agent_finish() -> None:
    rig = await _start_long_reply(config=_cfg(barge_in=BargeInConfig(enabled=False)))
    await rig.say("wait that is wrong", word_ms=100)
    await rig.advance(8000)
    assert rig.session.barge_in_latencies_ms == []
    assert rig.agent_turns()[0] == (LONG, False)
    await rig.finish()


async def test_speech_start_only_interrupts_when_configured() -> None:
    from axis_runtime.voice.fakes import directive_frame
    from axis_runtime.voice.types import SttEventKind

    for flag in (False, True):
        rig = await _start_long_reply(
            config=_cfg(barge_in=BargeInConfig(speech_start_triggers=flag))
        )
        await rig.transport.push(
            Frame(directive_frame(SttEventKind.SPEECH_START, "", ts_ms=rig.clock.now_ms()))
        )
        await rig.advance(10)
        assert (len(rig.session.barge_in_latencies_ms) == 1) is flag
        await rig.finish()


async def test_grace_window_ignores_early_interruptions() -> None:
    rig = await make_rig(config=_cfg(barge_in=BargeInConfig(grace_ms=500)))
    rig.agent.replies = [LONG]
    await rig.start()
    await rig.say("what is the status of my claim")
    await rig.advance(900)
    await rig.say("wait wait wait", word_ms=50)  # inside the grace window
    await rig.advance(10)
    assert rig.session.barge_in_latencies_ms == []
    await rig.finish()


async def test_barge_in_latency_includes_stt_delay_property() -> None:
    for latency in (0, 40, 120, 200):
        rig = await _start_long_reply(stt_latency_ms=latency)
        await rig.say("wait one moment please", word_ms=60)
        await rig.advance(latency + 20)
        got = rig.session.barge_in_latencies_ms
        assert len(got) == 1 and got[0] <= latency + 60 + 10, (latency, got)
        await rig.finish()


# ---- DTMF -------------------------------------------------------------------------------------


async def test_dtmf_digits_go_to_the_agent_but_are_not_persisted() -> None:
    rig = await make_rig()
    await rig.start()
    for d in "1234":
        await rig.caller.press(d)
    await rig.caller.press("#")
    await rig.advance(4000)
    assert rig.agent.requests[0].utterance == "1234"
    assert rig.agent.requests[0].input_kind == "dtmf"
    persisted = [t for t in rig.state.voice_turns if t.role == "dtmf"]
    assert [t.text for t in persisted] == ["[4 keypad digits]"]
    assert "1234" not in json.dumps([e.data for e in await rig.rec.log.read(rig.rec.run_id)])
    await rig.finish()


async def test_dtmf_interdigit_timeout_flushes_and_bad_keys_are_dropped() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.caller.press("5")
    await rig.caller.press("x")
    await rig.caller.press("")
    await rig.advance(3100)
    assert rig.agent.requests[0].utterance == "5"
    assert rig.session.dtmf_dropped == 2
    await rig.finish()


async def test_dtmf_flood_is_bounded() -> None:
    rig = await make_rig(config=_cfg(dtmf=DtmfConfig(max_digits=8)))
    rig.agent.think_ms = 100000  # never answers
    await rig.start()
    for _ in range(200):
        await rig.caller.press("9")
    await rig.advance(3100)
    assert rig.agent.requests[0].utterance == "9" * 8
    assert rig.session.dtmf_dropped == 192
    await rig.finish()


async def test_dtmf_disabled_drops_digits() -> None:
    rig = await make_rig(config=_cfg(dtmf=DtmfConfig(enabled=False)))
    await rig.start()
    await rig.caller.press("1")
    await rig.advance(4000)
    assert rig.agent.started == 0 and rig.session.dtmf_dropped == 1
    await rig.finish()


async def test_dtmf_can_interrupt_a_speaking_agent() -> None:
    rig = await _start_long_reply()
    await rig.caller.press("2")
    await rig.advance(20)
    assert rig.transport.queued_ms() == 0 and len(rig.session.barge_in_latencies_ms) == 1
    await rig.advance(3500)
    assert rig.agent.requests[-1].utterance == "2"
    await rig.finish()


async def test_dtmf_during_an_uninterruptible_turn_is_held() -> None:
    rig = await make_rig(
        config=_cfg(
            greeting="Welcome to the claims line, how can I help you today?",
            barge_in=BargeInConfig(dtmf_interrupts=False),
        )
    )
    await rig.start()
    await rig.advance(200)
    await rig.caller.press("7")
    await rig.caller.press("#")
    await rig.advance(200)
    assert rig.agent.started == 0  # still greeting
    await rig.advance(6000)
    assert rig.agent.requests[0].utterance == "7"
    await rig.finish()


# ---- idle, duration, greeting -----------------------------------------------------------------


async def test_idle_prompt_then_timeout() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.advance(12_100)
    assert rig.tts.requests == ["Are you still there?"]
    await rig.advance(8_500)
    summary = await rig.finish()
    assert summary.reason == "idle_timeout"
    assert 19_900 <= summary.duration_ms <= 21_500  # idle_timeout_ms of caller silence in total
    assert rig.transport.hung_up == "idle_timeout"


async def test_caller_speech_resets_the_idle_clock() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.advance(11_000)
    await rig.say("hello there friend")
    await rig.advance(5000)
    await rig.advance(10_000)
    assert rig.session.history[0].text == "hello there friend"
    summary = await rig.finish()
    assert summary.reason == "caller_hangup"  # no idle timeout fired in 16 s since the answer


async def test_max_duration_speaks_a_farewell_then_hangs_up() -> None:
    rig = await make_rig(
        config=_cfg(max_call_ms=5_000, idle_timeout_ms=60_000, idle_prompt_text=None)
    )
    await rig.start()
    await rig.advance(5_100)
    assert rig.tts.requests[0] == "We have reached the time limit for this call."
    await rig.advance(5_000)
    assert rig.tts.requests[-1] == "Goodbye."
    summary = await rig.finish()
    assert summary.reason == "max_duration"
    assert rig.transport.hung_up == "max_duration"
    assert summary.duration_ms <= 5_000 + 5_000 + 500


async def test_max_duration_without_farewell_ends_immediately() -> None:
    rig = await make_rig(
        config=_cfg(
            max_call_ms=3_000, farewell_text=None, idle_timeout_ms=60_000, idle_prompt_text=None
        )
    )
    await rig.start()
    await rig.advance(3_050)
    summary = await rig.finish()
    assert summary.reason == "max_duration" and summary.duration_ms <= 3_100


async def test_max_duration_interrupts_a_speaking_agent() -> None:
    rig = await make_rig(config=_cfg(max_call_ms=2_500, idle_prompt_text=None))
    rig.agent.replies = [LONG]
    await rig.start()
    await rig.say("what is the status of my claim")
    await rig.advance(2_000)
    assert rig.agent_turns()
    assert rig.agent_turns()[0][1] is True  # cut off by the call limit
    await rig.finish()


async def test_greeting_is_spoken_first() -> None:
    rig = await make_rig(config=_cfg(greeting="Hello, this is the claims line."))
    await rig.start()
    await rig.advance(3000)
    assert rig.tts.requests[0] == "Hello, this is the claims line."
    assert any(t.role == "system" for t in rig.state.voice_turns)
    await rig.finish()


async def test_max_turns_ends_the_call() -> None:
    rig = await make_rig(config=_cfg(max_turns=1))
    await rig.start()
    await rig.say("first question here")
    await rig.advance(4000)
    await rig.say("second question here")
    await rig.advance(2000)
    summary = await rig.finish()
    assert summary.reason == "max_turns" and summary.turns == 1


# ---- metrics ----------------------------------------------------------------------------------


async def test_stage_metrics_are_recorded_per_turn() -> None:
    rig = await make_rig(stt_latency_ms=0)
    rig.agent.think_ms = 120
    await rig.start()
    await rig.say("hello there how are you")
    await rig.advance(5000)
    summary = await rig.finish()
    m = summary.metrics[0]
    assert m.endpoint_silence_ms == 700
    assert m.agent_first_ms == 120
    assert m.tts_first_byte_ms == 40
    assert m.response_ms == 160
    assert m.perceived_ms == 700 + 160
    stages = {(s.stage, s.latency_ms) for s in rig.state.voice_stages}
    assert {("agent", 120), ("tts", 40), ("response", 160), ("endpoint", 700)} <= stages
    names = {s.name for s in rig.tracer.spans}
    assert {"voice.stt", "voice.agent", "voice.tts"} <= names
    agent_span = rig.tracer.named("voice.agent")[0]
    assert agent_span.attributes["latency_ms"] == 120 and agent_span.ended


async def test_sentences_are_streamed_to_tts_separately() -> None:
    rig = await make_rig()
    rig.agent.replies = [LONG]
    rig.agent.split = lambda t: [t[:20], t[20:55], t[55:]]
    rig.agent.delta_ms = 50
    await rig.start()
    await rig.say("what is the status of my claim")
    await rig.advance(8000)
    assert rig.tts.requests == [
        "I can look that up for you right now.",
        "Your claim was filed on Monday.",
        "It is under review.",
    ]
    assert rig.agent_turns() == [(LONG, False)]
    await rig.finish()


# ---- failures ---------------------------------------------------------------------------------


async def test_agent_failure_is_not_silent() -> None:
    rig = await make_rig()
    rig.agent.fail = RuntimeError("boom")
    await rig.start()
    await rig.say("hello there how are you")
    await rig.advance(5000)
    assert rig.tts.requests[0] == "Sorry, I am having trouble answering."
    await rig.finish()


async def test_agent_timeout_speaks_the_fallback_and_cancels_the_agent() -> None:
    rig = await make_rig(config=_cfg(agent_timeout_ms=2000))
    rig.agent.think_ms = 60_000
    await rig.start()
    await rig.say("hello there how are you")
    await rig.advance(3500)
    assert rig.agent.cancelled == 1
    assert rig.tts.requests[0] == "Sorry, I am having trouble answering."
    await rig.finish()


async def test_tts_denied_ends_the_call() -> None:
    class Denied(FakeTtsProvider):
        async def synthesize(self, text, config):  # type: ignore[no-untyped-def,override]
            raise SpeechDeniedError("policy")

    rig = await make_rig(tts=Denied(ManualVoiceClock()))
    await rig.start()
    await rig.say("hello there how are you")
    await rig.advance(4000)
    summary = await rig.finish()
    assert summary.reason == "tts_denied"


async def test_repeated_tts_failure_ends_the_call() -> None:
    rig = await make_rig()
    rig.tts.fail_on = "Sure"
    await rig.start()
    await rig.say("hello there how are you")
    await rig.advance(3000)
    await rig.say("and another thing please")
    await rig.advance(3000)
    summary = await rig.finish()
    assert summary.reason == "tts_failed"


async def test_stt_open_denied_and_failed() -> None:
    for exc, reason in (
        (SpeechDeniedError("no"), "stt_denied"),
        (ConnectionError("x"), "stt_failed"),
    ):
        rig = await make_rig(stt=FakeSttProvider(ManualVoiceClock(), fail_open=exc))
        await rig.start()
        await rig.advance(100)
        summary = await rig.finish()
        assert summary.reason == reason


async def test_stt_stream_ending_ends_the_call() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.stt.streams[0].finish()
    await rig.advance(100)
    summary = await rig.finish()
    assert summary.reason == "stt_closed"


# ---- backpressure -----------------------------------------------------------------------------


async def test_inbound_frame_flood_drops_oldest_and_survives() -> None:
    rig = await make_rig(config=_cfg(inbound_queue_frames=4))
    await rig.start()
    for i in range(500):
        await rig.transport.push(Frame(AudioFrame(b"\x00" * 320, ts_ms=i, seq=i)))
    await rig.advance(50)
    assert rig.session.frames_dropped > 0
    await rig.say("hello there how are you")
    await rig.advance(5000)
    assert rig.user_turns() == ["hello there how are you"]
    summary = await rig.finish()
    assert summary.frames_dropped == rig.session.frames_dropped


async def test_oversized_frames_are_rejected() -> None:
    rig = await make_rig(config=_cfg(max_frame_bytes=100))
    await rig.start()
    await rig.transport.push(Frame(AudioFrame(b"\x00" * 1000, ts_ms=1)))
    await rig.advance(10)
    assert rig.session.frames_rejected == 1
    assert rig.stt.streams[0].frames == []
    await rig.finish()


async def test_playout_backpressure_keeps_the_buffer_bounded() -> None:
    rig = await _start_long_reply(capacity_ms=150)
    for _ in range(30):
        assert rig.transport.queued_ms() <= 150 + 100  # capacity + one chunk
        await rig.advance(100)
    await rig.finish()


async def test_caller_hangup_mid_sentence_records_a_truncated_turn() -> None:
    rig = await _start_long_reply()
    await rig.caller.hangup()
    summary = await rig.finish()
    assert summary.reason == "caller_hangup"
    turns = rig.agent_turns()
    assert len(turns) == 1 and turns[0][1] is True
    ended = [c for c in rig.state.voice_calls if c.phase == "ended"]
    assert len(ended) == 1 and ended[0].reason == "caller_hangup"


async def test_events_are_all_voice_types_and_the_log_replays() -> None:
    from axis_runtime.events import replay

    rig = await make_rig()
    await rig.start()
    await rig.say("hello there how are you")
    await rig.advance(4000)
    await rig.finish()
    events = await rig.rec.log.read(rig.rec.run_id)
    kinds = {e.type for e in events}
    assert {EventType.VOICE_CALL, EventType.VOICE_TURN, EventType.VOICE_STAGE} <= kinds
    assert replay(events) == rig.state


@pytest.mark.parametrize("n", [1, 3])
async def test_sequential_turns(n: int) -> None:
    rig = await make_rig()
    await rig.start()
    for i in range(n):
        await rig.say(f"question number {i} please")
        await rig.advance(4000)
    assert len(rig.user_turns()) == n and len(rig.agent_turns()) == n
    await rig.finish()
