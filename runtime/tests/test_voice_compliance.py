"""Consent, PHI redaction and the no-raw-audio rule."""

from __future__ import annotations

import json

import pytest
from axis_runtime.events import replay
from axis_runtime.voice.consent import (
    DEFAULT_NOTICE,
    ConsentConfigError,
    ConsentMode,
    ConsentPolicy,
    classify_consent_speech,
    resolve_consent,
)
from axis_runtime.voice.fakes import FakeTtsProvider
from axis_runtime.voice.phi import PhiMode, redact_transcript
from axis_runtime.voice.session import VoiceSessionConfig
from voice_helpers import make_rig

NOTICE = "This call is recorded and transcribed by an AI assistant."


def _policy(mode: ConsentMode, **kw: object) -> ConsentPolicy:
    return resolve_consent(
        manifest_notice=NOTICE,
        configured=ConsentPolicy(mode=mode, notice=NOTICE, **kw),  # type: ignore[arg-type]
    )


# ---- policy resolution --------------------------------------------------------------------------


def test_manifest_notice_makes_consent_required() -> None:
    p = resolve_consent(manifest_notice="You are talking to an AI.")
    assert p.required and p.mode is ConsentMode.NOTICE and p.notice == "You are talking to an AI."


def test_tenant_policy_makes_consent_required_with_default_text() -> None:
    p = resolve_consent(manifest_notice=None, tenant_requires=True)
    assert p.required and p.mode is ConsentMode.NOTICE and p.notice == DEFAULT_NOTICE


def test_nothing_required_means_no_consent_step() -> None:
    p = resolve_consent(manifest_notice=None)
    assert not p.required and p.mode is ConsentMode.NONE
    assert not resolve_consent(manifest_notice="   ").required


def test_a_required_policy_cannot_be_switched_off() -> None:
    p = resolve_consent(manifest_notice=NOTICE, configured=ConsentPolicy(mode=ConsentMode.NONE))
    assert p.required and p.mode is ConsentMode.NOTICE


def test_required_may_be_stricter_and_keeps_its_own_notice() -> None:
    p = resolve_consent(
        manifest_notice=NOTICE,
        configured=ConsentPolicy(mode=ConsentMode.DTMF, notice="Press 1 to agree."),
    )
    assert p.mode is ConsentMode.DTMF and p.notice == "Press 1 to agree." and p.required


def test_invalid_consent_configs_are_refused() -> None:
    with pytest.raises(ConsentConfigError):
        ConsentPolicy(required=True)
    with pytest.raises(ConsentConfigError):
        ConsentPolicy(mode=ConsentMode.NOTICE, notice="  ")
    with pytest.raises(ConsentConfigError):
        ConsentPolicy(mode=ConsentMode.NOTICE, notice="x", timeout_ms=0)


@pytest.mark.parametrize(
    ("text", "verdict"),
    [
        ("yes", "accept"),
        ("Yes, I agree.", "accept"),
        ("okay go ahead", "accept"),
        ("no", "decline"),
        ("No thanks, hang up", "decline"),
        ("I don't consent", "decline"),
        ("yes no", None),
        ("maybe later", None),
        ("", None),
        ("yesterday", None),  # a substring is not a word
        ("nobody", None),
    ],
)
def test_speech_consent_classification(text: str, verdict: str | None) -> None:
    assert (
        classify_consent_speech(text, ConsentPolicy(mode=ConsentMode.SPEECH, notice="x")) == verdict
    )


@pytest.mark.parametrize(
    "text",
    [
        "that is not okay",
        "I am not okay with that",
        "ok but don't record me",
        "yes... actually never mind, I won't",
        "sure, I cannot agree",
        "okay no",
        "yes I can't",
    ],
)
def test_a_negated_accept_is_never_consent(text: str) -> None:
    """Review: 'that is not okay' contains the accept word 'okay' and no decline phrase, so it granted consent."""
    assert (
        classify_consent_speech(text, ConsentPolicy(mode=ConsentMode.SPEECH, notice="x"))
        != "accept"
    )


# ---- session: notice mode -----------------------------------------------------------------------


async def test_notice_is_played_before_anything_else_and_before_stt_opens() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.NOTICE))
    await rig.start()
    await rig.advance(100)
    assert rig.tts.requests == [NOTICE]
    assert rig.stt.opens == [], "no STT while the notice plays"
    await rig.say("hello there how are you")  # spoken over the notice: ignored
    assert rig.agent.started == 0 and rig.user_turns() == []
    await rig.advance(4000)  # notice finishes
    assert len(rig.stt.opens) == 1
    await rig.say("hello again how are you")
    await rig.advance(4000)
    assert rig.user_turns() == ["hello again how are you"]
    consent = [c for c in rig.state.voice_calls if c.phase == "consent"]
    assert [c.reason for c in consent] == ["granted:notice"]
    assert consent[0].detail["granted"] is True
    assert len(str(consent[0].detail["notice_sha256"])) == 64
    summary = await rig.finish()
    assert summary.consent_granted is True


async def test_speech_during_the_notice_never_reaches_the_transcript_or_agent() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.NOTICE))
    await rig.start()
    await rig.say("my social security number is one two three four five")
    await rig.advance(500)
    await rig.finish()
    log = json.dumps([e.data for e in await rig.rec.log.read(rig.rec.run_id)])
    assert "social" not in log and rig.agent.started == 0


async def test_notice_not_barge_in_able() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.NOTICE))
    await rig.start()
    await rig.advance(300)
    assert rig.transport.queued_ms() > 0
    await rig.say("stop stop stop", word_ms=50)
    assert rig.session.barge_in_latencies_ms == []
    await rig.advance(4000)
    assert [c.reason for c in rig.state.voice_calls if c.phase == "consent"] == ["granted:notice"]
    await rig.finish()


async def test_hangup_during_the_notice_ends_without_consent_and_without_the_agent() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.NOTICE))
    await rig.start()
    await rig.advance(300)
    await rig.caller.hangup()
    summary = await rig.finish()
    assert summary.reason == "caller_hangup" and rig.agent.started == 0
    assert summary.consent_granted is None
    assert rig.stt.opens == []


async def test_notice_that_cannot_be_played_refuses_the_call() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.NOTICE), tts=FakeTtsProvider(None))  # type: ignore[arg-type]
    rig.tts.fail_on = "recorded"
    await rig.start()
    await rig.advance(500)
    summary = await rig.finish()
    assert summary.reason == "consent_notice_failed" and summary.consent_granted is False
    assert rig.agent.started == 0 and rig.stt.opens == []
    refused = [c for c in rig.state.voice_calls if c.phase == "consent"]
    assert refused[0].reason == "refused:notice_not_played"


async def test_no_consent_step_when_not_required() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.advance(10)
    assert [c.reason for c in rig.state.voice_calls if c.phase == "consent"] == ["not_required"]
    assert rig.tts.requests == []
    summary = await rig.finish()
    assert summary.consent_granted is None


# ---- session: DTMF consent ----------------------------------------------------------------------


async def test_dtmf_accept_continues() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.DTMF))
    await rig.start()
    await rig.advance(4000)
    assert rig.stt.opens == [] and rig.agent.started == 0
    await rig.caller.press("1")
    await rig.advance(100)
    assert len(rig.stt.opens) == 1
    await rig.say("hello there how are you")
    await rig.advance(4000)
    assert rig.agent.started == 1
    assert [c.reason for c in rig.state.voice_calls if c.phase == "consent"] == ["granted:dtmf"]
    await rig.finish()


async def test_dtmf_decline_ends_the_call_with_no_agent_and_no_stt() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.DTMF))
    await rig.start()
    await rig.advance(4000)
    await rig.caller.press("2")
    await rig.advance(100)
    summary = await rig.finish()
    assert summary.reason == "consent_declined" and summary.consent_granted is False
    assert rig.agent.started == 0 and rig.stt.opens == []


async def test_dtmf_timeout_refuses() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.DTMF, timeout_ms=5000))
    await rig.start()
    await rig.advance(4000 + 5100)
    summary = await rig.finish()
    assert summary.reason == "consent_timeout" and rig.agent.started == 0


async def test_other_digits_do_not_grant_consent() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.DTMF, timeout_ms=3000))
    await rig.start()
    await rig.advance(4000)
    for d in "3579#":
        await rig.caller.press(d)
    await rig.advance(3100)
    summary = await rig.finish()
    assert summary.reason == "consent_timeout" and rig.agent.started == 0


async def test_digit_pressed_during_the_notice_does_not_count() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.DTMF, timeout_ms=3000))
    await rig.start()
    await rig.advance(300)
    await rig.caller.press("1")  # before the notice has finished
    await rig.advance(4000)
    assert rig.stt.opens == []
    await rig.advance(3100)
    summary = await rig.finish()
    assert summary.reason == "consent_timeout"


# ---- session: spoken consent --------------------------------------------------------------------


async def test_speech_accept_continues_and_is_not_persisted() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.SPEECH))
    await rig.start()
    await rig.advance(4000)
    assert len(rig.stt.opens) == 1
    await rig.say("yes I agree")
    await rig.advance(100)
    assert [c.reason for c in rig.state.voice_calls if c.phase == "consent"] == ["granted:speech"]
    assert rig.user_turns() == []  # the "yes" is the consent record, not a conversation turn
    await rig.say("what is my balance today")
    await rig.advance(4000)
    assert rig.user_turns() == ["what is my balance today"]
    await rig.finish()


async def test_speech_decline_ends_the_call() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.SPEECH))
    await rig.start()
    await rig.advance(4000)
    await rig.say("no thanks")
    await rig.advance(100)
    summary = await rig.finish()
    assert summary.reason == "consent_declined" and rig.agent.started == 0
    assert rig.user_turns() == []


async def test_unclear_speech_waits_then_times_out() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.SPEECH, timeout_ms=4000))
    await rig.start()
    await rig.advance(4000)
    await rig.say("hmm what is this")
    await rig.advance(4100)
    summary = await rig.finish()
    assert summary.reason == "consent_timeout" and rig.agent.started == 0


# ---- PHI ----------------------------------------------------------------------------------------

SSN_LINE = "my social security number is one two three four five six seven eight nine"


@pytest.mark.parametrize(
    "text",
    [
        "my ssn is 123-45-6789",
        "call me on 415 555 0100",
        "it is jane.doe@example.com",
        "jane dot doe at example dot com",
        "born on 03/04/1980",
        "i was born on march 3rd 1980",
        "my member id is AB123456",
        "i live at 221 baker street",
        "my name is Jane Q Public",
        "card 4111 1111 1111 1111",
        SSN_LINE,
        "123​-45-6789",
    ],
)
def test_phi_patterns_are_redacted(text: str) -> None:
    out = redact_transcript(text)
    assert "[REDACTED]" in out
    for secret in (
        "123-45",
        "415 555",
        "jane.doe",
        "example",
        "03/04",
        "march 3",
        "AB123456",
        "baker",
        "Jane",
        "4111",
        "one two three",
    ):
        assert secret not in out, (text, out)


def test_redaction_is_idempotent_and_leaves_plain_text() -> None:
    once = redact_transcript("my ssn is 123-45-6789 and i need a refund")
    assert redact_transcript(once) == once
    assert "refund" in once
    assert redact_transcript("what is the status of my claim") == "what is the status of my claim"


async def test_phi_mode_persists_only_redacted_transcripts() -> None:
    rig = await make_rig(phi=True)
    rig.agent.replies = ["Thanks Jane Doe, I found claim 9988776655 for you."]
    await rig.start()
    await rig.say("my ssn is 123-45-6789 and my name is Jane Doe")
    await rig.advance(5000)
    # the live agent got the raw words (it needs them) ...
    assert "123-45-6789" in rig.agent.requests[0].utterance
    await rig.finish()
    # ... but nothing persisted holds them
    events = await rig.rec.log.read(rig.rec.run_id)
    blob = json.dumps([e.data for e in events])
    for raw in ("123-45-6789", "Jane Doe", "9988776655"):
        assert raw not in blob, raw
    user = [t for t in rig.state.voice_turns if t.role == "user"][0]
    assert user.redacted is True and "[REDACTED]" in user.text
    assert all(t.redacted for t in rig.state.voice_turns)
    assert "123-45" not in " ".join(t.text for t in rig.tw.turns)
    assert replay(events) == rig.state


async def test_phi_omit_mode_stores_no_text_at_all() -> None:
    rig = await make_rig(phi=True, phi_mode=PhiMode.OMIT)
    await rig.start()
    await rig.say("what is the status of my claim")
    await rig.advance(5000)
    await rig.finish()
    turns = rig.state.voice_turns
    assert turns and all(t.text == "" and t.redacted for t in turns)
    assert all(t.text_chars == 0 for t in turns)
    blob = json.dumps([e.data for e in await rig.rec.log.read(rig.rec.run_id)])
    assert "status of my claim" not in blob and "I can help" not in blob


async def test_non_phi_calls_keep_plain_text_and_the_flag_is_honest() -> None:
    rig = await make_rig(phi=False)
    await rig.start()
    await rig.say("my number is 415 555 0100")
    await rig.advance(5000)
    await rig.finish()
    user = [t for t in rig.state.voice_turns if t.role == "user"][0]
    assert user.text == "my number is 415 555 0100" and user.redacted is False


async def test_phi_redaction_also_applies_to_the_consent_and_greeting_turns() -> None:
    rig = await make_rig(phi=True, config=VoiceSessionConfig(greeting="Hello, this is Dr Smith."))
    await rig.start()
    await rig.advance(5000)
    await rig.finish()
    assert all(t.redacted for t in rig.state.voice_turns)


# ---- raw audio ----------------------------------------------------------------------------------


async def test_raw_audio_is_never_stored_only_hash_and_length() -> None:
    rig = await make_rig()
    await rig.start()
    await rig.silence(500)
    await rig.say("hello there how are you")
    await rig.advance(5000)
    await rig.finish()
    user = [t for t in rig.state.voice_turns if t.role == "user"][0]
    assert user.audio_sha256 and len(user.audio_sha256) == 64 and user.audio_bytes > 0
    events = await rig.rec.log.read(rig.rec.run_id)
    blob = json.dumps([e.data for e in events])
    assert "AXIS-STT" not in blob  # the script payload (our stand-in for audio) is not in the log
    assert "TTS|" not in blob
    agent = [t for t in rig.state.voice_turns if t.role == "agent"][0]
    assert agent.audio_sha256 is None and agent.audio_bytes == 0


async def test_audio_hash_covers_only_audio_after_consent() -> None:
    rig = await make_rig(consent=_policy(ConsentMode.NOTICE))
    await rig.start()
    await rig.silence(200)  # during the notice: dropped
    await rig.advance(4000)
    assert rig.session._audio_bytes == 0  # noqa: SLF001
    await rig.finish()
