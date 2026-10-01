"""Harness for voice tests: a loopback call on a virtual clock with scripted agent, STT and TTS."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable, Sequence
from dataclasses import dataclass, field

from axis_runtime.events import InMemoryRunEventLog, RunRecorder
from axis_runtime.nexus.telemetry import InMemoryTracer
from axis_runtime.voice.agent import AgentTurnRequest
from axis_runtime.voice.callrun import start_call_run
from axis_runtime.voice.clock import ManualVoiceClock
from axis_runtime.voice.consent import ConsentPolicy
from axis_runtime.voice.fakes import FakeSttProvider, FakeTtsProvider
from axis_runtime.voice.gateway import LoopbackCaller, LoopbackGateway, LoopbackTransport
from axis_runtime.voice.phi import PhiMode
from axis_runtime.voice.session import VoiceSession, VoiceSessionConfig
from axis_runtime.voice.transcript import TranscriptWriter
from axis_runtime.voice.types import CallSummary
from conftest import TENANT


@dataclass
class ScriptedAgent:
    """AgentTurn: replies in order (the last repeats).  ``deltas`` splits a reply into pieces with
    ``delta_ms`` between them, ``think_ms`` is the delay before the first one."""

    clock: ManualVoiceClock
    replies: Sequence[str] = ("Sure, I can help with that.",)
    think_ms: int = 0
    delta_ms: int = 0
    split: Callable[[str], list[str]] | None = None
    fail: Exception | None = None
    requests: list[AgentTurnRequest] = field(default_factory=list)
    started: int = 0
    finished: int = 0
    cancelled: int = 0

    async def reply(self, request: AgentTurnRequest) -> AsyncGenerator[str, None]:
        self.requests.append(request)
        self.started += 1
        text = self.replies[min(len(self.requests) - 1, len(self.replies) - 1)]
        try:
            if self.think_ms:
                await self.clock.sleep_ms(self.think_ms)
            if self.fail is not None:
                raise self.fail
            pieces = self.split(text) if self.split else [text]
            for piece in pieces:
                yield piece
                if self.delta_ms:
                    await self.clock.sleep_ms(self.delta_ms)
            self.finished += 1
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        except GeneratorExit:
            self.cancelled += 1
            raise


@dataclass
class Rig:
    clock: ManualVoiceClock
    gw: LoopbackGateway
    caller: LoopbackCaller
    transport: LoopbackTransport
    stt: FakeSttProvider
    tts: FakeTtsProvider
    agent: ScriptedAgent
    rec: RunRecorder
    pid: str
    tw: TranscriptWriter
    session: VoiceSession
    tracer: InMemoryTracer
    task: asyncio.Task[CallSummary] | None = None

    async def start(self) -> None:
        self.task = asyncio.create_task(self.session.run())
        await self.caller.connect()
        await self.clock.settle()

    async def say(self, text: str, *, word_ms: int = 250) -> None:
        """The caller speaks ``text`` in virtual time (returns when the words are out)."""
        n = len(text.split())
        t = asyncio.create_task(self.caller.say(text, word_ms=word_ms))
        await self.clock.advance(max(0, n * word_ms))
        await t

    async def silence(self, ms: int, *, step_ms: int = 100) -> None:
        t = asyncio.create_task(self.caller.silence(ms, step_ms=step_ms))
        await self.clock.advance(ms)
        await t

    async def advance(self, ms: int) -> None:
        await self.clock.advance(ms)

    async def finish(self) -> CallSummary:
        assert self.task is not None
        if not self.task.done():
            await self.caller.hangup()
            await self.clock.settle()
        return await asyncio.wait_for(self.task, 5)

    @property
    def state(self):  # type: ignore[no-untyped-def]
        return self.rec.state

    def user_turns(self) -> list[str]:
        return [t.text for t in self.state.voice_turns if t.role == "user"]

    def agent_turns(self) -> list[tuple[str, bool]]:
        return [(t.text, t.truncated) for t in self.state.voice_turns if t.role == "agent"]


async def make_rig(
    *,
    agent: ScriptedAgent | None = None,
    config: VoiceSessionConfig | None = None,
    consent: ConsentPolicy | None = None,
    phi: bool = False,
    phi_mode: PhiMode = PhiMode.REDACT,
    stt_latency_ms: int = 0,
    tts: FakeTtsProvider | None = None,
    capacity_ms: int = 200,
    stt: FakeSttProvider | None = None,
) -> Rig:
    clock = ManualVoiceClock()
    gw = LoopbackGateway(clock, capacity_ms=capacity_ms)
    caller = gw.dial_in(TENANT, "+14155550100", "+14155550199")
    transport = caller.transport
    rec, pid = await start_call_run(
        InMemoryRunEventLog(),
        clock,
        tenant_id=TENANT,
        call_id=transport.info.call_id,
        agent="support",
        version="1.0.0",
    )
    tw = TranscriptWriter(rec, pid, transport.info.call_id, phi=phi, phi_mode=phi_mode)
    stt = stt or FakeSttProvider(clock, latency_ms=stt_latency_ms)
    tts = tts or FakeTtsProvider(clock)
    agent = agent or ScriptedAgent(clock)
    tracer = InMemoryTracer()
    session = VoiceSession(
        transport=transport,
        stt=stt,
        tts=tts,
        agent=agent,
        transcript=tw,
        clock=clock,
        config=config,
        consent=consent,
        tracer=tracer,
    )
    return Rig(clock, gw, caller, transport, stt, tts, agent, rec, pid, tw, session, tracer)
