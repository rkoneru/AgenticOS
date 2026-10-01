"""The SIP / WebRTC gateway seam and an in-process loopback fake.

A real telephony stack (SIP trunking, RTP media, WebRTC SFU, STIR/SHAKEN, carrier interconnect) is
NOT built (docs/NEEDS.md).  ``CallGateway`` is what the session host needs from one: inbound calls
arrive as ``AudioTransport`` objects, outbound calls are originated by number and become a transport
once answered.  ``LoopbackGateway`` implements it in memory on a ``VoiceClock``: the "caller" is a
``LoopbackCaller`` the test (or a demo) drives, and playout is paced in clock time so barge-in
timing can be asserted in virtual milliseconds.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field, replace
from typing import Protocol

from axis_runtime.voice.clock import VoiceClock
from axis_runtime.voice.fakes import caller_script, plain_frame
from axis_runtime.voice.interfaces import AudioTransport
from axis_runtime.voice.types import (
    AudioFrame,
    CallInfo,
    Connected,
    Direction,
    Dtmf,
    Frame,
    Hangup,
    TransportEvent,
)


class TransportClosedError(ConnectionError):
    pass


@dataclass(frozen=True)
class OriginateRequest:
    tenant_id: str
    to_number: str
    from_number: str = ""
    call_id: str = ""
    ring_timeout_ms: int = 30_000


@dataclass(frozen=True)
class OriginatedCall:
    call_id: str
    status: str  # "ringing" | "answered"


class CallGateway(Protocol):
    def incoming(self) -> AsyncIterator[AudioTransport]: ...

    async def originate(self, request: OriginateRequest) -> OriginatedCall: ...

    async def transport_for(self, call_id: str) -> AudioTransport:
        """The transport of an originated call, once it is answered (raises if it never is)."""
        ...


@dataclass
class HeardChunk:
    data: bytes
    duration_ms: int  # what the caller actually heard (shorter than the chunk if it was cleared)
    started_ms: int
    partial: bool = False


class LoopbackTransport:
    """AudioTransport over an asyncio queue.  Playout drains one chunk at a time in clock time."""

    def __init__(
        self,
        info: CallInfo,
        clock: VoiceClock,
        *,
        capacity_ms: int = 200,
        event_queue: int = 4096,
    ) -> None:
        self.info = info
        self._clock = clock
        self._capacity = capacity_ms
        self._events: asyncio.Queue[TransportEvent] = asyncio.Queue(maxsize=event_queue)
        self._out: list[tuple[bytes, int]] = []
        self._current: tuple[bytes, int, int] | None = None
        self._wake = asyncio.Event()
        self._space = asyncio.Event()
        self._drain: asyncio.Task[None] | None = None
        self.heard: list[HeardChunk] = []
        self.hung_up: str | None = None
        self.clears: list[int] = []  # ms discarded by each clear_output
        self.clear_at: list[int] = []  # clock time of each clear_output

    # ---- AudioTransport ------------------------------------------------------------------
    async def events(self) -> AsyncIterator[TransportEvent]:
        while True:
            event = await self._events.get()
            yield event
            if isinstance(event, Hangup):
                return

    async def send_audio(self, data: bytes, duration_ms: int) -> None:
        while self.queued_ms() > 0 and self.queued_ms() + duration_ms > self._capacity:
            if self.hung_up is not None:
                break
            self._space.clear()
            await self._space.wait()
        if self.hung_up is not None:
            raise TransportClosedError(self.hung_up)
        self._out.append((data, duration_ms))
        if self._drain is None or self._drain.done():
            self._drain = asyncio.create_task(self._drain_loop())
        self._wake.set()

    def queued_ms(self) -> int:
        total = sum(d for _, d in self._out)
        if self._current is not None:
            _, dur, started = self._current
            total += max(0, dur - (self._clock.now_ms() - started))
        return total

    async def clear_output(self) -> int:
        discarded = self.queued_ms()
        if self._drain is not None and not self._drain.done():
            self._drain.cancel()
            await asyncio.gather(self._drain, return_exceptions=True)
        if self._current is not None:
            data, dur, started = self._current
            played = max(0, min(dur, self._clock.now_ms() - started))
            self.heard.append(HeardChunk(data, played, started, partial=played < dur))
            self._current = None
        self._out.clear()
        self.clears.append(discarded)
        self.clear_at.append(self._clock.now_ms())
        self._space.set()
        return discarded

    async def hangup(self, reason: str) -> None:
        if self.hung_up is None:
            self.hung_up = reason
        if self._drain is not None and not self._drain.done():
            self._drain.cancel()
            await asyncio.gather(self._drain, return_exceptions=True)
        self._space.set()
        # the far end learns of the hangup too
        if not self._events.full():
            self._events.put_nowait(Hangup(reason))

    # ---- playout -------------------------------------------------------------------------
    async def _drain_loop(self) -> None:
        while True:
            if not self._out:
                self._wake.clear()
                await self._wake.wait()
                continue
            data, dur = self._out.pop(0)
            self._current = (data, dur, self._clock.now_ms())
            started = self._current[2]
            await self._clock.sleep_ms(dur)
            self.heard.append(HeardChunk(data, dur, started))
            self._current = None
            self._space.set()

    # ---- the far end ---------------------------------------------------------------------
    async def push(self, event: TransportEvent) -> None:
        await self._events.put(event)

    def heard_ms(self) -> int:
        return sum(h.duration_ms for h in self.heard)


@dataclass
class LoopbackCaller:
    """The caller's side of a loopback call: say things, press keys, hang up."""

    transport: LoopbackTransport
    clock: VoiceClock
    _seq: int = field(default=0, repr=False)

    async def connect(self) -> None:
        await self.transport.push(Connected(self.transport.info))

    async def _frame(self, frame: AudioFrame) -> None:
        await self.transport.push(Frame(frame))

    async def say(self, text: str, *, word_ms: int = 250) -> None:
        """Speak ``text`` in clock time: one directive frame per word, then the final."""
        frames = caller_script(text, start_ms=self.clock.now_ms(), word_ms=word_ms)
        for i, f in enumerate(frames):
            await self._frame(replace(f, seq=self._next(), duration_ms=word_ms))
            if i < len(frames) - 1:  # words are word_ms apart; the final follows the last word
                await self.clock.sleep_ms(word_ms)

    async def silence(self, ms: int, *, step_ms: int = 100) -> None:
        elapsed = 0
        while elapsed < ms:
            step = min(step_ms, ms - elapsed)
            await self._frame(plain_frame(self.clock.now_ms(), self._next(), step))
            await self.clock.sleep_ms(step)
            elapsed += step

    async def press(self, digit: str) -> None:
        await self.transport.push(Dtmf(digit, self.clock.now_ms()))

    async def hangup(self, reason: str = "caller_hangup") -> None:
        await self.transport.push(Hangup(reason))

    def _next(self) -> int:
        self._seq += 1
        return self._seq


class LoopbackGateway:
    """In-process CallGateway: ``dial_in`` simulates an inbound call, ``answer`` an outbound one."""

    def __init__(self, clock: VoiceClock, *, capacity_ms: int = 200) -> None:
        self.clock = clock
        self._capacity = capacity_ms
        self._incoming: asyncio.Queue[LoopbackTransport] = asyncio.Queue()
        self._outbound: dict[str, LoopbackTransport] = {}
        self._answered: dict[str, asyncio.Event] = {}
        self.originated: list[OriginateRequest] = []
        self._n = 0

    def _new(
        self, direction: Direction, tenant: str, frm: str, to: str, call_id: str = ""
    ) -> LoopbackTransport:
        self._n += 1
        info = CallInfo(call_id or f"call-{self._n}", direction, frm, to, tenant)
        return LoopbackTransport(info, self.clock, capacity_ms=self._capacity)

    def dial_in(self, tenant_id: str, from_number: str, to_number: str) -> LoopbackCaller:
        transport = self._new(Direction.INBOUND, tenant_id, from_number, to_number)
        self._incoming.put_nowait(transport)
        return LoopbackCaller(transport, self.clock)

    async def incoming(self) -> AsyncIterator[AudioTransport]:
        while True:
            yield await self._incoming.get()

    async def originate(self, request: OriginateRequest) -> OriginatedCall:
        self.originated.append(request)
        transport = self._new(
            Direction.OUTBOUND,
            request.tenant_id,
            request.from_number,
            request.to_number,
            request.call_id,
        )
        call_id = transport.info.call_id
        self._outbound[call_id] = transport
        self._answered[call_id] = asyncio.Event()
        return OriginatedCall(call_id, "ringing")

    def answer(self, call_id: str) -> LoopbackCaller:
        self._answered[call_id].set()
        return LoopbackCaller(self._outbound[call_id], self.clock)

    async def transport_for(self, call_id: str) -> AudioTransport:
        event = self._answered.get(call_id)
        if event is None:
            raise KeyError(call_id)
        await event.wait()
        return self._outbound[call_id]
