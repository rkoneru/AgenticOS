"""Millisecond clocks for the voice pipeline.

Every timer in the pipeline (endpointing silence, idle and call-length limits, playout pacing,
barge-in latency) goes through a ``VoiceClock`` so tests drive them with ``ManualVoiceClock`` and
assert in virtual milliseconds.  ``ManualVoiceClock`` is also a run-log ``Clock`` so recorded
timestamps follow virtual time.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from typing import Protocol


class VoiceClock(Protocol):
    def now_ms(self) -> int: ...

    async def sleep_ms(self, ms: int) -> None: ...


class SystemVoiceClock:
    def __init__(self) -> None:
        self._origin = time.monotonic()
        self._wall = datetime.now(UTC)

    def now_ms(self) -> int:
        return int((time.monotonic() - self._origin) * 1000)

    def now(self) -> datetime:
        return self._wall + timedelta(milliseconds=self.now_ms())

    async def sleep_ms(self, ms: int) -> None:
        await asyncio.sleep(max(0, ms) / 1000)


class ManualVoiceClock:
    """Deterministic virtual clock.  ``sleep_ms`` parks until ``advance`` reaches the deadline.

    ``advance(ms)`` moves time forward in timer order, letting every task that a firing timer wakes
    run to its next suspension point before the next timer fires (``settle`` yields to the loop).
    """

    def __init__(
        self, start_ms: int = 0, *, epoch: datetime | None = None, settle: int = 25
    ) -> None:
        self._now = start_ms
        self._epoch = epoch or datetime(2026, 1, 1, tzinfo=UTC)
        self._timers: list[tuple[int, int, asyncio.Future[None]]] = []
        self._seq = 0
        self._settle = settle
        self.sleeps: list[int] = []

    def now_ms(self) -> int:
        return self._now

    def now(self) -> datetime:
        # strictly increasing sub-millisecond ordering is not needed: the run log orders by seq
        return self._epoch + timedelta(milliseconds=self._now)

    @property
    def pending_timers(self) -> int:
        return sum(1 for _, _, f in self._timers if not f.done())

    async def sleep_ms(self, ms: int) -> None:
        self.sleeps.append(ms)
        if ms <= 0:
            await asyncio.sleep(0)
            return
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._seq += 1
        self._timers.append((self._now + ms, self._seq, fut))
        self._timers.sort(key=lambda t: (t[0], t[1]))
        await fut

    async def settle(self) -> None:
        for _ in range(self._settle):
            await asyncio.sleep(0)

    async def advance(self, ms: int) -> None:
        """Move virtual time forward by ``ms``, firing due timers in order."""
        target = self._now + ms
        await self.settle()
        while True:
            self._timers = [t for t in self._timers if not t[2].done()]
            due = [t for t in self._timers if t[0] <= target]
            if not due:
                break
            deadline, _, fut = due[0]
            self._timers.remove(due[0])
            self._now = max(self._now, deadline)
            if not fut.done():
                fut.set_result(None)
            await self.settle()
        self._now = target
        await self.settle()
