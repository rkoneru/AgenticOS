"""Retries with jitter and a per-provider circuit breaker (injectable clock and RNG)."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol


class ModelClock(Protocol):
    def monotonic(self) -> float: ...
    def now(self) -> datetime: ...
    async def sleep(self, seconds: float) -> None: ...


class SystemModelClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(UTC)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class Rng(Protocol):
    def uniform(self, a: float, b: float) -> float: ...


def default_rng() -> Rng:
    return random.Random()  # noqa: S311 - jitter, not security


@dataclass(frozen=True)
class RetryPolicy:
    """Exponential backoff with FULL jitter: delay ~ U(0, min(max_delay, base * 2**(n-1)))."""

    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 8.0

    def delay(self, attempt: int, rng: Rng, retry_after: float | None = None) -> float:
        ceiling = min(self.max_delay, self.base_delay * 2 ** (attempt - 1))
        delay = rng.uniform(0.0, ceiling)
        if (
            retry_after is not None
        ):  # server hint is a floor, bounded so a bad header cannot stall us
            delay = max(delay, min(retry_after, self.max_delay))
        return delay


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Opens after ``failure_threshold`` consecutive failures; after ``reset_timeout`` it lets ONE
    probe through (half-open): success closes it, failure re-opens it."""

    def __init__(
        self, clock: ModelClock, failure_threshold: int = 5, reset_timeout: float = 30.0
    ) -> None:
        self._clock = clock
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False

    @property
    def state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self._clock.monotonic() - self._opened_at >= self.reset_timeout:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    def allow(self) -> bool:
        state = self.state
        if state is BreakerState.CLOSED:
            return True
        if state is BreakerState.HALF_OPEN and not self._probe_in_flight:
            self._probe_in_flight = True
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._probe_in_flight = False

    def record_failure(self) -> None:
        self._probe_in_flight = False
        self._failures += 1
        if self._opened_at is not None or self._failures >= self.failure_threshold:
            self._opened_at = self._clock.monotonic()
