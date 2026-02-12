"""Seeded async scheduler controlling runtime determinism."""

from __future__ import annotations
from collections.abc import Awaitable, Callable

import asyncio
import random
from dataclasses import dataclass

@dataclass(slots=True)
class SchedulerConfig:
    seed: int
    operation_timeout: float = 30.0
    heartbeat_seconds: float = 5.0

class SeededScheduler:
    """Seeded deterministic scheduler for coordinating timed operations.

    Consumes from a per-run RNG seed to guarantee reproducible ordering
    of concurrent operations.
    """

    def __init__(self, config: SchedulerConfig | None = None, *, seed: int | None = None) -> None:
        """Initialize the seeded scheduler.

        Prefer passing a ``SchedulerConfig`` instance, but retain backwards
        compatibility with ``SeededScheduler(seed=42)`` used in tests and
        potential external callers.
        """

        if config is None:
            if seed is None:
                raise TypeError("SeededScheduler requires either config or seed")
            config = SchedulerConfig(seed=seed)

        self.config = config
        self._rng = random.Random(config.seed)

    async def sleep(self, minimum: float, jitter: float = 0.0) -> None:
        """Deterministic sleep helper with optional jitter."""

        delay = minimum
        if jitter:
            delay += self._rng.uniform(0.0, jitter)
        await asyncio.sleep(delay)

    async def run_with_timeout(self, coro: Awaitable, *, timeout: float | None = None):
        """Run coroutine with scheduler defaults applied."""

        effective_timeout = timeout or self.config.operation_timeout
        return await asyncio.wait_for(coro, timeout=effective_timeout)

    def random(self) -> float:
        """Expose RNG for deterministic draws."""

        return self._rng.random()

    def choice(self, items: list):
        """Choice helper sourced from the seeded RNG."""

        return self._rng.choice(items)
