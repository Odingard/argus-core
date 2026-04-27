"""Adaptive concurrency tuner.

Algorithm:
  - Maintain a rolling window of probe latencies (last N samples).
  - Every cooldown_seconds, examine p95 latency:
      p95 > 1.2x target  → shrink capacity by backoff_factor
      p95 < 0.7x target  → grow capacity by growth_factor
      otherwise          → hold steady
  - Capacity changes are applied to a ResizableSemaphore that the engine
    uses to gate every probe.

Saturation points by target type (empirical, from ARGUS run logs):
  - Single Node.js process MCP server: 30-50 concurrent
  - Multi-worker MCP server:           100-200
  - Kubernetes-deployed MCP fleet:     500+
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque


@dataclass
class TunerConfig:
    initial: int = 30
    minimum: int = 4
    maximum: int = 500
    target_p95_ms: float = 1500.0
    backoff_factor: float = 0.8
    growth_factor: float = 1.5
    sample_window: int = 50
    cooldown_seconds: float = 2.0


class ResizableSemaphore:
    """asyncio semaphore with dynamic capacity. Standard library doesn't ship one."""

    def __init__(self, capacity: int) -> None:
        self._capacity = max(1, capacity)
        self._held = 0
        self._cond = asyncio.Condition()

    async def acquire(self) -> None:
        async with self._cond:
            while self._held >= self._capacity:
                await self._cond.wait()
            self._held += 1

    async def release(self) -> None:
        async with self._cond:
            self._held = max(0, self._held - 1)
            self._cond.notify_all()

    async def set_capacity(self, n: int) -> None:
        async with self._cond:
            self._capacity = max(1, n)
            self._cond.notify_all()

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def in_flight(self) -> int:
        return self._held


class AdaptiveConcurrencyTuner:
    """Watches probe latencies and resizes the semaphore to stay below saturation."""

    def __init__(self, config: TunerConfig | None = None) -> None:
        self.config = config or TunerConfig()
        self._current = self.config.initial
        self._sem = ResizableSemaphore(self._current)
        self._latencies: Deque[float] = deque(maxlen=self.config.sample_window)
        self._last_adjust = time.monotonic()
        self._lock = asyncio.Lock()
        self._history: list[tuple[float, int, float]] = []  # (ts, capacity, p95)

    @property
    def semaphore(self) -> ResizableSemaphore:
        return self._sem

    @property
    def current(self) -> int:
        return self._current

    @property
    def history(self) -> list[tuple[float, int, float]]:
        return list(self._history)

    def record(self, latency_ms: float) -> None:
        self._latencies.append(latency_ms)

    def _p95(self) -> float:
        sorted_lat = sorted(self._latencies)
        idx = max(0, int(len(sorted_lat) * 0.95) - 1)
        return sorted_lat[idx]

    async def maybe_adjust(self) -> int:
        now = time.monotonic()
        if now - self._last_adjust < self.config.cooldown_seconds:
            return self._current
        if len(self._latencies) < max(10, self.config.sample_window // 5):
            return self._current

        async with self._lock:
            if now - self._last_adjust < self.config.cooldown_seconds:
                return self._current  # double-check after await
            self._last_adjust = now
            p95 = self._p95()
            target = self.config.target_p95_ms

            if p95 > target * 1.2:
                new = max(self.config.minimum, int(self._current * self.config.backoff_factor))
            elif p95 < target * 0.7:
                new = min(self.config.maximum, int(self._current * self.config.growth_factor))
            else:
                new = self._current

            if new != self._current:
                await self._sem.set_capacity(new)
                self._current = new

            self._history.append((now, self._current, p95))
            return self._current
