"""SwarmProbeEngine — parallel probe orchestrator.

Replaces the legacy sequential pattern that ate 3,124 requests / 90 minutes
on node-code-sandbox-mcp:

    for technique in techniques:
        for surface in surfaces:
            result = await probe(technique, surface)   # SEQUENTIAL

With:

    engine = SwarmProbeEngine(probe_fn=probe)
    async for result in engine.run(techniques, surfaces):
        report.ingest(result)

Probes execute concurrently up to the adaptive semaphore limit. The first
confirmed result fires the global kill signal (configurable). Exceptions in
individual probes are isolated — one bad probe does not crash the swarm.

Wave architecture (Day 2's WaveController) is built on top of this engine.
A wave is just a single `engine.run(...)` call with a curated subset of
techniques × surfaces.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from itertools import product
from typing import AsyncIterator, Iterable, Optional, Sequence

from argus.swarm.concurrency import AdaptiveConcurrencyTuner, TunerConfig
from argus.swarm.kill import GlobalKillSignal
from argus.swarm.results import StreamingResultQueue
from argus.swarm.types import ProbeFn, ProbeResult, ProbeStatus, Surface, Technique

log = logging.getLogger("argus.swarm")


@dataclass
class SwarmConfig:
    tuner: TunerConfig = field(default_factory=TunerConfig)
    queue_max: int = 1024
    stop_on_first_confirm: bool = True
    per_probe_timeout_s: float = 30.0
    return_exceptions: bool = True


@dataclass
class SwarmStats:
    submitted: int = 0
    completed: int = 0
    confirmed: int = 0
    errored: int = 0
    killed: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def elapsed_s(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.finished_at or time.monotonic()
        return end - self.started_at


class SwarmProbeEngine:
    """Parallel probe orchestrator with adaptive concurrency and global kill."""

    def __init__(
        self,
        probe_fn: ProbeFn,
        config: Optional[SwarmConfig] = None,
        kill_signal: Optional[GlobalKillSignal] = None,
    ) -> None:
        self.probe_fn = probe_fn
        self.config = config or SwarmConfig()
        self.kill = kill_signal or GlobalKillSignal()
        self.tuner = AdaptiveConcurrencyTuner(self.config.tuner)
        self.stats = SwarmStats()
        self._results = StreamingResultQueue(maxsize=self.config.queue_max)
        self._tasks: list[asyncio.Task] = []

    # ------------------------------------------------------------------ probe
    async def _run_one(self, technique: Technique, surface: Surface) -> ProbeResult:
        if self.kill.is_set():
            return self._killed_result(technique, surface, latency_ms=0.0)

        sem = self.tuner.semaphore
        await sem.acquire()
        start = time.monotonic()
        try:
            if self.kill.is_set():
                return self._killed_result(technique, surface, latency_ms=0.0)

            try:
                result = await asyncio.wait_for(
                    self.probe_fn(technique, surface),
                    timeout=self.config.per_probe_timeout_s,
                )
            except asyncio.TimeoutError:
                return self._error_result(
                    technique, surface, start,
                    error=f"timeout after {self.config.per_probe_timeout_s}s",
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not self.config.return_exceptions:
                    raise
                return self._error_result(
                    technique, surface, start,
                    error=f"{type(exc).__name__}: {exc}",
                )

            latency_ms = (time.monotonic() - start) * 1000
            self.tuner.record(latency_ms)
            if result.finished_at is None:
                result.finished_at = time.monotonic()
            if not result.latency_ms:
                result.latency_ms = latency_ms

            if (result.confirmed or result.status == ProbeStatus.CONFIRMED) and \
                    self.config.stop_on_first_confirm:
                self.kill.fire(
                    reason=f"confirmed:{technique.id}@{surface.id}",
                    fired_by=f"{technique.id}/{surface.id}",
                )
            return result
        finally:
            await sem.release()

    def _killed_result(
        self, technique: Technique, surface: Surface, latency_ms: float
    ) -> ProbeResult:
        return ProbeResult(
            technique_id=technique.id,
            surface_id=surface.id,
            status=ProbeStatus.KILLED,
            latency_ms=latency_ms,
            finished_at=time.monotonic(),
        )

    def _error_result(
        self,
        technique: Technique,
        surface: Surface,
        start: float,
        error: str,
    ) -> ProbeResult:
        return ProbeResult(
            technique_id=technique.id,
            surface_id=surface.id,
            status=ProbeStatus.ERROR,
            latency_ms=(time.monotonic() - start) * 1000,
            error=error,
            finished_at=time.monotonic(),
        )

    # --------------------------------------------------------------- consumer
    async def _consume_one(self, technique: Technique, surface: Surface) -> None:
        try:
            result = await self._run_one(technique, surface)
        except asyncio.CancelledError:
            self.stats.killed += 1
            await self._results.put(self._killed_result(technique, surface, 0.0))
            return

        self.stats.completed += 1
        if result.status == ProbeStatus.CONFIRMED or result.confirmed:
            self.stats.confirmed += 1
        elif result.status == ProbeStatus.ERROR:
            self.stats.errored += 1
        elif result.status == ProbeStatus.KILLED:
            self.stats.killed += 1
        await self._results.put(result)
        await self.tuner.maybe_adjust()

    # -------------------------------------------------------------------- run
    async def run(
        self,
        techniques: Sequence[Technique],
        surfaces: Sequence[Surface],
    ) -> AsyncIterator[ProbeResult]:
        """Submit techniques × surfaces and stream results as they complete."""
        self.stats = SwarmStats(started_at=time.monotonic())
        self._results = StreamingResultQueue(maxsize=self.config.queue_max)
        self._tasks = []

        pairs = list(product(techniques, surfaces))
        self.stats.submitted = len(pairs)
        log.info(
            "swarm.run.start submitted=%d concurrency=%d",
            len(pairs),
            self.tuner.current,
        )

        producer = asyncio.create_task(self._submit_all(pairs))

        try:
            async for result in self._results.stream():
                yield result
        finally:
            self.stats.finished_at = time.monotonic()
            if not producer.done():
                producer.cancel()
                try:
                    await producer
                except (asyncio.CancelledError, Exception):
                    pass
            for t in self._tasks:
                if not t.done():
                    t.cancel()
            log.info(
                "swarm.run.end submitted=%d completed=%d confirmed=%d "
                "errored=%d killed=%d elapsed=%.2fs",
                self.stats.submitted,
                self.stats.completed,
                self.stats.confirmed,
                self.stats.errored,
                self.stats.killed,
                self.stats.elapsed_s,
            )

    async def _submit_all(self, pairs: list[tuple[Technique, Surface]]) -> None:
        try:
            for technique, surface in pairs:
                if self.kill.is_set():
                    break
                self._tasks.append(
                    asyncio.create_task(self._consume_one(technique, surface))
                )
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
        finally:
            await self._results.close()

    async def fire_global_kill(self, reason: str) -> None:
        self.kill.fire(reason=reason, fired_by="external")


    # --------------------------------------------------------- wave utilities
    @staticmethod
    def hot_surfaces(
        results: "Iterable[ProbeResult]", top_n: int = 10
    ) -> list[str]:
        """Heat ranking — used by WaveController (Day 2) to focus exploitation.

        A surface is "hot" if probes against it returned non-empty responses
        and/or low-latency replies. ERROR results are ignored.
        """
        scores: dict[str, float] = {}
        for r in results:
            if r.status == ProbeStatus.ERROR:
                continue
            score = 1.0
            if r.response:
                score += 2.0
            if 0 < r.latency_ms < 500:
                score += 1.0
            scores[r.surface_id] = scores.get(r.surface_id, 0.0) + score
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return [sid for sid, _ in ranked[:top_n]]
