"""WaveController — sequence parallel probe waves with heat-rank carryover.

Day 2 of the SwarmProbeEngine sprint. Built on top of SwarmProbeEngine.

A "wave" is a single ``engine.run(techniques, surfaces)`` call — all probes
execute in parallel up to the adaptive concurrency limit. Waves run
sequentially, with optional heat-rank carryover between them so each wave
narrows its target set to the surfaces the previous wave found most
responsive.

The canonical three-wave plan:

    fingerprint  →  hot surfaces  →  saturation  →  hot surfaces  →  exploitation
       (cheap)         (top N)       (heavier)        (top N)        (full slate)

All waves share a single GlobalKillSignal — first confirmed finding from
any wave terminates the rest.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional, Sequence

from argus.swarm.engine import SwarmConfig, SwarmProbeEngine, SwarmStats
from argus.swarm.kill import GlobalKillSignal
from argus.swarm.types import ProbeFn, ProbeResult, Surface, Technique

log = logging.getLogger("argus.swarm.waves")


@dataclass
class Wave:
    """A single parallel-probe phase within a multi-wave engagement."""

    name: str
    techniques: Sequence[Technique]
    surfaces: Sequence[Surface] = field(default_factory=tuple)
    heat_rank_top_n: Optional[int] = None
    narrow_to_previous_hot: bool = False
    description: str = ""


@dataclass
class WaveResult:
    """Outcome of one wave — the per-wave slice the report renderer needs."""

    wave_name: str
    elapsed_s: float
    stats: SwarmStats
    results: list[ProbeResult]
    confirmed: list[ProbeResult]
    hot_surfaces: list[str]
    skipped: bool = False
    skip_reason: str = ""


class WaveController:
    """Sequence parallel probe waves over a shared GlobalKillSignal."""

    def __init__(
        self,
        probe_fn: ProbeFn,
        config: Optional[SwarmConfig] = None,
        kill_signal: Optional[GlobalKillSignal] = None,
    ) -> None:
        self.probe_fn = probe_fn
        self.config = config or SwarmConfig()
        self.kill = kill_signal or GlobalKillSignal()
        self.wave_results: list[WaveResult] = []

    async def execute_waves(
        self, waves: Sequence[Wave]
    ) -> AsyncIterator[ProbeResult]:
        """Run waves sequentially, streaming each wave's results inline."""
        self.wave_results = []
        previous_hot_ids: Optional[list[str]] = None

        for wave in waves:
            if self.kill.is_set():
                self.wave_results.append(
                    self._skipped(wave, reason="kill signal already fired")
                )
                continue

            effective_surfaces, skip = self._narrow_surfaces(
                wave, previous_hot_ids
            )
            if skip:
                self.wave_results.append(self._skipped(wave, reason=skip))
                continue

            log.info(
                "wave %s start techniques=%d surfaces=%d",
                wave.name, len(wave.techniques), len(effective_surfaces),
            )

            engine = SwarmProbeEngine(
                probe_fn=self.probe_fn,
                config=self.config,
                kill_signal=self.kill,
            )
            wave_results: list[ProbeResult] = []
            start = time.monotonic()

            async for r in engine.run(wave.techniques, effective_surfaces):
                r.metadata.setdefault("wave", wave.name)
                wave_results.append(r)
                yield r

            elapsed = time.monotonic() - start
            confirmed = [r for r in wave_results if r.confirmed]
            hot_ids: list[str] = []
            if wave.heat_rank_top_n is not None:
                hot_ids = SwarmProbeEngine.hot_surfaces(
                    wave_results, top_n=wave.heat_rank_top_n,
                )
                previous_hot_ids = hot_ids

            log.info(
                "wave %s end elapsed=%.2fs results=%d confirmed=%d hot=%d",
                wave.name, elapsed, len(wave_results),
                len(confirmed), len(hot_ids),
            )

            self.wave_results.append(WaveResult(
                wave_name=wave.name,
                elapsed_s=elapsed,
                stats=engine.stats,
                results=wave_results,
                confirmed=confirmed,
                hot_surfaces=hot_ids,
            ))

    # ------------------------------------------------------------- internals
    def _narrow_surfaces(
        self,
        wave: Wave,
        previous_hot_ids: Optional[list[str]],
    ) -> tuple[list[Surface], str]:
        """Apply heat-rank carryover. Returns (effective_surfaces, skip_reason)."""
        if not wave.narrow_to_previous_hot:
            return list(wave.surfaces), ""
        if previous_hot_ids is None:
            log.info(
                "wave %s requested narrow_to_previous_hot but no prior "
                "heat-rank — using full surface list",
                wave.name,
            )
            return list(wave.surfaces), ""

        hot_set = set(previous_hot_ids)
        narrowed = [s for s in wave.surfaces if s.id in hot_set]
        if not narrowed:
            return [], (
                f"no surfaces in previous hot set ({len(hot_set)}) "
                f"intersect this wave's surfaces ({len(wave.surfaces)})"
            )
        return narrowed, ""

    @staticmethod
    def _skipped(wave: Wave, reason: str) -> WaveResult:
        return WaveResult(
            wave_name=wave.name,
            elapsed_s=0.0,
            stats=SwarmStats(),
            results=[],
            confirmed=[],
            hot_surfaces=[],
            skipped=True,
            skip_reason=reason,
        )

    # ----------------------------------------------------------- factories
    @staticmethod
    def standard_three_wave(
        all_surfaces: Sequence[Surface],
        fingerprint_techniques: Sequence[Technique],
        saturation_techniques: Sequence[Technique],
        exploitation_techniques: Sequence[Technique],
        hot_top_n: int = 10,
    ) -> list[Wave]:
        """Factory: the canonical fingerprint → saturation → exploitation plan."""
        return [
            Wave(
                name="fingerprint",
                techniques=fingerprint_techniques,
                surfaces=all_surfaces,
                heat_rank_top_n=hot_top_n,
                description="Cheap probes to identify responsive surfaces.",
            ),
            Wave(
                name="saturation",
                techniques=saturation_techniques,
                surfaces=all_surfaces,
                narrow_to_previous_hot=True,
                heat_rank_top_n=hot_top_n,
                description="Heavy probes concentrated on hottest surfaces.",
            ),
            Wave(
                name="exploitation",
                techniques=exploitation_techniques,
                surfaces=all_surfaces,
                narrow_to_previous_hot=True,
                description="Full exploitation slate against confirmed-warm surfaces.",
            ),
        ]
