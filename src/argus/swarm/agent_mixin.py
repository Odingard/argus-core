"""argus/swarm/agent_mixin.py — generic swarm wiring for any Gang-of-Thirty agent.

Goal: let any agent migrate to SwarmProbeEngine without re-implementing the
common scaffolding (probe-fn adaptation, kill threading, FindingsBus
publishing, max-confirms early stop, surface/technique filtering).

Usage in an agent:

    class EP11Agent(SwarmAgentMixin, BaseAgent):
        agent_id = "EP-11"

        def list_techniques(self):
            return [t for t in self.TECHNIQUES.values() if t.kind != "catalog"]

        def list_surfaces(self, all_surfaces):
            return [s for s in all_surfaces if not _is_skipped(s)]

        async def run_probe(self, technique, surface):
            # The single (technique, surface) probe — same logic as the legacy
            # inner loop, just extracted into one async function.
            ...

        async def execute(self, surfaces, *, swarm: bool = False):
            if swarm:
                async for finding in self.run_swarm(surfaces):
                    self.record(finding)
            else:
                # legacy path — unchanged
                ...

The mixin is additive. Agents keep their legacy execution path. They opt in
by calling self.run_swarm(surfaces) when ARGUS_SWARM_MODE=1 (or another
agent-chosen condition).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Optional,
    Sequence,
)

from argus.swarm.engine import SwarmConfig, SwarmProbeEngine
from argus.swarm.kill import GlobalKillSignal
from argus.swarm.types import ProbeResult, ProbeStatus, Surface, Technique

log = logging.getLogger("argus.swarm.agent_mixin")


def swarm_mode_enabled() -> bool:
    """Single source of truth for the swarm-mode feature flag.

    Set ARGUS_SWARM_MODE=1 in the environment to enable swarm execution
    on agents that have opted in via SwarmAgentMixin.
    """
    return os.environ.get("ARGUS_SWARM_MODE", "").strip() in {"1", "true", "True"}


@dataclass
class SwarmRunSummary:
    """Per-agent run summary the agent records back to its session."""

    agent_id: str
    submitted: int = 0
    completed: int = 0
    confirmed: int = 0
    errored: int = 0
    killed: int = 0
    elapsed_s: float = 0.0
    confirmed_results: list[ProbeResult] = field(default_factory=list)


class SwarmAgentMixin:
    """Mixin that gives any agent a parallel-probe execution path.

    Subclasses MUST provide:
        - agent_id: str
        - run_probe(technique, surface) -> ProbeResult (async)
        - list_techniques() -> Sequence[Technique]
        - list_surfaces(all_surfaces) -> Sequence[Surface]

    Subclasses MAY override:
        - max_confirms: int — stop after this many confirmed findings (0 = no cap)
        - swarm_config() -> SwarmConfig — engine config (concurrency, timeout, etc.)
        - on_confirm(result) — async hook fired per confirmed finding (publish
          to FindingsBus, etc.)
    """

    # Subclasses override.
    agent_id: str = "UNSET"
    max_confirms: int = 0  # 0 = no cap, run the full slate

    # ---------------------------------------------------------- subclass API
    async def run_probe(
        self, technique: Technique, surface: Surface
    ) -> ProbeResult:  # pragma: no cover - abstract
        raise NotImplementedError(
            f"{type(self).__name__}.run_probe must be implemented"
        )

    def list_techniques(self) -> Sequence[Technique]:  # pragma: no cover
        raise NotImplementedError(
            f"{type(self).__name__}.list_techniques must be implemented"
        )

    def list_surfaces(
        self, all_surfaces: Sequence[Any]
    ) -> Sequence[Surface]:  # pragma: no cover
        raise NotImplementedError(
            f"{type(self).__name__}.list_surfaces must be implemented"
        )

    def swarm_config(self) -> SwarmConfig:
        return SwarmConfig()

    async def on_confirm(self, result: ProbeResult) -> None:
        """Hook for agents to publish to FindingsBus / record into session."""
        return None


    # --------------------------------------------------------------- runner
    async def run_swarm(
        self,
        all_surfaces: Sequence[Any],
        *,
        kill_signal: Optional[GlobalKillSignal] = None,
    ) -> AsyncIterator[ProbeResult]:
        """Stream probe results as they complete.

        Wires the agent's probe-fn into a fresh SwarmProbeEngine, threads in
        the session's GlobalKillSignal (so cross-agent kill propagation works),
        applies max_confirms early-stop, and fires on_confirm() per confirmed
        finding so subclasses can publish to FindingsBus without touching the
        engine.
        """
        techniques = list(self.list_techniques())
        surfaces = list(self.list_surfaces(all_surfaces))

        if not techniques or not surfaces:
            log.info(
                "%s.run_swarm noop: techniques=%d surfaces=%d",
                self.agent_id, len(techniques), len(surfaces),
            )
            self._last_swarm_summary = SwarmRunSummary(agent_id=self.agent_id)
            return

        engine = SwarmProbeEngine(
            probe_fn=self.run_probe,  # type: ignore[arg-type]
            config=self.swarm_config(),
            kill_signal=kill_signal,
        )
        confirmed_count = 0
        confirmed_results: list[ProbeResult] = []

        log.info(
            "%s.run_swarm start techniques=%d surfaces=%d max_confirms=%d",
            self.agent_id, len(techniques), len(surfaces), self.max_confirms,
        )

        async for result in engine.run(techniques, surfaces):
            # Tag every result with the agent that produced it for downstream
            # report rendering and FindingsBus correlation.
            result.metadata.setdefault("agent_id", self.agent_id)

            if result.confirmed or result.status == ProbeStatus.CONFIRMED:
                confirmed_count += 1
                confirmed_results.append(result)
                try:
                    await self.on_confirm(result)
                except Exception:
                    log.exception(
                        "%s.on_confirm raised — continuing", self.agent_id,
                    )
                if self.max_confirms and confirmed_count >= self.max_confirms:
                    await engine.fire_global_kill(
                        f"{self.agent_id} max_confirms={self.max_confirms} reached"
                    )

            yield result

        self._last_swarm_summary = SwarmRunSummary(
            agent_id=self.agent_id,
            submitted=engine.stats.submitted,
            completed=engine.stats.completed,
            confirmed=engine.stats.confirmed,
            errored=engine.stats.errored,
            killed=engine.stats.killed,
            elapsed_s=engine.stats.elapsed_s,
            confirmed_results=confirmed_results,
        )
        log.info(
            "%s.run_swarm done submitted=%d completed=%d confirmed=%d "
            "errored=%d killed=%d elapsed=%.2fs",
            self.agent_id,
            engine.stats.submitted,
            engine.stats.completed,
            engine.stats.confirmed,
            engine.stats.errored,
            engine.stats.killed,
            engine.stats.elapsed_s,
        )

    @property
    def last_swarm_summary(self) -> Optional[SwarmRunSummary]:
        return getattr(self, "_last_swarm_summary", None)
