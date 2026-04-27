"""Tests for SwarmAgentMixin."""
from __future__ import annotations

import asyncio
import os
from typing import Sequence
from unittest.mock import patch

import pytest

from argus.swarm import (
    GlobalKillSignal,
    ProbeResult,
    ProbeStatus,
    Surface,
    SwarmAgentMixin,
    SwarmConfig,
    Technique,
    TunerConfig,
    swarm_mode_enabled,
)


# ----------------------------------------------------------------- fixtures
class FakeAgent(SwarmAgentMixin):
    """Minimal agent for exercising the mixin."""

    agent_id = "FAKE-99"

    def __init__(
        self,
        techniques: Sequence[Technique],
        surface_filter=lambda s: True,
        confirm_at: tuple[str, str] | None = None,
        max_confirms: int = 0,
    ) -> None:
        self._techniques = list(techniques)
        self._surface_filter = surface_filter
        self._confirm_at = confirm_at
        self.max_confirms = max_confirms
        self.on_confirm_calls: list[ProbeResult] = []
        self.probe_calls = 0

    def list_techniques(self) -> Sequence[Technique]:
        return self._techniques

    def list_surfaces(self, all_surfaces) -> Sequence[Surface]:
        return [s for s in all_surfaces if self._surface_filter(s)]

    def swarm_config(self) -> SwarmConfig:
        return SwarmConfig(
            tuner=TunerConfig(initial=20),
            stop_on_first_confirm=False,  # let max_confirms control kill
            per_probe_timeout_s=5.0,
        )

    async def run_probe(self, technique, surface) -> ProbeResult:
        self.probe_calls += 1
        await asyncio.sleep(0.01)
        is_target = (
            self._confirm_at is not None
            and (technique.id, surface.id) == self._confirm_at
        )
        return ProbeResult(
            technique_id=technique.id,
            surface_id=surface.id,
            status=ProbeStatus.CONFIRMED if is_target else ProbeStatus.NEGATIVE,
            confirmed=is_target,
        )

    async def on_confirm(self, result: ProbeResult) -> None:
        self.on_confirm_calls.append(result)


def make_techniques(n: int) -> list[Technique]:
    return [Technique(id=f"T-{i:03d}", family="test") for i in range(n)]


def make_surfaces(n: int) -> list[Surface]:
    return [Surface(id=f"S-{i:03d}", target=f"target-{i}") for i in range(n)]


# -------------------------------------------------------------------- tests
def test_swarm_mode_enabled_off_by_default():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ARGUS_SWARM_MODE", None)
        assert swarm_mode_enabled() is False


def test_swarm_mode_enabled_when_set():
    with patch.dict(os.environ, {"ARGUS_SWARM_MODE": "1"}):
        assert swarm_mode_enabled() is True
    with patch.dict(os.environ, {"ARGUS_SWARM_MODE": "true"}):
        assert swarm_mode_enabled() is True
    with patch.dict(os.environ, {"ARGUS_SWARM_MODE": "0"}):
        assert swarm_mode_enabled() is False


@pytest.mark.asyncio
async def test_mixin_runs_full_slate_when_no_max_confirms():
    agent = FakeAgent(techniques=make_techniques(4))
    surfaces = make_surfaces(5)

    results = []
    async for r in agent.run_swarm(surfaces):
        results.append(r)

    assert len(results) == 20  # 4 techniques x 5 surfaces
    assert agent.probe_calls == 20
    assert all(r.metadata["agent_id"] == "FAKE-99" for r in results)
    assert agent.last_swarm_summary is not None
    assert agent.last_swarm_summary.submitted == 20
    assert agent.last_swarm_summary.completed == 20


@pytest.mark.asyncio
async def test_mixin_filters_surfaces():
    agent = FakeAgent(
        techniques=make_techniques(2),
        surface_filter=lambda s: int(s.id.split("-")[1]) % 2 == 0,
    )
    surfaces = make_surfaces(10)

    results = []
    async for r in agent.run_swarm(surfaces):
        results.append(r)

    # Only even-numbered surfaces should be probed: 5 surfaces x 2 techniques.
    assert len(results) == 10
    surface_ids = {r.surface_id for r in results}
    assert surface_ids == {"S-000", "S-002", "S-004", "S-006", "S-008"}


@pytest.mark.asyncio
async def test_mixin_max_confirms_short_circuits():
    techniques = make_techniques(5)
    surfaces = make_surfaces(20)
    target = (techniques[2].id, surfaces[7].id)

    agent = FakeAgent(
        techniques=techniques,
        confirm_at=target,
        max_confirms=1,
    )

    results = []
    async for r in agent.run_swarm(surfaces):
        results.append(r)

    confirmed = [r for r in results if r.confirmed]
    assert len(confirmed) >= 1
    assert len(agent.on_confirm_calls) == len(confirmed)
    # max_confirms=1 should fire kill after first confirm; remaining should
    # be killed-or-completed, but probe_calls should be < submitted.
    assert agent.probe_calls < 100  # 5 x 20 = 100 if it ran the full slate


@pytest.mark.asyncio
async def test_mixin_on_confirm_hook_isolated_from_failures():
    techniques = make_techniques(3)
    surfaces = make_surfaces(5)
    target = (techniques[0].id, surfaces[0].id)

    class BoomAgent(FakeAgent):
        async def on_confirm(self, result):
            self.on_confirm_calls.append(result)
            raise RuntimeError("on_confirm boom")

    agent = BoomAgent(techniques=techniques, confirm_at=target)

    results = []
    async for r in agent.run_swarm(surfaces):
        results.append(r)

    # The on_confirm hook raised, but the swarm continued.
    assert len(agent.on_confirm_calls) >= 1
    assert len(results) == 15  # 3 x 5 — full slate, no max_confirms set


@pytest.mark.asyncio
async def test_mixin_threads_external_kill_signal():
    """A shared GlobalKillSignal stops the agent's swarm mid-flight."""
    techniques = make_techniques(2)
    surfaces = make_surfaces(50)
    kill = GlobalKillSignal()

    class SlowAgent(FakeAgent):
        async def run_probe(self, technique, surface):
            self.probe_calls += 1
            await asyncio.sleep(0.05)
            return ProbeResult(
                technique_id=technique.id,
                surface_id=surface.id,
                status=ProbeStatus.NEGATIVE,
            )

    agent = SlowAgent(techniques=techniques)

    async def fire_after_delay():
        await asyncio.sleep(0.05)
        kill.fire("external test")

    asyncio.create_task(fire_after_delay())

    results = []
    async for r in agent.run_swarm(surfaces, kill_signal=kill):
        results.append(r)

    killed = [r for r in results if r.status == ProbeStatus.KILLED]
    assert len(killed) > 0
    assert kill.is_set()


@pytest.mark.asyncio
async def test_mixin_empty_inputs_are_a_noop():
    agent = FakeAgent(techniques=[])
    surfaces = make_surfaces(5)

    results = []
    async for r in agent.run_swarm(surfaces):
        results.append(r)

    assert results == []
    assert agent.probe_calls == 0
    assert agent.last_swarm_summary is not None
    assert agent.last_swarm_summary.submitted == 0
