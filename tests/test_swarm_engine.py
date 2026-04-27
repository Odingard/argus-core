"""Tests for SwarmProbeEngine — parallelism, kill switch, exception isolation, streaming."""
from __future__ import annotations

import asyncio
import time

import pytest

from argus.swarm import (
    GlobalKillSignal,
    ProbeResult,
    ProbeStatus,
    Surface,
    SwarmConfig,
    SwarmProbeEngine,
    Technique,
    TunerConfig,
)


# --------------------------------------------------------------------- helpers
def make_techniques(n: int) -> list[Technique]:
    return [Technique(id=f"T-{i:03d}", family="test") for i in range(n)]


def make_surfaces(n: int) -> list[Surface]:
    return [Surface(id=f"S-{i:03d}", target=f"target-{i}") for i in range(n)]


def fixed_delay_probe(delay_ms: float):
    async def probe(t: Technique, s: Surface) -> ProbeResult:
        await asyncio.sleep(delay_ms / 1000)
        return ProbeResult(
            technique_id=t.id,
            surface_id=s.id,
            status=ProbeStatus.NEGATIVE,
            response="ok",
        )
    return probe


# ----------------------------------------------------------------------- tests
@pytest.mark.asyncio
async def test_empty_run_completes_immediately():
    engine = SwarmProbeEngine(probe_fn=fixed_delay_probe(10))
    results = []
    async for r in engine.run([], []):
        results.append(r)
    assert results == []
    assert engine.stats.submitted == 0


@pytest.mark.asyncio
async def test_parallelism_beats_sequential_by_an_order_of_magnitude():
    """50 probes × 100ms each: sequential = 5s, swarm with cap 50 ≈ 0.1s."""
    techniques = make_techniques(1)
    surfaces = make_surfaces(50)
    config = SwarmConfig(
        tuner=TunerConfig(initial=50, minimum=10),
        stop_on_first_confirm=False,
    )
    engine = SwarmProbeEngine(probe_fn=fixed_delay_probe(100), config=config)

    start = time.monotonic()
    count = 0
    async for _ in engine.run(techniques, surfaces):
        count += 1
    elapsed = time.monotonic() - start

    assert count == 50
    assert elapsed < 1.0, f"swarm took {elapsed:.2f}s — should be ~0.1s"


@pytest.mark.asyncio
async def test_first_confirm_fires_global_kill():
    """When stop_on_first_confirm=True, the engine kills remaining work."""
    confirmed_at = 5

    async def probe(t: Technique, s: Surface) -> ProbeResult:
        await asyncio.sleep(0.05)
        idx = int(s.id.split("-")[1])
        return ProbeResult(
            technique_id=t.id,
            surface_id=s.id,
            status=ProbeStatus.CONFIRMED if idx == confirmed_at else ProbeStatus.NEGATIVE,
            confirmed=(idx == confirmed_at),
        )

    techniques = make_techniques(1)
    surfaces = make_surfaces(100)
    config = SwarmConfig(
        tuner=TunerConfig(initial=4),
        stop_on_first_confirm=True,
    )
    engine = SwarmProbeEngine(probe_fn=probe, config=config)

    confirmed = 0
    async for r in engine.run(techniques, surfaces):
        if r.confirmed:
            confirmed += 1

    assert confirmed >= 1
    assert engine.kill.is_set()
    assert "confirmed:" in (engine.kill.reason or "")
    assert engine.stats.confirmed >= 1
    assert engine.stats.killed > 0


@pytest.mark.asyncio
async def test_exception_isolation_does_not_break_swarm():
    """A probe that raises returns ProbeStatus.ERROR; swarm continues."""

    async def flaky_probe(t: Technique, s: Surface) -> ProbeResult:
        idx = int(s.id.split("-")[1])
        if idx % 3 == 0:
            raise RuntimeError(f"boom on {s.id}")
        await asyncio.sleep(0.01)
        return ProbeResult(
            technique_id=t.id, surface_id=s.id, status=ProbeStatus.NEGATIVE
        )

    techniques = make_techniques(1)
    surfaces = make_surfaces(30)
    engine = SwarmProbeEngine(
        probe_fn=flaky_probe,
        config=SwarmConfig(stop_on_first_confirm=False),
    )

    errored = 0
    negative = 0
    async for r in engine.run(techniques, surfaces):
        if r.status == ProbeStatus.ERROR:
            errored += 1
            assert r.error is not None and "boom" in r.error
        elif r.status == ProbeStatus.NEGATIVE:
            negative += 1

    assert errored == 10  # surfaces 0, 3, 6, ..., 27
    assert negative == 20
    assert engine.stats.errored == 10


@pytest.mark.asyncio
async def test_per_probe_timeout_returns_error():
    async def hanging_probe(t: Technique, s: Surface) -> ProbeResult:
        await asyncio.sleep(10)
        return ProbeResult(technique_id=t.id, surface_id=s.id, status=ProbeStatus.NEGATIVE)

    config = SwarmConfig(
        tuner=TunerConfig(initial=5),
        per_probe_timeout_s=0.1,
        stop_on_first_confirm=False,
    )
    engine = SwarmProbeEngine(probe_fn=hanging_probe, config=config)

    results = []
    async for r in engine.run(make_techniques(1), make_surfaces(3)):
        results.append(r)

    assert len(results) == 3
    assert all(r.status == ProbeStatus.ERROR for r in results)
    assert all("timeout" in (r.error or "") for r in results)


@pytest.mark.asyncio
async def test_results_stream_incrementally():
    """Results yield as they complete, not in one batch at the end."""

    async def probe(t: Technique, s: Surface) -> ProbeResult:
        idx = int(s.id.split("-")[1])
        await asyncio.sleep(0.02 * (idx + 1))  # staggered completion
        return ProbeResult(technique_id=t.id, surface_id=s.id, status=ProbeStatus.NEGATIVE)

    config = SwarmConfig(
        tuner=TunerConfig(initial=10),
        stop_on_first_confirm=False,
    )
    engine = SwarmProbeEngine(probe_fn=probe, config=config)

    arrival_times: list[float] = []
    start = time.monotonic()
    async for _ in engine.run(make_techniques(1), make_surfaces(5)):
        arrival_times.append(time.monotonic() - start)

    spread = arrival_times[-1] - arrival_times[0]
    assert spread > 0.05, f"results arrived in a single batch (spread={spread:.3f}s)"


@pytest.mark.asyncio
async def test_external_kill_short_circuits_run():
    async def slow_probe(t: Technique, s: Surface) -> ProbeResult:
        await asyncio.sleep(0.05)
        return ProbeResult(technique_id=t.id, surface_id=s.id, status=ProbeStatus.NEGATIVE)

    kill = GlobalKillSignal()
    config = SwarmConfig(
        tuner=TunerConfig(initial=4),
        stop_on_first_confirm=False,
    )
    engine = SwarmProbeEngine(probe_fn=slow_probe, config=config, kill_signal=kill)

    async def fire_after_delay():
        await asyncio.sleep(0.05)
        kill.fire("external test", fired_by="pytest")

    asyncio.create_task(fire_after_delay())

    results = []
    async for r in engine.run(make_techniques(1), make_surfaces(50)):
        results.append(r)

    killed = sum(1 for r in results if r.status == ProbeStatus.KILLED)
    assert killed > 0
    assert engine.kill.is_set()


def test_hot_surfaces_ranking():
    results = [
        ProbeResult(technique_id="T-0", surface_id="S-A", status=ProbeStatus.NEGATIVE,
                    latency_ms=100, response="data"),
        ProbeResult(technique_id="T-1", surface_id="S-A", status=ProbeStatus.NEGATIVE,
                    latency_ms=200, response="data"),
        ProbeResult(technique_id="T-0", surface_id="S-B", status=ProbeStatus.NEGATIVE,
                    latency_ms=2000),  # slow, no response
        ProbeResult(technique_id="T-0", surface_id="S-C", status=ProbeStatus.ERROR,
                    latency_ms=50, error="boom"),  # ignored
    ]
    hot = SwarmProbeEngine.hot_surfaces(results, top_n=2)
    assert hot[0] == "S-A"
    assert "S-C" not in hot
