"""Tests for WaveController — Day 2 of the SwarmProbeEngine sprint."""
from __future__ import annotations

import asyncio

import pytest

from argus.swarm import (
    ProbeResult,
    ProbeStatus,
    Surface,
    SwarmConfig,
    Technique,
    TunerConfig,
)
from argus.swarm.waves import Wave, WaveController


def make_techniques(prefix: str, n: int) -> list[Technique]:
    return [Technique(id=f"{prefix}-{i:02d}", family=prefix) for i in range(n)]


def make_surfaces(n: int) -> list[Surface]:
    return [Surface(id=f"S-{i:02d}", target=f"target-{i}") for i in range(n)]


@pytest.mark.asyncio
async def test_single_wave_streams_results_with_metadata():
    async def probe(t, s):
        await asyncio.sleep(0.01)
        return ProbeResult(
            technique_id=t.id, surface_id=s.id, status=ProbeStatus.NEGATIVE
        )

    controller = WaveController(
        probe_fn=probe,
        config=SwarmConfig(stop_on_first_confirm=False),
    )
    waves = [Wave(name="solo",
                  techniques=make_techniques("T", 2),
                  surfaces=make_surfaces(3))]

    results = []
    async for r in controller.execute_waves(waves):
        results.append(r)

    assert len(results) == 6
    assert all(r.metadata.get("wave") == "solo" for r in results)
    assert len(controller.wave_results) == 1
    assert not controller.wave_results[0].skipped


@pytest.mark.asyncio
async def test_three_wave_carryover_narrows_targets():
    """Hot surfaces from fingerprint narrow saturation; saturation narrows exploitation."""

    async def probe(t, s):
        await asyncio.sleep(0.005)
        idx = int(s.id.split("-")[1])
        responsive = idx < 5  # only first 5 surfaces "respond"
        return ProbeResult(
            technique_id=t.id,
            surface_id=s.id,
            status=ProbeStatus.NEGATIVE,
            response="data" if responsive else None,
            latency_ms=100 if responsive else 0,
        )

    controller = WaveController(
        probe_fn=probe,
        config=SwarmConfig(stop_on_first_confirm=False,
                           tuner=TunerConfig(initial=20)),
    )
    surfaces = make_surfaces(20)
    waves = WaveController.standard_three_wave(
        all_surfaces=surfaces,
        fingerprint_techniques=make_techniques("FP", 1),
        saturation_techniques=make_techniques("SAT", 1),
        exploitation_techniques=make_techniques("EXP", 1),
        hot_top_n=5,
    )

    async for _ in controller.execute_waves(waves):
        pass

    fp, sat, exp = controller.wave_results
    assert fp.wave_name == "fingerprint"
    assert len(fp.results) == 20  # all surfaces probed in fingerprint
    assert len(fp.hot_surfaces) == 5

    assert sat.wave_name == "saturation"
    assert len(sat.results) == 5  # narrowed via fingerprint's hot list

    assert exp.wave_name == "exploitation"
    assert len(exp.results) == 5  # narrowed via saturation's hot list


@pytest.mark.asyncio
async def test_kill_short_circuits_remaining_waves():
    """A confirmation in one wave fires the kill — later waves are skipped."""

    confirm_pair = ("FP-00", "S-02")

    async def probe(t, s):
        await asyncio.sleep(0.01)
        is_confirm = (t.id, s.id) == confirm_pair
        return ProbeResult(
            technique_id=t.id, surface_id=s.id,
            status=ProbeStatus.CONFIRMED if is_confirm else ProbeStatus.NEGATIVE,
            confirmed=is_confirm,
            response="ok" if is_confirm else None,
        )

    controller = WaveController(
        probe_fn=probe,
        config=SwarmConfig(stop_on_first_confirm=True),
    )
    waves = WaveController.standard_three_wave(
        all_surfaces=make_surfaces(5),
        fingerprint_techniques=make_techniques("FP", 1),
        saturation_techniques=make_techniques("SAT", 1),
        exploitation_techniques=make_techniques("EXP", 1),
        hot_top_n=3,
    )

    confirmed = []
    async for r in controller.execute_waves(waves):
        if r.confirmed:
            confirmed.append(r)

    assert len(confirmed) >= 1
    assert controller.kill.is_set()

    sat = controller.wave_results[1]
    exp = controller.wave_results[2]
    assert sat.skipped
    assert exp.skipped
    assert "kill signal" in sat.skip_reason


@pytest.mark.asyncio
async def test_narrow_to_hot_falls_back_when_no_prior_heat():
    """If a wave declares narrow_to_previous_hot first, falls back to full surfaces."""

    async def probe(t, s):
        await asyncio.sleep(0.005)
        return ProbeResult(
            technique_id=t.id, surface_id=s.id, status=ProbeStatus.NEGATIVE
        )

    controller = WaveController(
        probe_fn=probe,
        config=SwarmConfig(stop_on_first_confirm=False),
    )
    waves = [
        Wave(name="orphan",
             techniques=make_techniques("T", 1),
             surfaces=make_surfaces(3),
             narrow_to_previous_hot=True),  # no prior wave
    ]

    results = []
    async for r in controller.execute_waves(waves):
        results.append(r)

    assert len(results) == 3
    assert not controller.wave_results[0].skipped
