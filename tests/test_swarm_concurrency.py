"""Tests for AdaptiveConcurrencyTuner and ResizableSemaphore."""
from __future__ import annotations

import asyncio

import pytest

from argus.swarm.concurrency import (
    AdaptiveConcurrencyTuner,
    ResizableSemaphore,
    TunerConfig,
)


@pytest.mark.asyncio
async def test_resizable_semaphore_basic_acquire_release():
    sem = ResizableSemaphore(2)
    await sem.acquire()
    await sem.acquire()
    assert sem.in_flight == 2

    async def third():
        await sem.acquire()

    task = asyncio.create_task(third())
    await asyncio.sleep(0.05)
    assert not task.done()  # blocked at capacity

    await sem.release()
    await asyncio.wait_for(task, timeout=0.5)
    assert sem.in_flight == 2


@pytest.mark.asyncio
async def test_resizable_semaphore_grow_unblocks_waiters():
    sem = ResizableSemaphore(1)
    await sem.acquire()

    blocked: list[asyncio.Task] = [
        asyncio.create_task(sem.acquire()) for _ in range(3)
    ]
    await asyncio.sleep(0.02)
    assert all(not t.done() for t in blocked)

    await sem.set_capacity(4)
    await asyncio.wait_for(asyncio.gather(*blocked), timeout=0.5)
    assert sem.in_flight == 4


@pytest.mark.asyncio
async def test_resizable_semaphore_shrink_blocks_new_acquires():
    sem = ResizableSemaphore(5)
    for _ in range(3):
        await sem.acquire()
    assert sem.in_flight == 3

    await sem.set_capacity(2)
    new_task = asyncio.create_task(sem.acquire())
    await asyncio.sleep(0.05)
    assert not new_task.done()

    await sem.release()  # in_flight 2, still at capacity
    await asyncio.sleep(0.02)
    assert not new_task.done()

    await sem.release()  # in_flight 1, room for one
    await asyncio.wait_for(new_task, timeout=0.5)


@pytest.mark.asyncio
async def test_tuner_grows_on_low_latency():
    config = TunerConfig(
        initial=10, target_p95_ms=1000, sample_window=20,
        cooldown_seconds=0.0, growth_factor=2.0,
    )
    tuner = AdaptiveConcurrencyTuner(config)
    for _ in range(20):
        tuner.record(100)  # well below target

    new = await tuner.maybe_adjust()
    assert new > 10


@pytest.mark.asyncio
async def test_tuner_shrinks_on_high_latency():
    config = TunerConfig(
        initial=50, target_p95_ms=1000, sample_window=20,
        cooldown_seconds=0.0, backoff_factor=0.5, minimum=4,
    )
    tuner = AdaptiveConcurrencyTuner(config)
    for _ in range(20):
        tuner.record(5000)

    new = await tuner.maybe_adjust()
    assert new < 50
    assert new >= config.minimum


@pytest.mark.asyncio
async def test_tuner_holds_in_target_band():
    config = TunerConfig(
        initial=20, target_p95_ms=1000, sample_window=20,
        cooldown_seconds=0.0,
    )
    tuner = AdaptiveConcurrencyTuner(config)
    for _ in range(20):
        tuner.record(900)  # within 0.7x–1.2x of target

    new = await tuner.maybe_adjust()
    assert new == 20


@pytest.mark.asyncio
async def test_tuner_respects_cooldown():
    config = TunerConfig(
        initial=10, target_p95_ms=1000, sample_window=20,
        cooldown_seconds=10.0,
    )
    tuner = AdaptiveConcurrencyTuner(config)
    for _ in range(20):
        tuner.record(100)

    first = await tuner.maybe_adjust()  # adjusts
    for _ in range(20):
        tuner.record(100)
    second = await tuner.maybe_adjust()  # cooldown blocks

    assert second == first
