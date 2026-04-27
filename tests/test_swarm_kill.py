"""Tests for GlobalKillSignal — idempotency, wait, provenance, guard."""
from __future__ import annotations

import asyncio

import pytest

from argus.swarm import GlobalKillSignal


@pytest.mark.asyncio
async def test_kill_signal_basic():
    kill = GlobalKillSignal()
    assert not kill.is_set()
    fired = kill.fire("test", fired_by="pytest")
    assert fired is True
    assert kill.is_set()
    assert kill.reason == "test"
    assert kill.fired_by == "pytest"


@pytest.mark.asyncio
async def test_kill_signal_idempotent():
    kill = GlobalKillSignal()
    assert kill.fire("first", fired_by="A") is True
    assert kill.fire("second", fired_by="B") is False
    assert kill.reason == "first"
    assert kill.fired_by == "A"


@pytest.mark.asyncio
async def test_kill_signal_wait_returns_when_fired():
    kill = GlobalKillSignal()

    async def fire_later():
        await asyncio.sleep(0.05)
        kill.fire("delayed")

    asyncio.create_task(fire_later())
    await asyncio.wait_for(kill.wait(), timeout=0.5)
    assert kill.is_set()


@pytest.mark.asyncio
async def test_kill_signal_guard_raises_when_already_fired():
    kill = GlobalKillSignal()
    kill.fire("preset")

    with pytest.raises(asyncio.CancelledError):
        async with kill.guard():
            pass


@pytest.mark.asyncio
async def test_kill_signal_guard_passes_when_unfired():
    kill = GlobalKillSignal()
    entered = False
    async with kill.guard() as k:
        entered = True
        assert k is kill
    assert entered
