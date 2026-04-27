"""Global kill signal shared across all probes in a swarm session.

When the first probe confirms an exploitable finding, the engine fires the
kill switch. In-flight probes finish their current syscall and return
ProbeStatus.KILLED. Pending tasks are cancelled by the engine.

This is the mechanism that lets the Gang-of-Thirty stop work the instant
*any* agent confirms a finding — no agent runs to completion uselessly.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator


class GlobalKillSignal:
    """Cooperative kill signal. Wraps an asyncio.Event with provenance fields."""

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._reason: str | None = None
        self._fired_by: str | None = None

    def is_set(self) -> bool:
        return self._event.is_set()

    def fire(self, reason: str, fired_by: str | None = None) -> bool:
        """Idempotent — first caller wins, subsequent calls no-op."""
        if self._event.is_set():
            return False
        self._reason = reason
        self._fired_by = fired_by
        self._event.set()
        return True

    async def wait(self) -> None:
        await self._event.wait()

    @property
    def reason(self) -> str | None:
        return self._reason

    @property
    def fired_by(self) -> str | None:
        return self._fired_by

    @asynccontextmanager
    async def guard(self) -> AsyncIterator["GlobalKillSignal"]:
        """Probes can use `async with kill.guard():` to abort fast on entry."""
        if self._event.is_set():
            raise asyncio.CancelledError("Killed before start")
        yield self
