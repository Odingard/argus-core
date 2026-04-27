"""Streaming result queue.

The legacy pattern collected results into a list and processed them after the
final probe. The swarm pattern needs results to flow out *as they arrive* so
the kill switch fires the moment a confirmation lands and downstream consumers
(report renderer, judge agent, etc.) can start processing without blocking.

Implementation: a bounded asyncio.Queue with a sentinel value to signal
completion. Consumers iterate via `async for r in queue.stream():`.
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator

from argus.swarm.types import ProbeResult


class StreamingResultQueue:
    """Bounded asyncio.Queue with sentinel-based completion."""

    SENTINEL: object = object()

    def __init__(self, maxsize: int = 1024) -> None:
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._closed = False

    async def put(self, result: ProbeResult) -> None:
        if self._closed:
            return
        await self._queue.put(result)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._queue.put(self.SENTINEL)

    async def stream(self) -> AsyncIterator[ProbeResult]:
        while True:
            item = await self._queue.get()
            if item is self.SENTINEL:
                return
            yield item

    @property
    def closed(self) -> bool:
        return self._closed
