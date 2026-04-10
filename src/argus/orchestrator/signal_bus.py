"""Inter-agent signal bus.

Agents signal partial findings to the Correlation Agent and to each other
in real time. When Agent 1 finds a prompt injection that reaches the file
system, Agent 7 is immediately notified to look for tool calls that write
to external storage.

Security: All shared state is protected by async lock. Handler lists are
snapshot-copied before iteration to prevent race conditions.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

MAX_SIGNAL_HISTORY = 10_000


class SignalType(str, Enum):
    FINDING = "finding"
    PARTIAL_FINDING = "partial_finding"
    TECHNIQUE_RESULT = "technique_result"
    AGENT_STATUS = "agent_status"
    CORRELATION_REQUEST = "correlation_request"


@dataclass
class Signal:
    """A message on the inter-agent signal bus."""

    signal_type: SignalType
    source_agent: str
    source_instance: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    target_agent: str | None = None  # None = broadcast to all


class SignalBus:
    """Async pub/sub bus for inter-agent communication.

    All 10 attack agents and the Correlation Agent share this bus.
    Signals are delivered in real time as they are produced.

    Thread safety: all mutations and reads of shared state are protected
    by an async lock. Handler lists are snapshot-copied under the lock
    before delivery to prevent race conditions during iteration.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable]] = {}
        self._broadcast_subscribers: list[Callable] = []
        self._history: list[Signal] = []
        self._lock = asyncio.Lock()

    async def subscribe(self, agent_id: str, handler: Callable) -> None:
        """Subscribe an agent to receive targeted signals."""
        async with self._lock:
            if agent_id not in self._subscribers:
                self._subscribers[agent_id] = []
            self._subscribers[agent_id].append(handler)

    async def subscribe_broadcast(self, handler: Callable) -> None:
        """Subscribe to all broadcast signals (used by Correlation Agent)."""
        async with self._lock:
            self._broadcast_subscribers.append(handler)

    async def emit(self, signal: Signal) -> None:
        """Emit a signal to targeted agent(s) or broadcast.

        Snapshot-copies handler lists under the lock to prevent race
        conditions if subscriptions change during delivery.
        """
        async with self._lock:
            self._history.append(signal)
            # Enforce history size limit to prevent unbounded memory growth
            if len(self._history) > MAX_SIGNAL_HISTORY:
                self._history = self._history[-MAX_SIGNAL_HISTORY:]

            # Snapshot handler lists under the lock
            broadcast_handlers = list(self._broadcast_subscribers)
            targeted_handlers = (
                list(self._subscribers[signal.target_agent])
                if signal.target_agent and signal.target_agent in self._subscribers
                else []
            )

        logger.debug(
            "Signal [%s] from %s -> %s",
            signal.signal_type.value,
            signal.source_agent,
            signal.target_agent or "BROADCAST",
        )

        # Deliver to broadcast subscribers (Correlation Agent) — outside lock
        for handler in broadcast_handlers:
            try:
                await handler(signal)
            except Exception as exc:
                logger.error("Broadcast handler error: %s", exc)

        # Deliver to targeted agent — outside lock
        for handler in targeted_handlers:
            try:
                await handler(signal)
            except Exception as exc:
                logger.error("Targeted handler error for %s: %s", signal.target_agent, exc)

    async def get_history(self) -> list[Signal]:
        """Return a copy of signal history (thread-safe)."""
        async with self._lock:
            return list(self._history)

    async def clear(self) -> None:
        """Clear all subscriptions and history (thread-safe)."""
        async with self._lock:
            self._subscribers.clear()
            self._broadcast_subscribers.clear()
            self._history.clear()
