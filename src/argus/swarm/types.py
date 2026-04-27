"""Core types for the swarm probe engine.

These are the shared data contracts every agent (EP-11, SC-09, TP-02, ME-10, ...)
will use when handing work to the swarm. Probe functions are just async callables
that take (technique, surface) and return a ProbeResult.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Optional


class ProbeStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    NEGATIVE = "negative"
    ERROR = "error"
    KILLED = "killed"


@dataclass
class Surface:
    """A target attack surface — a tool, endpoint, transport, parameter, etc."""

    id: str
    target: str
    transport: str = "stdio"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Technique:
    """An attack technique (e.g., EP-T12 shell injection, SC-T04 SSRF)."""

    id: str
    family: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeResult:
    """The outcome of running a single (technique, surface) probe."""

    technique_id: str
    surface_id: str
    status: ProbeStatus
    latency_ms: float = 0.0
    payload: Optional[str] = None
    response: Optional[str] = None
    confirmed: bool = False
    error: Optional[str] = None
    started_at: float = field(default_factory=time.monotonic)
    finished_at: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# Probe contract: an async function that runs one technique against one surface.
ProbeFn = Callable[[Technique, Surface], Awaitable[ProbeResult]]
