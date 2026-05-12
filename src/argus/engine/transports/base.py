"""Transport protocol — the interface every transport implements.

A transport is the wire between ARGUS-ENGINE and a target. It accepts a
``Variant`` (which carries messages, tools, resources, and a canary set)
and returns a ``ProbeResult`` (response text, observed tool calls, OOB
hits, streaming timings, refusal flag).

Transports are async. Streaming-capable transports populate
``streaming_timings`` so the latency-fingerprint matcher can run.

Each transport declares ``supported_surfaces`` — the set of attack
surfaces the wire actually carries. ``"chat"`` is the universal floor.
``"session_state"`` is only present on transports that thread real
server-tracked turns (cookies / ``X-Session-Id`` / ``conversation_id``).
The strategy navigator merges this into ``available_surfaces`` so
classes whose ``target_surface`` requires session state are filtered
out on chat-only transports without spending budget.
"""

from __future__ import annotations

from typing import ClassVar, Protocol, runtime_checkable

from ..core.variant import Variant
from ..grading.matcher import ProbeResult


@runtime_checkable
class Transport(Protocol):
    name: str
    supported_surfaces: ClassVar[frozenset[str]]

    async def probe(self, variant: Variant) -> ProbeResult:
        """Send the variant to the target and observe its behavior."""
        ...

    async def aclose(self) -> None:
        """Release any open connections / streams."""
        ...
