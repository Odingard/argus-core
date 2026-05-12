"""Passive recon sources.

Each source returns a list of :class:`Observation` records. Sources do
not enforce scope — the orchestrator (``recon.passive``) filters every
observation through the operator-supplied :class:`~..scope.Scope`
before any further processing.

All sources are passive: they query third-party indexes (Certificate
Transparency, free DNS APIs, Wayback) — they do not connect to the
target's own infrastructure. The first network packet that touches a
target host is sent by ``recon.fingerprint`` only when ``--active`` is
explicitly enabled by the operator.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Observation:
    """A single subdomain / host observation from a passive source."""

    host: str
    source: str
    first_seen: str = ""
    record_type: str = ""
    extra: tuple[tuple[str, str], ...] = field(default_factory=tuple)
