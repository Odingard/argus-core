"""
argus/engagement/registry.py — URL-scheme → target-factory registry.

Every target class (labrat OR live-transport adapter) registers a
factory here. The engage runner looks up the scheme from the
operator-supplied URL and calls the factory to get a configured
BaseAdapter.

    register_target(
        scheme="crewai",
        factory=lambda url: CrewAILabrat(),
        description="In-process crewAI-shaped labrat",
        agent_selection=("SC-09","TP-02","ME-10","PI-01","MP-03",
                         "IS-04","XE-06","PE-07","EP-11"),
    )

``agent_selection`` lets each target declare which agents make
sense against it — HTTP-agent targets probably skip IS-04 (no
handoff surface), memory-free targets skip MP-03, etc. The runner
falls back to the full roster when a target doesn't specify.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

from argus.adapter.base import BaseAdapter


TargetFactory = Callable[[str], BaseAdapter]
"""Given an engage URL, return a connected-ready BaseAdapter instance."""


# Full Phase-1..Pillar roster. Individual target schemes can narrow.
DEFAULT_AGENT_SLATE: tuple[str, ...] = (
    "SC-09", "TP-02", "ME-10", "PI-01", "MP-03",
    "IS-04", "XE-06", "PE-07", "EP-11", "CW-05", "RC-08",
)


@dataclass
class TargetSpec:
    scheme:          str
    factory:         TargetFactory
    description:     str
    agent_selection: tuple[str, ...] = DEFAULT_AGENT_SLATE
    aliases:         tuple[str, ...] = field(default_factory=tuple)


_REGISTRY: dict[str, TargetSpec] = {}


def register_target(
    scheme:          str,
    *,
    factory:         TargetFactory,
    description:     str = "",
    agent_selection: Iterable[str] = DEFAULT_AGENT_SLATE,
    aliases:         Iterable[str] = (),
) -> TargetSpec:
    """Register a target class. Re-registration replaces the prior
    entry — call sites that ship with ARGUS always win over operator
    overrides made at runtime."""
    spec = TargetSpec(
        scheme=scheme,
        factory=factory,
        description=description,
        agent_selection=tuple(agent_selection),
        aliases=tuple(aliases),
    )
    _REGISTRY[scheme] = spec
    for alias in spec.aliases:
        _REGISTRY[alias] = spec
    return spec


def target_for_url(url: str) -> Optional[TargetSpec]:
    """Resolve ``url`` to a TargetSpec by its scheme."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return None
    return _REGISTRY.get(parsed.scheme)


def list_targets() -> list[TargetSpec]:
    """Unique specs (deduped across aliases)."""
    seen: set[int] = set()
    out: list[TargetSpec] = []
    for spec in _REGISTRY.values():
        if id(spec) in seen:
            continue
        seen.add(id(spec))
        out.append(spec)
    return out


# ── Built-in registrations ──────────────────────────────────────────────────
# Each target's module imports this registry and calls register_target
# at import time, so importing argus.engagement populates the table
# with every ship-slate target.

def _ensure_builtin_registrations() -> None:
    # Imports are local so circulars don't bite when callers import
    # the registry first.
    try:
        from argus.engagement import builtin     # noqa: F401
    except ImportError:       # pragma: no cover
        pass


_ensure_builtin_registrations()
