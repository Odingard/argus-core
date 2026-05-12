"""Class registry — every attack class self-registers here.

This is what the CLI walks when emitting corpora or pointing the runner at a
specific layer.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .generator import Generator
from .types import LayerId

if TYPE_CHECKING:
    from ..grading.matcher import ProbeResult

GeneratorFactory = Callable[..., Generator]
"""Factory signature: ``factory(seed_value: int, *, recon: ReconProfile | None = None)``.

Recon-aware classes accept the optional ``recon`` keyword argument and pass
it through to ``Generator(..., recon=...)``. Non-adopting classes are called
without it; the registry tracks which classes opt in via ``recon_aware``.
"""


HarvestFunction = Callable[["ProbeResult"], dict[str, tuple[str, ...]]]
"""Harvest signature used by the chain synthesiser.

A class with non-empty ``produces`` artefacts on its ``ChainNode``
registers a deterministic ``harvest`` callable that pulls those
artefacts out of a confirmed-landed ``ProbeResult``. Returns a dict
keyed on ``ReconProfile`` field names. Empty values are dropped by the
runner before merging into the running ``ChainContext``.
"""


@dataclass(frozen=True, slots=True)
class AttackClass:
    class_id: str
    layer: LayerId
    title: str
    target_variants: int
    factory: GeneratorFactory
    description: str = ""
    target_surface: frozenset[str] = field(default_factory=frozenset)
    recon_aware: bool = False
    """If True, the supervisor will pass ``recon=`` to ``factory``."""
    harvest: HarvestFunction | None = None
    """Optional callable extracting artefacts from a confirmed finding's
    probe result. Required for any class that appears as a chain
    producer (non-empty ``ChainNode.produces``).
    """
    carrier_surfaces: frozenset[str] = field(default_factory=frozenset)
    """Phase P — declared carrier surfaces the class can render through.

    Empty (default) means the class only supports the canonical
    ``user_turn`` delivery — every variant rides the user-role
    payload, matching the pre-Phase-P behaviour bit-for-bit. A
    non-empty set advertises additional surfaces (``tool_result``,
    ``rag_document``, ``roleplay_persona``, ``system_reflection``)
    the supervisor may pick when the target's recon profile exposes
    a matching surface. Classes that have not opted into carrier
    rendering simply keep the default empty set (AGENTS.md rule #7
    — backwards-compatible deterministic dispatch).
    """
    arc_native: bool = False
    """Phase S — class wants to execute through Phase-Q's ArcRunner.

    When ``True`` the supervisor unrolls each variant through the
    canonical 5-stage arc (rapport → persona_seed → boundary_probe →
    boundary_erode → extract) rather than firing the variant as a
    single turn. Single-turn classes leave this ``False`` and keep
    pre-Phase-S behaviour bit-for-bit (AGENTS.md rule #7).
    """
    rapport_refusal_policy: str = "abort"
    """Phase S — per-class rapport refusal handling for ``arc_native``.

    One of ``"abort"`` (default; matches pre-Phase-S semantics —
    rapport refusal ends the arc immediately because identity is
    hard-gated) or ``"retry_alt"`` (arc-native classes whose rapport
    stage is a non-threatening opener — questions, benign topic — so
    a refusal there is usually a one-off false positive on a specific
    phrasing rather than a capability gate). Ignored when
    ``arc_native`` is ``False``.
    """


_REGISTRY: dict[str, AttackClass] = {}


def register(cls: AttackClass) -> AttackClass:
    if cls.class_id in _REGISTRY:
        raise ValueError(f"duplicate registration: {cls.class_id}")
    _REGISTRY[cls.class_id] = cls
    return cls


def get(class_id: str) -> AttackClass:
    return _REGISTRY[class_id]


def all_classes() -> Iterator[AttackClass]:
    yield from sorted(_REGISTRY.values(), key=lambda c: c.class_id)


def classes_in_layer(layer: LayerId) -> Iterator[AttackClass]:
    yield from (c for c in all_classes() if c.layer == layer)


def reset() -> None:
    """Test hook only."""
    _REGISTRY.clear()
