"""Seed exploit definitions.

A ``Seed`` is a verified, hand-tuned attack template — the cornerstone of one
attack class. Mutators compose around a seed to produce variants.

Seeds are versioned so future hardening or refinements don't silently change
the variant set produced by an old seed_id.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .types import LayerId


@dataclass(frozen=True, slots=True)
class Seed:
    """A single verified-landing attack template.

    Attributes:
        seed_id: Canonical id (``layer.class.seed_index``).
        attack_class: Class identifier (e.g. ``tp-schema-shadowing``).
        layer: Layer this seed belongs to.
        version: Bump on any structural change.
        template: Free-form template string with ``{placeholder}`` slots.
        placeholders: Mapping of placeholder name → list of substitution values.
        target_surface: Tags describing required target capabilities (e.g. ``{"tool", "mcp"}``).
        canary_label: Stable label used to derive the variant's canary.
        notes: Plain-language description of mechanism + landing evidence.
        meta: Arbitrary extra metadata (model affinity, prerequisite probes, etc.).
    """

    seed_id: str
    attack_class: str
    layer: LayerId
    version: int
    template: str
    placeholders: dict[str, tuple[str, ...]] = field(default_factory=dict)
    target_surface: frozenset[str] = field(default_factory=frozenset)
    canary_label: str = "primary"
    notes: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def with_meta(self, **kwargs: Any) -> Seed:
        new_meta = dict(self.meta)
        new_meta.update(kwargs)
        return Seed(
            seed_id=self.seed_id,
            attack_class=self.attack_class,
            layer=self.layer,
            version=self.version,
            template=self.template,
            placeholders=self.placeholders,
            target_surface=self.target_surface,
            canary_label=self.canary_label,
            notes=self.notes,
            meta=new_meta,
        )
