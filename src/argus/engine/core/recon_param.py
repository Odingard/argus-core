"""Seed parameterizer — substitutes recon artefacts into seeds.

Runs ONCE per seed BEFORE the mutator stack walks it. The resulting seed
has:

* ``{recon:<artefact>}`` tokens in ``template`` resolved to the first
  artefact in the corresponding profile field;
* ``placeholders["recon:<artefact>"]`` populated with the artefact tuple
  if the key was already declared (placeholders are not added implicitly,
  to keep the seed contract explicit);
* ``meta["recon"]`` set to the ``ReconProfile`` so opt-in mutators can
  read it directly.

Backward-compat contract: when ``recon`` is ``None`` *or* empty, the
parameterizer is a strict no-op — ``parameterize(seed) is seed`` — so
variant_ids remain bit-identical to the pre-upgrade head. This is what
``test_recon_param_backward_compat`` enforces.
"""

from __future__ import annotations

import re

from .recon_profile import ReconProfile
from .seed import Seed

_TOKEN_RE = re.compile(r"\{recon:([a-z_][a-z0-9_]*)\}")


class SeedParameterizer:
    """Resolves ``{recon:*}`` slots in a Seed against a ``ReconProfile``."""

    __slots__ = ("_recon",)

    def __init__(self, recon: ReconProfile | None) -> None:
        if recon is not None and not isinstance(recon, ReconProfile):
            raise TypeError(f"recon must be a ReconProfile or None, got {type(recon).__name__}")
        self._recon = recon

    @property
    def recon(self) -> ReconProfile | None:
        return self._recon

    def parameterize(self, seed: Seed) -> Seed:
        """Return a new Seed with recon slots resolved.

        If ``recon`` is None or empty, the original seed object is returned
        unchanged so downstream consumers (and variant_ids) are bit-identical
        to the baseline.
        """
        if self._recon is None or self._recon.is_empty():
            return seed

        new_template = _TOKEN_RE.sub(
            lambda m: self._first(m.group(1)) or m.group(0),
            seed.template,
        )

        new_placeholders = dict(seed.placeholders)
        for key in list(new_placeholders.keys()):
            if not key.startswith("recon:"):
                continue
            artefact = key.split(":", 1)[1]
            values = self._recon.get(artefact)
            if values:
                new_placeholders[key] = values

        new_meta = dict(seed.meta)
        new_meta["recon"] = self._recon

        return Seed(
            seed_id=seed.seed_id,
            attack_class=seed.attack_class,
            layer=seed.layer,
            version=seed.version,
            template=new_template,
            placeholders=new_placeholders,
            target_surface=seed.target_surface,
            canary_label=seed.canary_label,
            notes=seed.notes,
            meta=new_meta,
        )

    def parameterize_all(self, seeds: tuple[Seed, ...]) -> tuple[Seed, ...]:
        if self._recon is None or self._recon.is_empty():
            return seeds
        return tuple(self.parameterize(s) for s in seeds)

    def _first(self, artefact: str) -> str:
        if self._recon is None:
            return ""
        values = self._recon.get(artefact)
        return values[0] if values else ""


__all__ = ["SeedParameterizer"]
