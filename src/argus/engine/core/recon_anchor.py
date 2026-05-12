"""Mutator-side recon helpers.

Recon-adopting attack classes call ``recon_anchor(seed, "tool_names")`` from
inside their mutator's ``mutate`` loop to retrieve the first artefact for a
given field, or ``""`` if no recon profile is attached. Variant body / tool
definition / description text is then optionally decorated with the artefact
so the variant becomes target-specific without altering the surrounding
structural mutator axes.

Backward-compat contract: when ``seed.meta.get("recon")`` is ``None`` or the
profile carries no value for the requested field, ``recon_anchor`` returns
``""`` and the caller's "no decoration" branch produces the same variant the
pre-upgrade head produced. This is what
``test_recon_param_backward_compat`` enforces.

The helper is intentionally small — every adopting class consumes it through
the same surface so the adoption pattern is uniform and reviewable.
"""

from __future__ import annotations

from .seed import Seed


def recon_anchor(seed: Seed, field_name: str) -> str:
    """Return the first recon artefact for ``field_name`` on ``seed``, or ``""``.

    The artefact is read from ``seed.meta["recon"]`` (set by
    ``SeedParameterizer`` before the mutator stack runs). If the seed has no
    recon profile attached, or the profile has no values for the requested
    field, an empty string is returned and the caller treats the variant as
    a baseline (recon-blind) variant.
    """
    recon = seed.meta.get("recon")
    if recon is None:
        return ""
    getter = getattr(recon, "get", None)
    if getter is None:
        return ""
    values = getter(field_name)
    if not values:
        return ""
    return values[0]


def recon_anchors(seed: Seed, field_name: str) -> tuple[str, ...]:
    """Return the full artefact tuple for ``field_name`` on ``seed`` (or ``()``)."""
    recon = seed.meta.get("recon")
    if recon is None:
        return ()
    getter = getattr(recon, "get", None)
    if getter is None:
        return ()
    return getter(field_name)


__all__ = ["recon_anchor", "recon_anchors"]
