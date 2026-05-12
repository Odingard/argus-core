"""Tier-escalation tracker — first-cross detector per class.

Phase R-3 — tier-escalation banners.

The HUD and narrator both need to know the *first* moment a given
attack class crosses each tier boundary (MEDIUM → HIGH →
IRREFUTABLE). That moment is the visual beat that makes a live
engagement readable as a story: "cog-chain-of-thought-hijack just hit
MEDIUM for the first time."

This module keeps that logic in one deterministic place so both
sinks share identical semantics (rule #7 — same event stream → same
banner sequence).

Boundaries
==========

Tiers are ordered, low → high:

    LOW < MEDIUM < HIGH < IRREFUTABLE

The tracker remembers the highest tier already announced for each
class. On every event it consults:

* ``event["confidence"]`` or ``event["verdict"]`` (tier label), and
* ``event["signal_strength"]`` or ``event["lethality"]`` (continuous
  score) — used as a fallback when the event carries no explicit
  tier label but its numeric strength crosses a threshold.

If the new tier strictly exceeds the previously-announced one, the
tracker yields a ``TierMilestone`` and updates internal state. Same
tier reached a second time → no milestone. Lower-tier event after a
high one → also no milestone (we never *demote* a class's banner
state; that would create banner flicker on noisy event streams).

The thresholds mirror the verdict ladder in ``grading/`` and match
the JSONL → HTML / Markdown report renderers, so the live narration
and the static report agree on what a "first MEDIUM" means.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "TIER_RANK",
    "MEDIUM_THRESHOLD",
    "HIGH_THRESHOLD",
    "IRREFUTABLE_THRESHOLD",
    "TierMilestone",
    "TierEscalationTracker",
]


#: Ordered tier ladder. Higher number = stronger evidence.
TIER_RANK: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "IRREFUTABLE": 4,
}

#: Numeric thresholds used when only ``signal_strength`` / ``lethality``
#: is present on an event. The MEDIUM gate mirrors the genetic engine's
#: ``signal_strength`` MEDIUM floor in ``grading/signal_strength.py``;
#: the HIGH gate mirrors the structural-matcher tier; IRREFUTABLE is
#: reserved for canary echoes / OOB callbacks (lethality 1.0 only).
MEDIUM_THRESHOLD: float = 0.45
HIGH_THRESHOLD: float = 0.65
IRREFUTABLE_THRESHOLD: float = 0.99


@dataclass(frozen=True)
class TierMilestone:
    """A class crossed a tier boundary for the first time.

    Attributes
    ----------
    attack_class:
        The class id that crossed the threshold.
    tier:
        One of ``"MEDIUM"`` / ``"HIGH"`` / ``"IRREFUTABLE"``.
    variant_id:
        Variant that triggered the crossing (best-effort — may be
        ``None`` if the event omits it).
    score:
        Numeric signal_strength / lethality at the crossing moment.
    """

    attack_class: str
    tier: str
    variant_id: str | None
    score: float


class TierEscalationTracker:
    """Detect the first time each class crosses MEDIUM / HIGH / IRREFUTABLE.

    Usage::

        tracker = TierEscalationTracker()
        for event in stream:
            milestone = tracker.observe(event)
            if milestone is not None:
                render_banner(milestone)

    The tracker is **stateful but deterministic**: feeding the same
    event sequence into a fresh instance always produces the same
    milestone sequence (rule #7).
    """

    def __init__(
        self,
        *,
        medium: float = MEDIUM_THRESHOLD,
        high: float = HIGH_THRESHOLD,
        irrefutable: float = IRREFUTABLE_THRESHOLD,
    ) -> None:
        if not (0.0 <= medium <= high <= irrefutable <= 1.0):
            raise ValueError("tier thresholds must satisfy 0 <= medium <= high <= irrefutable <= 1")
        self._medium = float(medium)
        self._high = float(high)
        self._irrefutable = float(irrefutable)
        self._highest_seen: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def observe(self, event: dict[str, Any]) -> TierMilestone | None:
        """Inspect an event; return a milestone if it crossed a boundary.

        Returns ``None`` for events that are irrelevant (no class,
        unknown type, refusal) or that did not exceed the previous
        high-water mark for that class.
        """
        if not isinstance(event, dict):
            return None
        kind = event.get("type")
        if kind not in {"fire", "finding"}:
            return None
        cls = event.get("attack_class")
        if not isinstance(cls, str) or not cls:
            return None

        tier = self._infer_tier(event)
        if tier is None:
            return None
        rank = TIER_RANK[tier]
        # Only LOW/MEDIUM/HIGH/IRREFUTABLE banners are announced for
        # MEDIUM and above — LOW is too noisy to make a story beat.
        if rank < TIER_RANK["MEDIUM"]:
            return None

        previous = self._highest_seen.get(cls, 0)
        if rank <= previous:
            return None
        self._highest_seen[cls] = rank

        return TierMilestone(
            attack_class=cls,
            tier=tier,
            variant_id=_coerce_variant(event.get("variant_id")),
            score=_coerce_score(event),
        )

    def highest_tier_for(self, attack_class: str) -> str | None:
        """Return the highest tier observed for ``attack_class``, or None."""
        rank = self._highest_seen.get(attack_class)
        if rank is None:
            return None
        for label, value in TIER_RANK.items():
            if value == rank:
                return label
        return None

    def snapshot(self) -> dict[str, str]:
        """Return a deterministic ``class → tier`` map of highest seen.

        Ordered by class id for stable test assertions and for
        rendering the HUD heatmap deterministically.
        """
        out: dict[str, str] = {}
        for cls in sorted(self._highest_seen):
            label = self.highest_tier_for(cls)
            if label is not None:
                out[cls] = label
        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _infer_tier(self, event: dict[str, Any]) -> str | None:
        """Determine the tier of an event.

        Preference order:

        1. Explicit ``confidence`` / ``verdict`` label, if it's one of
           the known tiers.
        2. Numeric ``signal_strength`` against MEDIUM / HIGH gates.
        3. Numeric ``lethality`` against the IRREFUTABLE gate (and the
           MEDIUM / HIGH gates as a fallback).
        """
        for key in ("confidence", "verdict"):
            raw = event.get(key)
            if isinstance(raw, str) and raw in TIER_RANK:
                return raw

        # Try signal_strength first (Phase N's continuous gradient).
        score = _coerce_score(event)
        if score >= self._irrefutable:
            return "IRREFUTABLE"
        if score >= self._high:
            return "HIGH"
        if score >= self._medium:
            return "MEDIUM"
        return None


def _coerce_score(event: dict[str, Any]) -> float:
    for key in ("signal_strength", "lethality"):
        raw = event.get(key)
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return 0.0


def _coerce_variant(raw: Any) -> str | None:
    if isinstance(raw, str) and raw:
        return raw
    return None
