"""
argus/observation/verdict.py — verdict shapes for the Observation Engine.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict


class BehaviorDelta(str, enum.Enum):
    """Coarse outcome of comparing baseline vs. post-attack."""
    UNCHANGED = "BEHAVIOR_UNCHANGED"
    DELTA     = "BEHAVIOR_DELTA"
    AMBIGUOUS = "BEHAVIOR_AMBIGUOUS"   # detector saw something but can't decide


class DeltaKind(str, enum.Enum):
    """Canonical kinds of behaviour delta. Keep this set small + meaningful —
    each kind is something a triager can point at and say 'yes, that is
    observable behaviour change'."""
    UNAUTHORISED_TOOL_CALL = "UNAUTHORISED_TOOL_CALL"
    TOOL_ARG_DRIFT         = "TOOL_ARG_DRIFT"
    CONTENT_LEAK           = "CONTENT_LEAK"
    STATE_MUTATION         = "STATE_MUTATION"
    IDENTITY_BYPASS        = "IDENTITY_BYPASS"
    RESPONSE_SHAPE_DELTA   = "RESPONSE_SHAPE_DELTA"
    PERSISTENCE            = "PERSISTENCE"


@dataclass
class Verdict:
    """A single detector's judgment on a baseline/post pair."""
    delta:      BehaviorDelta
    kind:       DeltaKind | None = None
    detector:   str = ""
    evidence:   str = ""
    confidence: float = 0.0        # 0..1, deterministic confidence
    turn_index: int | None = None
    meta:       dict = field(default_factory=dict)

    def is_finding(self) -> bool:
        """True if this verdict counts as an observable finding."""
        return self.delta == BehaviorDelta.DELTA and self.kind is not None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["delta"] = self.delta.value
        d["kind"]  = self.kind.value if self.kind else None
        return d


def unchanged(detector: str, evidence: str = "") -> Verdict:
    """Convenience constructor for 'nothing here'."""
    return Verdict(
        delta=BehaviorDelta.UNCHANGED,
        detector=detector,
        evidence=evidence,
        confidence=1.0,
    )
