"""Tests for the deterministic multi-judge consensus matcher."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from argus.engine.core.types import Confidence
from argus.engine.grading.consensus import (
    DEFAULT_THRESHOLDS,
    ConsensusMatcher,
    ConsensusThresholds,
    consensus,
)
from argus.engine.grading.matcher import Match, ProbeResult


def _probe(variant_id: str = "v0") -> ProbeResult:
    return ProbeResult(
        variant_id=variant_id,
        seed_id="seed",
        attack_class="ci-test",
        response_text="echo",
    )


@dataclass(frozen=True, slots=True)
class _FixedMatcher:
    """A matcher that always returns the same verdict, deterministically."""

    matcher_id: str
    confidence: Confidence = "MEDIUM"
    landed: bool | None = True

    def evaluate(self, probe: ProbeResult) -> Match | None:
        if self.landed is None:
            return None
        return Match(
            matcher_id=self.matcher_id,
            confidence=self.confidence,
            landed=self.landed,
            evidence={"probe": probe.variant_id},
        )


def test_unanimous_panel_lands_irrefutable() -> None:
    panel = (
        _FixedMatcher("a"),
        _FixedMatcher("b"),
        _FixedMatcher("c"),
    )
    matcher = ConsensusMatcher(
        matcher_id="consensus-test",
        children=panel,
        confidence="IRREFUTABLE",
    )

    result = matcher.evaluate(_probe())

    assert result is not None
    assert result.landed is True
    assert result.confidence == "IRREFUTABLE"
    assert result.evidence["panel_size"] == 3
    assert result.evidence["landed"] == 3
    assert result.evidence["landed_by"] == ("a", "b", "c")


def test_two_thirds_majority_lands_high() -> None:
    panel = (
        _FixedMatcher("a"),
        _FixedMatcher("b"),
        _FixedMatcher("c", landed=None),  # this child doesn't fire
    )
    matcher = ConsensusMatcher(
        matcher_id="consensus-high",
        children=panel,
        confidence="IRREFUTABLE",  # ceiling: HIGH should be the realised tier
    )

    result = matcher.evaluate(_probe())

    assert result is not None
    assert result.confidence == "HIGH"
    assert result.evidence["landed"] == 2


def test_simple_majority_lands_medium() -> None:
    # 3-of-5 lands -> just above the 50% medium threshold (ceil(5 * 0.5) = 3),
    # and below the 66% high threshold (ceil(5 * 0.66) = 4).
    panel = (
        _FixedMatcher("a"),
        _FixedMatcher("b"),
        _FixedMatcher("c"),
        _FixedMatcher("d", landed=None),
        _FixedMatcher("e", landed=None),
    )
    matcher = ConsensusMatcher(
        matcher_id="consensus-medium",
        children=panel,
        confidence="HIGH",
    )

    result = matcher.evaluate(_probe())

    assert result is not None
    assert result.confidence == "MEDIUM"


def test_minority_does_not_emit() -> None:
    # 1-of-3 lands -> below 50% threshold.
    panel = (
        _FixedMatcher("a"),
        _FixedMatcher("b", landed=None),
        _FixedMatcher("c", landed=None),
    )
    matcher = ConsensusMatcher(
        matcher_id="consensus-none",
        children=panel,
        confidence="HIGH",
    )

    assert matcher.evaluate(_probe()) is None


def test_ceiling_clamps_high_panel_to_medium() -> None:
    panel = (_FixedMatcher("a"), _FixedMatcher("b"), _FixedMatcher("c"))
    matcher = ConsensusMatcher(
        matcher_id="consensus-clamp",
        children=panel,
        confidence="MEDIUM",
    )

    result = matcher.evaluate(_probe())

    assert result is not None
    assert result.confidence == "MEDIUM"


def test_rejecting_child_counts_against_consensus() -> None:
    panel = (
        _FixedMatcher("a"),
        _FixedMatcher("b"),
        _FixedMatcher("c", landed=False),  # explicit rejection
    )
    matcher = ConsensusMatcher(
        matcher_id="consensus-rejected",
        children=panel,
        confidence="IRREFUTABLE",
    )

    result = matcher.evaluate(_probe())

    assert result is not None
    assert result.evidence["rejected"] == 1
    assert result.evidence["landed"] == 2
    # 2/3 still clears HIGH but not IRREFUTABLE.
    assert result.confidence == "HIGH"


def test_evidence_records_every_child_in_panel_order() -> None:
    panel = (
        _FixedMatcher("zeta", confidence="MEDIUM"),
        _FixedMatcher("alpha", confidence="HIGH"),
    )
    matcher = ConsensusMatcher(
        matcher_id="consensus-order",
        children=panel,
        confidence="HIGH",
    )

    result = matcher.evaluate(_probe())

    assert result is not None
    records = result.evidence["children"]
    assert tuple(r["matcher_id"] for r in records) == ("zeta", "alpha")
    assert all(r["fired"] for r in records)


def test_same_probe_yields_same_verdict_across_calls() -> None:
    panel = (
        _FixedMatcher("a"),
        _FixedMatcher("b"),
        _FixedMatcher("c", landed=None),
    )
    matcher = ConsensusMatcher(
        matcher_id="consensus-determinism",
        children=panel,
        confidence="HIGH",
    )

    a = matcher.evaluate(_probe())
    b = matcher.evaluate(_probe())

    assert a == b


def test_thresholds_require_ordered_values() -> None:
    with pytest.raises(ValueError, match="ordered"):
        ConsensusThresholds(irrefutable=0.5, high=0.7, medium=0.5)


def test_thresholds_reject_invalid_range() -> None:
    with pytest.raises(ValueError, match="must be in"):
        ConsensusThresholds(irrefutable=1.5, high=0.66, medium=0.5)


def test_empty_panel_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        ConsensusMatcher(matcher_id="consensus-empty", children=())


def test_duplicate_child_ids_rejected_by_default() -> None:
    panel = (_FixedMatcher("dup"), _FixedMatcher("dup"))
    with pytest.raises(ValueError, match="distinct"):
        ConsensusMatcher(matcher_id="consensus-dup", children=panel)


def test_duplicate_child_ids_allowed_when_opted_out() -> None:
    panel = (_FixedMatcher("dup"), _FixedMatcher("dup"))
    matcher = ConsensusMatcher(
        matcher_id="consensus-dup-ok",
        children=panel,
        require_distinct_ids=False,
    )
    assert matcher.panel_size == 2


def test_thresholds_required_for_panel_size_one() -> None:
    # Single-child panel: any landed child is unanimous.
    assert DEFAULT_THRESHOLDS.required_for("IRREFUTABLE", 1) == 1
    assert DEFAULT_THRESHOLDS.required_for("HIGH", 1) == 1
    assert DEFAULT_THRESHOLDS.required_for("MEDIUM", 1) == 1
    assert DEFAULT_THRESHOLDS.required_for("LOW", 1) == 0


def test_thresholds_required_for_zero_panel() -> None:
    assert DEFAULT_THRESHOLDS.required_for("IRREFUTABLE", 0) == 0
    assert DEFAULT_THRESHOLDS.required_for("HIGH", 0) == 0


def test_consensus_helper_preserves_child_order() -> None:
    children = [_FixedMatcher(f"m{i}") for i in range(4)]
    matcher = consensus("helper", children, confidence="HIGH")
    assert [c.matcher_id for c in matcher.children] == ["m0", "m1", "m2", "m3"]
    assert matcher.confidence == "HIGH"
