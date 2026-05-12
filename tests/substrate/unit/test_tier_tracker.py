"""Phase R-3 — TierEscalationTracker unit tests."""

from __future__ import annotations

import pytest

from argus.engine.reporting.tier_tracker import (
    HIGH_THRESHOLD,
    IRREFUTABLE_THRESHOLD,
    MEDIUM_THRESHOLD,
    TIER_RANK,
    TierEscalationTracker,
    TierMilestone,
)

# ---------------------------------------------------------------------------
# construction / threshold validation
# ---------------------------------------------------------------------------


def test_default_thresholds_are_monotonic() -> None:
    assert 0.0 <= MEDIUM_THRESHOLD <= HIGH_THRESHOLD <= IRREFUTABLE_THRESHOLD <= 1.0


def test_default_tier_rank_orders_low_to_irrefutable() -> None:
    assert TIER_RANK["LOW"] < TIER_RANK["MEDIUM"]
    assert TIER_RANK["MEDIUM"] < TIER_RANK["HIGH"]
    assert TIER_RANK["HIGH"] < TIER_RANK["IRREFUTABLE"]


def test_invalid_thresholds_rejected() -> None:
    with pytest.raises(ValueError):
        TierEscalationTracker(medium=0.9, high=0.5, irrefutable=0.99)
    with pytest.raises(ValueError):
        TierEscalationTracker(medium=-0.1)
    with pytest.raises(ValueError):
        TierEscalationTracker(irrefutable=1.1)


# ---------------------------------------------------------------------------
# observe()
# ---------------------------------------------------------------------------


def test_first_medium_crossing_emits_milestone() -> None:
    tracker = TierEscalationTracker()
    milestone = tracker.observe(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v0001",
            "signal_strength": 0.5,
        }
    )
    assert isinstance(milestone, TierMilestone)
    assert milestone.tier == "MEDIUM"
    assert milestone.attack_class == "foo"
    assert milestone.variant_id == "v0001"
    assert milestone.score == pytest.approx(0.5)


def test_second_medium_does_not_re_emit() -> None:
    tracker = TierEscalationTracker()
    first = tracker.observe(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v1",
            "signal_strength": 0.5,
        }
    )
    second = tracker.observe(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v2",
            "signal_strength": 0.55,
        }
    )
    assert first is not None
    assert second is None


def test_climbing_through_tiers_emits_one_milestone_per_tier() -> None:
    tracker = TierEscalationTracker()
    events = [
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v1",
            "signal_strength": 0.5,
        },
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v2",
            "signal_strength": 0.7,
        },
        {
            "type": "finding",
            "attack_class": "foo",
            "variant_id": "v3",
            "confidence": "IRREFUTABLE",
            "lethality": 1.0,
        },
    ]
    milestones = [tracker.observe(e) for e in events]
    tiers = [m.tier for m in milestones if m is not None]
    assert tiers == ["MEDIUM", "HIGH", "IRREFUTABLE"]


def test_low_tier_events_do_not_emit_milestones() -> None:
    tracker = TierEscalationTracker()
    out = tracker.observe(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v",
            "signal_strength": 0.1,
        }
    )
    assert out is None


def test_explicit_confidence_label_wins_over_score() -> None:
    tracker = TierEscalationTracker()
    out = tracker.observe(
        {
            "type": "finding",
            "attack_class": "foo",
            "variant_id": "v",
            "confidence": "HIGH",
            "signal_strength": 0.05,
        }
    )
    assert out is not None
    assert out.tier == "HIGH"


def test_classes_tracked_independently() -> None:
    tracker = TierEscalationTracker()
    a = tracker.observe(
        {
            "type": "fire",
            "attack_class": "a",
            "variant_id": "v",
            "signal_strength": 0.7,
        }
    )
    b = tracker.observe(
        {
            "type": "fire",
            "attack_class": "b",
            "variant_id": "v",
            "signal_strength": 0.5,
        }
    )
    assert a is not None and a.tier == "HIGH"
    assert b is not None and b.tier == "MEDIUM"


def test_descending_score_does_not_demote_or_re_emit() -> None:
    tracker = TierEscalationTracker()
    tracker.observe(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v1",
            "signal_strength": 0.7,
        }
    )
    out = tracker.observe(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v2",
            "signal_strength": 0.5,
        }
    )
    assert out is None
    assert tracker.highest_tier_for("foo") == "HIGH"


def test_non_fire_non_finding_events_ignored() -> None:
    tracker = TierEscalationTracker()
    for kind in ("phase", "thought", "refusal", "mutation", "arc_outcome"):
        assert tracker.observe({"type": kind, "attack_class": "foo"}) is None


def test_missing_class_event_ignored() -> None:
    tracker = TierEscalationTracker()
    assert tracker.observe({"type": "fire", "signal_strength": 0.9, "variant_id": "v"}) is None


def test_non_dict_event_safe() -> None:
    tracker = TierEscalationTracker()
    assert tracker.observe("oops") is None  # type: ignore[arg-type]
    assert tracker.observe(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# snapshot / highest_tier_for
# ---------------------------------------------------------------------------


def test_snapshot_is_sorted_by_class_id_for_determinism() -> None:
    tracker = TierEscalationTracker()
    for cls, score in [("zeta", 0.5), ("alpha", 0.7), ("middle", 0.99)]:
        tracker.observe(
            {
                "type": "fire",
                "attack_class": cls,
                "variant_id": "v",
                "signal_strength": score,
            }
        )
    snap = tracker.snapshot()
    assert list(snap.keys()) == ["alpha", "middle", "zeta"]
    assert snap["alpha"] == "HIGH"
    assert snap["middle"] == "IRREFUTABLE"
    assert snap["zeta"] == "MEDIUM"


def test_highest_tier_for_unknown_class_is_none() -> None:
    assert TierEscalationTracker().highest_tier_for("nope") is None


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_same_event_stream_yields_same_milestones() -> None:
    events = [
        {
            "type": "fire",
            "attack_class": "a",
            "variant_id": "v1",
            "signal_strength": 0.5,
        },
        {
            "type": "fire",
            "attack_class": "a",
            "variant_id": "v2",
            "signal_strength": 0.7,
        },
        {
            "type": "fire",
            "attack_class": "b",
            "variant_id": "v3",
            "signal_strength": 0.99,
        },
    ]

    def run() -> list[tuple[str, str]]:
        t = TierEscalationTracker()
        out: list[tuple[str, str]] = []
        for e in events:
            m = t.observe(e)
            if m is not None:
                out.append((m.attack_class, m.tier))
        return out

    assert run() == run() == run()
