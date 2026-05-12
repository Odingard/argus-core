"""Tests for the Phase M JSONL → ``EngagementReport`` projection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.engine.reporting import parse_jsonl, parse_jsonl_text
from argus.engine.reporting.model import (
    TIER_ORDER,
    EngagementReport,
)


def _event(**kwargs: object) -> str:
    return json.dumps(kwargs)


@pytest.fixture
def synthetic_jsonl() -> str:
    """Synthetic forensic stream covering every Phase M-relevant event."""
    lines = [
        _event(
            type="engagement_started",
            target="https://t/mcp",
            transport="argt",
            layer="layer2_contextual_injection",
            seed=99,
        ),
        _event(type="phase", phase="rehydrate", outcome="hit", fingerprint_id="fp-abc"),
        _event(
            type="fire",
            variant_id="tp-x:0",
            attack_class="tp-x",
            lethality=0.1,
            verdict="LOW",
            landed=False,
            phase="probing",
        ),
        _event(
            type="fire",
            variant_id="tp-x:1",
            attack_class="tp-x",
            lethality=0.9,
            verdict="IRREFUTABLE",
            landed=True,
            phase="exploitation",
        ),
        _event(
            type="finding",
            variant_id="tp-x:1",
            attack_class="tp-x",
            lethality=0.9,
            confidence="IRREFUTABLE",
            phase="exploitation",
            generation=2,
            evidence={"trigger": "canary"},
        ),
        _event(
            type="fire",
            variant_id="ci-y:0",
            attack_class="ci-y",
            lethality=0.5,
            verdict="HIGH",
            landed=True,
            phase="probing",
        ),
        _event(
            type="finding",
            variant_id="ci-y:0",
            attack_class="ci-y",
            lethality=0.5,
            confidence="HIGH",
            phase="probing",
            generation=0,
            evidence={"trigger": "leak"},
        ),
        _event(
            type="finding",
            variant_id="ci-y:1",
            attack_class="ci-y",
            lethality=0.3,
            confidence="MEDIUM",
            phase="probing",
            generation=0,
            evidence={},
        ),
        _event(
            type="finding",
            variant_id="ci-y:2",
            attack_class="ci-y",
            lethality=0.05,
            confidence="LOW",
            phase="probing",
            generation=0,
            evidence={},
        ),
        _event(type="refusal", signature="i_cannot_provide"),
        _event(type="refusal", signature="i_cannot_provide"),
        _event(type="refusal", signature="not_able"),
        _event(
            type="recon_plausibility_fallback",
            attack_class="tp-x",
            recon_variant_id="r0",
            baseline_variant_id="b0",
            recon_score=0.2,
            baseline_score=0.7,
            margin=0.5,
        ),
        _event(
            type="emergence_report",
            chain_id="chain-1",
            links=[
                {
                    "producer_class": "tp-x",
                    "consumer_class": "ext-z",
                    "slot": "leaked_credentials",
                    "landed": True,
                }
            ],
        ),
        _event(type="done", duration_seconds=12.34, fired=3, findings=4),
    ]
    return "\n".join(lines)


def test_parse_jsonl_text_returns_engagement_report(synthetic_jsonl: str) -> None:
    report = parse_jsonl_text(synthetic_jsonl)
    assert isinstance(report, EngagementReport)
    assert report.metadata.target == "https://t/mcp"
    assert report.metadata.transport == "argt"
    assert report.metadata.layer == "layer2_contextual_injection"
    assert report.metadata.seed == 99
    assert report.metadata.duration_seconds == pytest.approx(12.34)
    assert report.metadata.rehydrated is True
    assert report.metadata.target_fingerprint_id == "fp-abc"


def test_findings_sorted_by_tier_then_class(synthetic_jsonl: str) -> None:
    report = parse_jsonl_text(synthetic_jsonl)
    # LOW is intentionally dropped from the kept set.
    confidences = [f.confidence for f in report.findings]
    assert "LOW" not in confidences
    # IRREFUTABLE must lead, then HIGH, then MEDIUM.
    ranks = [TIER_ORDER.index(c) for c in confidences]
    assert ranks == sorted(ranks)
    # Inside the same tier, attack_class ascending.
    by_tier: dict[str, list[str]] = {}
    for f in report.findings:
        by_tier.setdefault(f.confidence, []).append(f.attack_class)
    for tier, classes in by_tier.items():
        assert classes == sorted(classes), tier


def test_class_rollup_aggregates_fires_landings_and_tiers(synthetic_jsonl: str) -> None:
    report = parse_jsonl_text(synthetic_jsonl)
    rollup = {c.attack_class: c for c in report.classes}
    assert set(rollup) == {"tp-x", "ci-y"}
    tp_x = rollup["tp-x"]
    assert tp_x.fired == 2
    assert tp_x.landed == 1  # only one finding
    assert tp_x.tier_counts == {"IRREFUTABLE": 1}
    assert tp_x.top_lethality == pytest.approx(0.9)
    assert tp_x.headline_count == 1
    assert tp_x.landed_rate == pytest.approx(0.5)

    ci_y = rollup["ci-y"]
    assert ci_y.fired == 1
    # ``landed`` counts fire events that produced ≥ 1 finding, NOT the total
    # number of findings (which is what ``tier_counts`` exposes). The single
    # ci-y fire produced 3 findings across 3 tiers — but it's still one
    # landed fire, so ``landed_rate`` must stay bounded by 1.0.
    assert ci_y.landed == 1
    assert ci_y.tier_counts == {"HIGH": 1, "LOW": 1, "MEDIUM": 1}
    assert ci_y.headline_count == 1  # only HIGH is headline
    assert ci_y.landed_rate == pytest.approx(1.0)
    # Invariant: rule #10's "landing rate" must never exceed 100%, no matter
    # how many findings a single fire produces.
    for cls in report.classes:
        assert 0.0 <= cls.landed_rate <= 1.0


def test_refusal_rows_sorted_by_descending_count_then_signature(synthetic_jsonl: str) -> None:
    report = parse_jsonl_text(synthetic_jsonl)
    sigs = [(r.signature, r.occurrences) for r in report.refusals]
    assert sigs == [("i_cannot_provide", 2), ("not_able", 1)]


def test_fallback_event_round_trips(synthetic_jsonl: str) -> None:
    report = parse_jsonl_text(synthetic_jsonl)
    assert len(report.fallbacks) == 1
    fb = report.fallbacks[0]
    assert fb.attack_class == "tp-x"
    assert fb.recon_variant_id == "r0"
    assert fb.baseline_variant_id == "b0"
    assert fb.recon_score == pytest.approx(0.2)
    assert fb.baseline_score == pytest.approx(0.7)
    assert fb.margin == pytest.approx(0.5)


def test_emergence_links_round_trip_under_chain_id(synthetic_jsonl: str) -> None:
    report = parse_jsonl_text(synthetic_jsonl)
    assert len(report.emergence_links) == 1
    link = report.emergence_links[0]
    assert link.chain_id == "chain-1"
    assert link.producer_class == "tp-x"
    assert link.consumer_class == "ext-z"
    assert link.slot == "leaked_credentials"
    assert link.landed is True


def test_overall_tier_counts_match_findings(synthetic_jsonl: str) -> None:
    report = parse_jsonl_text(synthetic_jsonl)
    # Kept findings: IRREFUTABLE x1, HIGH x1, MEDIUM x1. LOW dropped.
    assert report.overall_tier_counts == {"IRREFUTABLE": 1, "HIGH": 1, "MEDIUM": 1}
    assert {f.confidence for f in report.headline_findings} == {"IRREFUTABLE", "HIGH"}


def test_parse_is_deterministic(synthetic_jsonl: str) -> None:
    """Rule #7 — same JSONL bytes in must produce the same report out."""
    a = parse_jsonl_text(synthetic_jsonl)
    b = parse_jsonl_text(synthetic_jsonl)
    assert a == b


def test_malformed_lines_are_tolerated_not_raised() -> None:
    """Rule #9 — a corrupt tail line must not lose the rest of the run."""
    body = "\n".join(
        [
            _event(
                type="fire",
                variant_id="x:0",
                attack_class="x",
                lethality=0.1,
                verdict="LOW",
                landed=False,
                phase="probing",
            ),
            "{not-json-at-all",
            _event(
                type="finding",
                variant_id="x:0",
                attack_class="x",
                lethality=0.1,
                confidence="HIGH",
                phase="probing",
                generation=0,
                evidence={},
            ),
        ]
    )
    report = parse_jsonl_text(body)
    # The HIGH finding from after the malformed line is still present.
    assert any(f.confidence == "HIGH" for f in report.findings)
    assert any(c.fired == 1 for c in report.classes)


def test_empty_input_returns_empty_report() -> None:
    """Rule #9 — explainable empty state, never an exception."""
    report = parse_jsonl_text("")
    assert report.classes == ()
    assert report.findings == ()
    assert report.refusals == ()
    assert report.fallbacks == ()
    assert report.emergence_links == ()
    assert report.metadata.total_fired == 0
    assert report.metadata.rehydrated is False


def test_parse_jsonl_disk_round_trip(tmp_path: Path, synthetic_jsonl: str) -> None:
    p = tmp_path / "run.jsonl"
    p.write_text(synthetic_jsonl, encoding="utf-8")
    file_report = parse_jsonl(p)
    text_report = parse_jsonl_text(synthetic_jsonl)
    assert file_report == text_report
