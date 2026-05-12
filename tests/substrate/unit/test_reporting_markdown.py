"""Tests for the Phase M Markdown summary renderer."""

from __future__ import annotations

import pytest

from argus.engine.reporting import render_markdown
from argus.engine.reporting.model import (
    ChainEmergenceLink,
    ClassRollup,
    EngagementReport,
    FallbackEvent,
    FindingRow,
    RefusalRow,
    RunMetadata,
)


@pytest.fixture
def sample_report() -> EngagementReport:
    return EngagementReport(
        metadata=RunMetadata(
            target="https://target.example/mcp",
            transport="argt",
            layer="layer2_contextual_injection",
            seed=42,
            duration_seconds=8.5,
            total_fired=3,
            total_findings=2,
            rehydrated=False,
        ),
        classes=(
            ClassRollup(
                attack_class="tp-x",
                fired=2,
                landed=1,
                tier_counts={"IRREFUTABLE": 1},
                top_lethality=0.9,
            ),
        ),
        findings=(
            FindingRow(
                variant_id="tp-x:1",
                attack_class="tp-x",
                confidence="IRREFUTABLE",
                lethality=0.9,
                phase="exploitation",
                generation=2,
                evidence={"trigger": "canary"},
            ),
            FindingRow(
                variant_id="tp-x:2",
                attack_class="tp-x",
                confidence="MEDIUM",
                lethality=0.4,
                phase="probing",
                generation=0,
                evidence={},
            ),
        ),
        refusals=(RefusalRow(signature="i_cannot_provide", occurrences=3),),
        fallbacks=(
            FallbackEvent(
                attack_class="tp-x",
                recon_variant_id="r0",
                baseline_variant_id="b0",
                recon_score=0.2,
                baseline_score=0.7,
                margin=0.5,
            ),
        ),
        emergence_links=(
            ChainEmergenceLink(
                chain_id="chain-1",
                producer_class="tp-x",
                consumer_class="ext-z",
                slot="leaked_credentials",
                landed=True,
            ),
        ),
    )


def test_starts_with_title(sample_report: EngagementReport) -> None:
    md = render_markdown(sample_report)
    assert md.startswith("# ARGUS-ENGINE Engagement Report")


def test_metadata_section_table(sample_report: EngagementReport) -> None:
    md = render_markdown(sample_report)
    assert "## Engagement" in md
    assert "| Target | `https://target.example/mcp` |" in md
    assert "| Transport | `argt` |" in md
    assert "| Seed | `42` |" in md


def test_summary_table_lists_all_tiers(sample_report: EngagementReport) -> None:
    md = render_markdown(sample_report)
    assert "## Confidence summary" in md
    for tier in ("IRREFUTABLE", "HIGH", "MEDIUM", "LOW"):
        assert f"| {tier} |" in md


def test_headline_section_shows_only_headline_findings(
    sample_report: EngagementReport,
) -> None:
    md = render_markdown(sample_report)
    assert "## Headline findings (IRREFUTABLE / HIGH)" in md
    assert "tp-x:1" in md  # IRREFUTABLE finding
    # MEDIUM findings must NOT appear under the headline section.
    headline_block = md.split("## Headline findings")[1].split("## ")[0]
    assert "tp-x:2" not in headline_block


def test_medium_findings_section_present_when_medium_exists(
    sample_report: EngagementReport,
) -> None:
    md = render_markdown(sample_report)
    assert "## MEDIUM findings (internal signal)" in md
    medium_block = md.split("## MEDIUM findings")[1]
    assert "tp-x:2" in medium_block


def test_class_rollup_uses_right_aligned_numeric_cells() -> None:
    report = EngagementReport(
        metadata=RunMetadata(
            target="t",
            transport="openai",
            layer="layer1_tool_poisoning",
            seed=0,
            duration_seconds=0.0,
            total_fired=0,
            total_findings=0,
        ),
        classes=(
            ClassRollup(
                attack_class="tp-x",
                fired=2,
                landed=1,
                tier_counts={"HIGH": 1},
                top_lethality=0.5,
            ),
        ),
        findings=(),
        refusals=(),
        fallbacks=(),
        emergence_links=(),
    )
    md = render_markdown(report)
    assert "## Per-class rollup" in md
    # Headers use right-alignment markers for numeric columns.
    assert "| ---: |" in md


def test_emergence_section_omitted_when_no_links() -> None:
    report = EngagementReport(
        metadata=RunMetadata(
            target="t",
            transport="openai",
            layer="layer1_tool_poisoning",
            seed=0,
            duration_seconds=0.0,
            total_fired=0,
            total_findings=0,
        ),
        classes=(),
        findings=(),
        refusals=(),
        fallbacks=(),
        emergence_links=(),
    )
    md = render_markdown(report)
    assert "## Chain emergence" not in md


def test_emergence_section_present_when_links_exist(
    sample_report: EngagementReport,
) -> None:
    md = render_markdown(sample_report)
    assert "## Chain emergence" in md
    assert "chain-1" in md
    assert "leaked_credentials" in md


def test_fallback_section_present_when_fallbacks_exist(
    sample_report: EngagementReport,
) -> None:
    md = render_markdown(sample_report)
    assert "## Recon-plausibility fallbacks" in md
    assert "r0" in md
    assert "b0" in md


def test_empty_headline_renders_explainable_placeholder() -> None:
    """Rule #9 — empty headline section must still explain itself."""
    report = EngagementReport(
        metadata=RunMetadata(
            target="t",
            transport="openai",
            layer="layer1_tool_poisoning",
            seed=0,
            duration_seconds=0.0,
            total_fired=0,
            total_findings=0,
        ),
        classes=(),
        findings=(),
        refusals=(),
        fallbacks=(),
        emergence_links=(),
    )
    md = render_markdown(report)
    assert "_None — no canary echo" in md


def test_render_is_deterministic(sample_report: EngagementReport) -> None:
    assert render_markdown(sample_report) == render_markdown(sample_report)


def test_backtick_in_variant_id_is_escaped() -> None:
    """Variant ids containing backticks must not break code-span rendering."""
    hostile = FindingRow(
        variant_id="evil`id",
        attack_class="ci-y",
        confidence="HIGH",
        lethality=0.5,
        phase="probing",
        generation=0,
        evidence={},
    )
    report = EngagementReport(
        metadata=RunMetadata(
            target="t",
            transport="openai",
            layer="layer2_contextual_injection",
            seed=0,
            duration_seconds=0.0,
            total_fired=0,
            total_findings=0,
        ),
        classes=(),
        findings=(hostile,),
        refusals=(),
        fallbacks=(),
        emergence_links=(),
    )
    md = render_markdown(report)
    assert "evil\\`id" in md
