"""Tests for the Phase M offline HTML report renderer.

The renderer must produce a *single-file, zero-dependency* HTML
document — no ``<script>``, no external ``href`` / ``src``
references, no JavaScript event handlers. These tests pin those
guarantees directly so we can never silently regress them.
"""

from __future__ import annotations

import datetime as _dt
import re
from html.parser import HTMLParser

import pytest

from argus.engine.reporting import render_html
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
            rehydrated=True,
            target_fingerprint_id="fp-test",
        ),
        classes=(
            ClassRollup(
                attack_class="ci-y",
                fired=1,
                landed=1,
                tier_counts={"HIGH": 1},
                top_lethality=0.5,
            ),
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
                evidence={"trigger": "canary", "source": "tool_output"},
            ),
            FindingRow(
                variant_id="ci-y:0",
                attack_class="ci-y",
                confidence="HIGH",
                lethality=0.5,
                phase="probing",
                generation=0,
                evidence={"trigger": "<script>alert(1)</script>"},
            ),
        ),
        refusals=(RefusalRow(signature="i_cannot_provide", occurrences=2),),
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


_FIXED_STAMP = _dt.datetime(2025, 1, 1, 0, 0, 0, tzinfo=_dt.UTC)


def _render(report: EngagementReport) -> str:
    return render_html(report, generated_at=_FIXED_STAMP)


# ---------------------------------------------------------------------------
# Output is a single, self-contained HTML document.
# ---------------------------------------------------------------------------


def test_starts_with_doctype_and_html_tags(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    assert html.startswith("<!DOCTYPE html>"), html[:80]
    assert html.rstrip().endswith("</html>"), html[-80:]


def test_contains_no_script_blocks(sample_report: EngagementReport) -> None:
    """Pin: HTML report must contain ZERO JavaScript."""
    html = _render(sample_report).lower()
    assert "<script" not in html
    assert "javascript:" not in html
    # Inline event handlers (onclick=, onload=, …) — block anything that
    # would execute when the page is opened.
    assert not re.search(r"\bon[a-z]+\s*=", html), "inline event handler detected"


def test_contains_no_external_url_references(sample_report: EngagementReport) -> None:
    """Pin: HTML report must be openable offline (no CDN, no fonts, no images)."""
    html = _render(sample_report)
    # The only places ``http`` is allowed to appear are: in the DOCTYPE
    # (it doesn't — modern doctype is bare) and inside escaped target /
    # variant strings inside the body. So src= and href= must never
    # appear at all.
    assert "src=" not in html, "src= attribute is forbidden in the offline report"
    assert "href=" not in html, "href= attribute is forbidden in the offline report"
    assert "@import" not in html, "@import in CSS would pull external resources"


def test_evidence_special_characters_are_escaped(sample_report: EngagementReport) -> None:
    """Tool-attacker-controlled evidence must never escape the HTML context."""
    html = _render(sample_report)
    # The hostile ci-y:0 evidence had ``<script>alert(1)</script>`` in
    # the trigger field. It must appear escaped, not literal.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_confidence_value_is_escaped_in_findings_table() -> None:
    """``finding.confidence`` is read raw from JSONL (``str(event.get(...))``)
    so a forensic log written by a compromised target can ship hostile bytes
    in that field. Pin that the renderer escapes them on *both* the CSS
    class and text-content interpolations of the tier badge.
    """
    hostile = '"><script>alert("xss")</script>'
    report = EngagementReport(
        metadata=RunMetadata(
            target="t",
            transport="argt",
            layer="L1",
            seed=0,
            duration_seconds=0.0,
            total_fired=1,
            total_findings=1,
            rehydrated=False,
            target_fingerprint_id=None,
        ),
        classes=(),
        findings=(
            FindingRow(
                variant_id="v0",
                attack_class="cls",
                confidence=hostile,
                lethality=0.0,
                phase="probing",
                generation=0,
                evidence={},
            ),
        ),
        refusals=(),
        fallbacks=(),
        emergence_links=(),
    )
    html = render_html(report, generated_at=_dt.datetime(2025, 1, 1, tzinfo=_dt.UTC))
    assert hostile not in html
    assert "<script>alert(" not in html
    # Both interpolations are escaped — the CSS-class slot and the text slot.
    assert "&lt;script&gt;alert(" in html


def test_render_is_html_parseable(sample_report: EngagementReport) -> None:
    """Smoke test: the rendered string is well-formed enough for the
    stdlib HTML parser to read without raising."""

    class _Sink(HTMLParser):
        pass

    _Sink().feed(_render(sample_report))


# ---------------------------------------------------------------------------
# Content surfaces the right facts.
# ---------------------------------------------------------------------------


def test_metadata_fields_appear(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    assert "https://target.example/mcp" in html
    assert "argt" in html
    assert "layer2_contextual_injection" in html
    assert "42" in html
    assert "8.50s" in html
    assert "fp-test" in html


def test_each_tier_card_appears_with_correct_count(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    # IRREFUTABLE 1, HIGH 1, MEDIUM 0, LOW 0.
    assert "tier-IRREFUTABLE" in html
    assert "tier-HIGH" in html
    # The medium / low cards still appear (zero count) for at-a-glance
    # comparison — pin the structure is there.
    assert "MEDIUM" in html
    assert "LOW" in html


def test_class_rollup_row_per_class(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    # Class rollup table contains both attack class names.
    assert "tp-x" in html and "ci-y" in html
    # Rate appears as a percentage.
    assert "50.0%" in html  # tp-x: 1 landed / 2 fired
    assert "100.0%" in html  # ci-y: 1 landed / 1 fired


def test_findings_rows_contain_variant_ids(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    assert "tp-x:1" in html
    assert "ci-y:0" in html


def test_emergence_link_appears(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    assert "chain-1" in html
    assert "leaked_credentials" in html


def test_refusal_row_appears(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    assert "i_cannot_provide" in html


def test_fallback_row_appears(sample_report: EngagementReport) -> None:
    html = _render(sample_report)
    assert "Recon-plausibility fallbacks" in html
    assert "r0" in html
    assert "b0" in html


# ---------------------------------------------------------------------------
# Empty-state behaviour (rule #9).
# ---------------------------------------------------------------------------


def test_empty_report_renders_with_explainable_empty_states() -> None:
    report = EngagementReport(
        metadata=RunMetadata(
            target="model-x",
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
    html = render_html(report, generated_at=_FIXED_STAMP)
    assert "No findings above LOW tier" in html
    assert "No fires recorded" in html
    assert "No refusal signatures captured" in html
    assert "No multi-class producer" in html


# ---------------------------------------------------------------------------
# Determinism (rule #7).
# ---------------------------------------------------------------------------


def test_render_is_deterministic(sample_report: EngagementReport) -> None:
    """Same input + same stamp → byte-identical output."""
    a = _render(sample_report)
    b = _render(sample_report)
    assert a == b
