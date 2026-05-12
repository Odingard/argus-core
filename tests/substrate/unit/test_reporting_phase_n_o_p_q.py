"""Phase N/O/P/Q reporting extensions — HTML + Markdown + JSONL.

Pins:

* HTML renderer surfaces every new section (signal-strength /
  diversity / carrier / arc), keeping the zero-JS / zero-external-
  resource constraints from Phase M intact.
* Markdown renderer surfaces every new section, conditionally —
  pre-Phase-N runs (no signal data) must not render empty Markdown
  blocks.
* JSONL reader round-trips ``signal_strength_summary`` /
  ``diversity_stats`` / ``carrier_histogram`` / ``arc_summary``
  events, **and** synthesises a signal summary from raw per-fire
  ``signal_strength`` blocks when no explicit summary event fired
  (rule #9 — every empty result must be explainable).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from html.parser import HTMLParser

from argus.engine.reporting import render_html, render_markdown
from argus.engine.reporting.jsonl_reader import parse_jsonl_text
from argus.engine.reporting.model import EngagementReport, RunMetadata


def _empty_metadata() -> RunMetadata:
    return RunMetadata(
        target="https://t.example",
        transport="argt",
        layer="layer3_cognitive",
        seed=42,
        duration_seconds=1.0,
        total_fired=0,
        total_findings=0,
    )


def _report_with(**overrides) -> EngagementReport:
    base: dict[str, object] = {
        "metadata": _empty_metadata(),
        "classes": (),
        "findings": (),
        "refusals": (),
        "fallbacks": (),
        "emergence_links": (),
    }
    base.update(overrides)
    return EngagementReport(**base)  # type: ignore[arg-type]


# --- HTML — section presence --------------------------------------


def test_html_includes_signal_strength_section() -> None:
    report = _report_with(
        signal_strength_summary={
            "count": 100,
            "mean": 0.42,
            "max": 0.85,
            "p50": 0.4,
            "p90": 0.7,
            "p99": 0.82,
        }
    )
    html = render_html(report, generated_at=_dt.datetime(2026, 1, 1))
    assert "Signal-strength gradient" in html
    assert "0.420" in html or "0.42" in html
    assert "100" in html


def test_html_renders_signal_strength_empty_explanation_rule9() -> None:
    """Rule #9 — empty signal summary must be explainable, not omitted."""
    report = _report_with()
    html = render_html(report, generated_at=_dt.datetime(2026, 1, 1))
    assert "Signal-strength gradient" in html
    assert "No signal-strength samples" in html


def test_html_includes_diversity_section() -> None:
    report = _report_with(diversity_stats={"observed": 200, "accepted": 50, "rejected": 150})
    html = render_html(report, generated_at=_dt.datetime(2026, 1, 1))
    assert "Diversity" in html or "diversity" in html
    assert "200" in html
    assert "150" in html


def test_html_includes_carrier_section() -> None:
    report = _report_with(carrier_histogram={"user_turn": 80, "rag_document": 20})
    html = render_html(report, generated_at=_dt.datetime(2026, 1, 1))
    assert "user_turn" in html
    assert "rag_document" in html
    assert "80" in html
    assert "20" in html


def test_html_includes_arc_section() -> None:
    report = _report_with(
        arc_summary={
            "arcs": 5,
            "completed": 3,
            "aborted": 2,
            "total_rewinds": 4,
            "stage_reach_counts": {"rapport": 5, "extract": 3},
        }
    )
    html = render_html(report, generated_at=_dt.datetime(2026, 1, 1))
    assert "Arc" in html or "arc" in html
    assert "rapport" in html or "5" in html


# --- HTML — zero JS / zero external resource (Phase M parity) -----


def _assert_no_js_or_external_resource(html: str) -> None:
    """Mirror the Phase M constraints — Phase N/O/P/Q sections must
    not introduce ``<script>`` tags or external resource refs."""
    lowered = html.lower()
    assert "<script" not in lowered
    assert "</script" not in lowered
    assert "javascript:" not in lowered
    assert " src=" not in lowered
    assert " href=" not in lowered
    assert "@import" not in lowered
    # No inline event handlers.
    assert not re.search(r"\son[a-z]+\s*=", lowered)


def test_html_with_all_phase_n_o_p_q_sections_still_zero_js() -> None:
    report = _report_with(
        signal_strength_summary={
            "count": 10,
            "mean": 0.4,
            "max": 0.7,
            "p50": 0.4,
            "p90": 0.6,
            "p99": 0.7,
        },
        diversity_stats={"observed": 100, "accepted": 30, "rejected": 70},
        carrier_histogram={"user_turn": 80, "tool_result": 20},
        arc_summary={
            "arcs": 3,
            "completed": 2,
            "aborted": 1,
            "total_rewinds": 2,
            "stage_reach_counts": {"rapport": 3, "extract": 2},
        },
    )
    html = render_html(report, generated_at=_dt.datetime(2026, 1, 1))
    _assert_no_js_or_external_resource(html)


def test_html_with_phase_n_o_p_q_parses_cleanly() -> None:
    """No malformed HTML even with all four new sections."""
    report = _report_with(
        signal_strength_summary={
            "count": 5,
            "mean": 0.5,
            "max": 0.5,
            "p50": 0.5,
            "p90": 0.5,
            "p99": 0.5,
        },
        diversity_stats={"observed": 10, "accepted": 5, "rejected": 5},
        carrier_histogram={"user_turn": 5},
        arc_summary={
            "arcs": 1,
            "completed": 1,
            "aborted": 0,
            "total_rewinds": 0,
            "stage_reach_counts": {},
        },
    )
    html = render_html(report, generated_at=_dt.datetime(2026, 1, 1))

    class _Parser(HTMLParser):
        errors: list[str] = []

        def error(self, message: str) -> None:  # pragma: no cover
            self.errors.append(message)

    p = _Parser()
    p.feed(html)
    assert p.errors == []


# --- Markdown — conditional rendering (no empty sections) ---------


def test_markdown_skips_signal_section_when_summary_empty() -> None:
    report = _report_with()
    md = render_markdown(report)
    assert "Signal-strength gradient" not in md


def test_markdown_emits_signal_section_when_summary_present() -> None:
    report = _report_with(
        signal_strength_summary={
            "count": 100,
            "mean": 0.42,
            "max": 0.85,
            "p50": 0.4,
            "p90": 0.7,
            "p99": 0.82,
        }
    )
    md = render_markdown(report)
    assert "Signal-strength gradient" in md
    assert "| mean |" in md
    assert "0.420" in md


def test_markdown_emits_diversity_when_stats_present() -> None:
    report = _report_with(diversity_stats={"observed": 200, "accepted": 50, "rejected": 150})
    md = render_markdown(report)
    assert "Diversity" in md or "diversity" in md
    assert "200" in md
    assert "150" in md


def test_markdown_emits_carrier_when_histogram_present() -> None:
    report = _report_with(carrier_histogram={"user_turn": 80, "rag_document": 20})
    md = render_markdown(report)
    assert "user_turn" in md
    assert "rag_document" in md


def test_markdown_emits_arc_when_summary_present() -> None:
    report = _report_with(
        arc_summary={
            "arcs": 5,
            "completed": 3,
            "aborted": 2,
            "total_rewinds": 4,
            "stage_reach_counts": {"rapport": 5, "extract": 3},
        }
    )
    md = render_markdown(report)
    assert "arc" in md.lower()


# --- JSONL reader — Phase N/O/P/Q event round-trip ----------------


def _run_meta() -> dict:
    return {
        "type": "run_metadata",
        "target": "https://t.example",
        "transport": "argt",
        "layer": "layer3_cognitive",
        "seed": 42,
        "duration_seconds": 0.0,
        "total_fired": 0,
        "total_findings": 0,
    }


def test_jsonl_reader_round_trips_phase_n_summary_event() -> None:
    events = [
        _run_meta(),
        {
            "type": "signal_strength_summary",
            "count": 3,
            "mean": 0.5,
            "max": 0.7,
            "p50": 0.5,
            "p90": 0.6,
            "p99": 0.7,
        },
    ]
    blob = "\n".join(json.dumps(e) for e in events)
    report = parse_jsonl_text(blob)
    assert report.signal_strength_summary["count"] == 3.0
    assert report.signal_strength_summary["max"] == 0.7


def test_jsonl_reader_synthesises_signal_summary_from_raw_samples() -> None:
    """Rule #9 — when no summary event arrives but raw per-fire
    samples landed, the reader reconstructs the summary so the
    report still answers 'how close did the engine get?'.
    """
    events = [_run_meta()]
    for strength in (0.1, 0.3, 0.5, 0.7, 0.9):
        events.append(
            {
                "type": "fire",
                "attack_class": "x",
                "variant_id": "v",
                "signal_strength": {"strength": strength},
            }
        )
    blob = "\n".join(json.dumps(e) for e in events)
    report = parse_jsonl_text(blob)
    summary = report.signal_strength_summary
    assert summary
    assert summary["count"] == 5.0
    assert summary["max"] == 0.9
    assert summary["mean"] == 0.5


def test_jsonl_reader_round_trips_diversity_event() -> None:
    events = [
        _run_meta(),
        {
            "type": "diversity_stats",
            "observed": 200,
            "accepted": 50,
            "rejected": 150,
        },
    ]
    blob = "\n".join(json.dumps(e) for e in events)
    report = parse_jsonl_text(blob)
    assert report.diversity_stats == {
        "observed": 200,
        "accepted": 50,
        "rejected": 150,
    }


def test_jsonl_reader_round_trips_carrier_event() -> None:
    events = [
        _run_meta(),
        {
            "type": "carrier_histogram",
            "counts": {"user_turn": 80, "rag_document": 20},
        },
    ]
    blob = "\n".join(json.dumps(e) for e in events)
    report = parse_jsonl_text(blob)
    assert report.carrier_histogram == {"user_turn": 80, "rag_document": 20}


def test_jsonl_reader_round_trips_arc_summary_event() -> None:
    events = [
        _run_meta(),
        {
            "type": "arc_summary",
            "arcs": 5,
            "completed": 3,
            "aborted": 2,
            "total_rewinds": 4,
            "stage_reach_counts": {"rapport": 5, "extract": 3},
        },
    ]
    blob = "\n".join(json.dumps(e) for e in events)
    report = parse_jsonl_text(blob)
    assert report.arc_summary["arcs"] == 5
    assert report.arc_summary["completed"] == 3
    assert report.arc_summary["stage_reach_counts"] == {
        "rapport": 5,
        "extract": 3,
    }
