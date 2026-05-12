"""Offline single-file HTML report renderer.

Constraints (enforced by tests):

* zero external resources — no ``<script src=…>``, no
  ``<link rel="stylesheet" href=…>``, no ``<img src=http…>``;
* zero JavaScript — no ``<script>`` blocks at all;
* CSS is inline inside a single ``<style>`` block;
* every dynamic value is HTML-escaped via :func:`html.escape`.

Output is one self-contained ``<!DOCTYPE html>`` document that can be
emailed, committed, opened from disk, or served as a static asset.
"""

from __future__ import annotations

import datetime as _dt
import html as _html
import json
from typing import Any

from .model import (
    TIER_ORDER,
    ChainEmergenceLink,
    ClassRollup,
    EngagementReport,
    FallbackEvent,
    FindingRow,
    RefusalRow,
    RunMetadata,
)

_CSS = """
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: #0c0c0f;
  color: #e6e6e6;
  margin: 0;
  padding: 2rem 3rem;
  line-height: 1.45;
}
h1 { font-size: 1.65rem; margin: 0 0 0.25rem 0; }
h2 { font-size: 1.15rem; margin: 2rem 0 0.5rem 0; border-bottom: 1px solid #333; padding-bottom: 0.3rem; }
h3 { font-size: 1rem; margin: 1.25rem 0 0.5rem 0; color: #c8c8d2; }
.subtitle { color: #9a9aa6; margin: 0 0 1.5rem 0; font-size: 0.9rem; }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 0.4rem 1.5rem;
  background: #15151b;
  border: 1px solid #2a2a36;
  padding: 1rem 1.25rem;
  border-radius: 6px;
}
.meta-grid .k { color: #8a8a98; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
.meta-grid .v { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9rem; word-break: break-all; }
table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1rem 0; font-size: 0.88rem; }
th, td { padding: 0.45rem 0.6rem; text-align: left; border-bottom: 1px solid #24242e; vertical-align: top; }
th { background: #1c1c24; color: #c8c8d2; font-weight: 600; }
tr:hover td { background: #15151b; }
.tier { display: inline-block; padding: 0.1rem 0.55rem; border-radius: 3px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em; }
.tier-IRREFUTABLE { background: #f72585; color: #0c0c0f; }
.tier-HIGH        { background: #ff9e00; color: #0c0c0f; }
.tier-MEDIUM      { background: #ffd166; color: #0c0c0f; }
.tier-LOW         { background: #4a4a55; color: #e6e6e6; }
.tier-NONE        { background: #2c2c36; color: #8a8a98; }
.summary-tiers { display: flex; gap: 0.6rem; flex-wrap: wrap; margin: 0.5rem 0 1rem 0; }
.summary-tiers .tier-card {
  background: #15151b; border: 1px solid #2a2a36; padding: 0.6rem 0.9rem; border-radius: 6px; min-width: 110px;
}
.summary-tiers .tier-card .n { font-size: 1.6rem; font-weight: 700; line-height: 1; }
.summary-tiers .tier-card .l { font-size: 0.72rem; color: #8a8a98; letter-spacing: 0.05em; text-transform: uppercase; margin-top: 0.2rem; }
details { margin-top: 0.4rem; }
details summary { cursor: pointer; color: #c8c8d2; }
pre.evidence {
  background: #0a0a0f; border: 1px solid #2a2a36; border-radius: 4px;
  padding: 0.6rem 0.8rem; overflow-x: auto; font-size: 0.78rem; white-space: pre-wrap; word-break: break-word;
}
.empty { color: #6f6f7c; font-style: italic; }
.footer { margin-top: 2.5rem; color: #6f6f7c; font-size: 0.78rem; }
""".strip()


def render_html(report: EngagementReport, *, generated_at: _dt.datetime | None = None) -> str:
    """Project ``report`` into a single self-contained HTML document.

    ``generated_at`` is exposed for deterministic tests (AGENTS.md
    rule #7); production callers can leave it ``None`` to stamp the
    current UTC time.
    """
    if generated_at is None:
        generated_at = _dt.datetime.now(tz=_dt.UTC)
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head>')
    parts.append('<meta charset="utf-8">')
    parts.append("<title>ARGUS-ENGINE Engagement Report</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head><body>")
    parts.append("<h1>ARGUS-ENGINE Engagement Report</h1>")
    parts.append(
        f'<p class="subtitle">Generated {_esc(generated_at.isoformat(timespec="seconds"))}'
        " — deterministic projection of forensic JSONL.</p>"
    )

    parts.append(_render_metadata(report.metadata))
    parts.append(_render_summary_tiers(report))
    parts.append(_render_signal_strength(report.signal_strength_summary))
    parts.append(_render_diversity(report.diversity_stats))
    parts.append(_render_carrier(report.carrier_histogram))
    parts.append(_render_arc(report.arc_summary))
    parts.append(_render_classes(report.classes))
    parts.append(_render_findings(report.findings))
    parts.append(_render_fallbacks(report.fallbacks))
    parts.append(_render_emergence(report.emergence_links))
    parts.append(_render_refusals(report.refusals))

    parts.append(
        '<p class="footer">'
        "Confidence tiers follow AGENTS.md: IRREFUTABLE (canary echo / OOB) "
        "and HIGH (structural regex on known leak shape) are headline. "
        "MEDIUM is internal signal until human-verified. LOW (statistical "
        "anomaly only) is omitted from this report."
        "</p>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _render_metadata(meta: RunMetadata) -> str:
    rows = [
        ("Target", meta.target),
        ("Transport", meta.transport),
        ("Layer", meta.layer),
        ("Seed", str(meta.seed)),
        ("Duration", f"{meta.duration_seconds:.2f}s"),
        ("Total fired", str(meta.total_fired)),
        ("Total findings", str(meta.total_findings)),
        ("Rehydrated", "yes" if meta.rehydrated else "no"),
    ]
    if meta.target_fingerprint_id:
        rows.append(("Fingerprint", meta.target_fingerprint_id))
    cells = "".join(f'<div><div class="k">{_esc(k)}</div><div class="v">{_esc(v)}</div></div>' for k, v in rows)
    return f'<h2>Engagement</h2><div class="meta-grid">{cells}</div>'


def _render_summary_tiers(report: EngagementReport) -> str:
    counts = report.overall_tier_counts
    cards = []
    for tier in TIER_ORDER:
        n = counts.get(tier, 0)
        css_class = f"tier-card tier tier-{tier}" if n else "tier-card tier tier-NONE"
        cards.append(f'<div class="{css_class}"><div class="n">{n}</div><div class="l">{_esc(tier)}</div></div>')
    body = "".join(cards) or '<p class="empty">No findings.</p>'
    return f'<h2>Confidence summary</h2><div class="summary-tiers">{body}</div>'


def _render_classes(classes: tuple[ClassRollup, ...]) -> str:
    if not classes:
        return '<h2>Per-class rollup</h2><p class="empty">No fires recorded.</p>'
    rows = []
    for cls in classes:
        tier_cells = " ".join(
            f'<span class="tier tier-{t}">{t}:{cls.tier_counts.get(t, 0)}</span>'
            for t in TIER_ORDER
            if cls.tier_counts.get(t, 0)
        )
        if not tier_cells:
            tier_cells = '<span class="tier tier-NONE">no landings</span>'
        rate = f"{cls.landed_rate * 100:.1f}%"
        rows.append(
            "<tr>"
            f"<td>{_esc(cls.attack_class)}</td>"
            f"<td>{cls.fired}</td>"
            f"<td>{cls.landed}</td>"
            f"<td>{rate}</td>"
            f"<td>{cls.top_lethality:.2f}</td>"
            f"<td>{tier_cells}</td>"
            "</tr>"
        )
    return (
        "<h2>Per-class rollup</h2>"
        "<table><thead><tr>"
        "<th>Attack class</th><th>Fired</th><th>Landed</th><th>Rate</th>"
        "<th>Top lethality</th><th>Tier breakdown</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_findings(findings: tuple[FindingRow, ...]) -> str:
    if not findings:
        return '<h2>Findings</h2><p class="empty">No findings above LOW tier.</p>'
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f'<td><span class="tier tier-{_esc(finding.confidence)}">{_esc(finding.confidence)}</span></td>'
            f"<td>{_esc(finding.attack_class)}</td>"
            f"<td>{_esc(finding.variant_id)}</td>"
            f"<td>{_esc(finding.phase)}</td>"
            f"<td>{finding.lethality:.2f}</td>"
            f"<td>{finding.generation}</td>"
            f"<td>{_render_evidence(finding.evidence)}</td>"
            "</tr>"
        )
    return (
        "<h2>Findings</h2>"
        "<table><thead><tr>"
        "<th>Tier</th><th>Class</th><th>Variant</th><th>Phase</th>"
        "<th>Lethality</th><th>Gen</th><th>Evidence</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_evidence(evidence: dict[str, Any]) -> str:
    if not evidence:
        return '<span class="empty">—</span>'
    body = json.dumps(evidence, indent=2, sort_keys=True, default=str)
    return f'<details><summary>show</summary><pre class="evidence">{_esc(body)}</pre></details>'


def _render_fallbacks(fallbacks: tuple[FallbackEvent, ...]) -> str:
    if not fallbacks:
        return (
            "<h2>Recon-plausibility fallbacks (X8 gate)</h2>"
            '<p class="empty">None — every recon-aware fire used the recon arm.</p>'
        )
    rows = []
    for fb in fallbacks:
        rows.append(
            "<tr>"
            f"<td>{_esc(fb.attack_class)}</td>"
            f"<td>{_esc(fb.recon_variant_id)}</td>"
            f"<td>{_esc(fb.baseline_variant_id)}</td>"
            f"<td>{fb.recon_score:.3f}</td>"
            f"<td>{fb.baseline_score:.3f}</td>"
            f"<td>{fb.margin:.3f}</td>"
            "</tr>"
        )
    return (
        "<h2>Recon-plausibility fallbacks (X8 gate)</h2>"
        "<table><thead><tr>"
        "<th>Class</th><th>Recon variant</th><th>Baseline variant</th>"
        "<th>Recon score</th><th>Baseline score</th><th>Margin</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_emergence(links: tuple[ChainEmergenceLink, ...]) -> str:
    if not links:
        return '<h2>Chain emergence</h2><p class="empty">No multi-class producer→consumer hops observed.</p>'
    rows = []
    for link in links:
        landed = "yes" if link.landed else "no"
        rows.append(
            "<tr>"
            f"<td>{_esc(link.chain_id)}</td>"
            f"<td>{_esc(link.producer_class)}</td>"
            f"<td>{_esc(link.consumer_class)}</td>"
            f"<td>{_esc(link.slot)}</td>"
            f"<td>{landed}</td>"
            "</tr>"
        )
    return (
        "<h2>Chain emergence</h2>"
        "<table><thead><tr>"
        "<th>Chain</th><th>Producer</th><th>Consumer</th>"
        "<th>Slot</th><th>Landed</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_refusals(refusals: tuple[RefusalRow, ...]) -> str:
    if not refusals:
        return '<h2>Refusal-KB hits</h2><p class="empty">No refusal signatures captured this run.</p>'
    rows = "".join(f"<tr><td>{_esc(r.signature)}</td><td>{r.occurrences}</td></tr>" for r in refusals)
    return (
        "<h2>Refusal-KB hits</h2>"
        "<table><thead><tr><th>Signature</th><th>Occurrences</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _render_signal_strength(summary: dict[str, float]) -> str:
    """Phase N — surface the continuous-gradient signal scoreboard.

    When ``summary`` is empty (pre-Phase-N run or signal scoring
    disabled) the section explicitly says so rather than being
    omitted — AGENTS.md rule #9, every empty result must be
    explainable.
    """
    if not summary:
        return (
            "<h2>Signal-strength gradient (Phase N)</h2>"
            '<p class="empty">No signal-strength samples recorded for this run.</p>'
        )
    keys = ("count", "mean", "max", "p50", "p90", "p99")
    cards = []
    for key in keys:
        if key not in summary:
            continue
        value = summary[key]
        formatted = f"{int(value)}" if key == "count" else f"{value:.3f}"
        cards.append(
            f'<div class="tier-card"><div class="n">{_esc(formatted)}</div><div class="l">{_esc(key)}</div></div>'
        )
    body = "".join(cards) or '<p class="empty">No signal-strength samples recorded.</p>'
    return (
        "<h2>Signal-strength gradient (Phase N)</h2>"
        '<p class="subtitle">Continuous [0,1] gradient (boundary_softening · '
        "topic_acknowledgment · partial_leak · model_confusion) emitted for "
        "every fire — answers 'how close did the engine get' even when no "
        "canary landed.</p>"
        f'<div class="summary-tiers">{body}</div>'
    )


def _render_diversity(stats: dict[str, int]) -> str:
    """Phase O — diversity-gate rejection telemetry."""
    if not stats:
        return '<h2>Population diversity (Phase O)</h2><p class="empty">No diversity-gate activity for this run.</p>'
    observed = int(stats.get("observed", 0))
    accepted = int(stats.get("accepted", 0))
    rejected = int(stats.get("rejected", 0))
    rate = (rejected / observed) if observed else 0.0
    cards = [
        ("observed", observed),
        ("accepted", accepted),
        ("rejected", rejected),
        ("reject_rate", f"{rate * 100:.1f}%"),
    ]
    body = "".join(
        f'<div class="tier-card"><div class="n">{_esc(v)}</div><div class="l">{_esc(k)}</div></div>' for k, v in cards
    )
    return (
        "<h2>Population diversity (Phase O)</h2>"
        '<p class="subtitle">MinHash/shingle Jaccard gate — rejected children '
        "are clones of the active pool. High reject rate means the population "
        "was collapsing and the gate kept it spread.</p>"
        f'<div class="summary-tiers">{body}</div>'
    )


def _render_carrier(histogram: dict[str, int]) -> str:
    """Phase P — fires per carrier surface."""
    if not histogram:
        return '<h2>Carrier surfaces (Phase P)</h2><p class="empty">No carrier-surface activity recorded.</p>'
    total = sum(histogram.values()) or 1
    rows = []
    for surface, count in sorted(histogram.items()):
        share = f"{(count / total) * 100:.1f}%"
        rows.append(f"<tr><td>{_esc(surface)}</td><td>{count}</td><td>{share}</td></tr>")
    return (
        "<h2>Carrier surfaces (Phase P)</h2>"
        '<p class="subtitle">Trust surface each fire was rendered through — '
        "user_turn is the canonical surface; non-user_turn carriers route the "
        "payload via tool result, RAG doc, roleplay persona, or system "
        "reflection.</p>"
        "<table><thead><tr>"
        "<th>Carrier</th><th>Fires</th><th>Share</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_arc(summary: dict[str, object]) -> str:
    """Phase Q — ARGT multi-call arc-progression aggregate."""
    if not summary:
        return '<h2>Conversation arcs (Phase Q)</h2><p class="empty">No ARGT arcs executed this run.</p>'
    arcs = int(summary.get("arcs", 0) or 0)
    completed = int(summary.get("completed", 0) or 0)
    aborted = int(summary.get("aborted", 0) or 0)
    total_rewinds = int(summary.get("total_rewinds", 0) or 0)
    stage_reach_raw = summary.get("stage_reach_counts") or {}
    cards = [
        ("arcs", arcs),
        ("completed", completed),
        ("aborted", aborted),
        ("rewinds", total_rewinds),
    ]
    head_cards = "".join(
        f'<div class="tier-card"><div class="n">{_esc(v)}</div><div class="l">{_esc(k)}</div></div>' for k, v in cards
    )
    if isinstance(stage_reach_raw, dict) and stage_reach_raw:
        stage_rows = "".join(
            f"<tr><td>{_esc(stage)}</td><td>{int(count)}</td></tr>" for stage, count in stage_reach_raw.items()
        )
        stage_table = (
            "<h3>Stage reach</h3>"
            "<table><thead><tr><th>Stage</th><th>Arcs reaching</th></tr></thead>"
            f"<tbody>{stage_rows}</tbody></table>"
        )
    else:
        stage_table = ""
    return (
        "<h2>Conversation arcs (Phase Q)</h2>"
        '<p class="subtitle">Planned 5-stage arcs '
        "(rapport → persona → probe → erode → extract); refusals rewind to "
        "the previous stage rather than restarting.</p>"
        f'<div class="summary-tiers">{head_cards}</div>' + stage_table
    )


def _esc(value: object) -> str:
    return _html.escape(str(value), quote=True)
