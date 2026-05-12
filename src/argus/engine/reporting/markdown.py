"""CI-friendly Markdown summary renderer.

Designed for the most common downstream surfaces: GitHub / GitLab PR
comments, Slack snippets, ``pre-commit`` summaries, and ``argus-engine
engage`` stdout when ``--md`` is passed. No HTML, no tables wider than
~120 columns, no characters that break in monospaced terminals.

Headlines IRREFUTABLE + HIGH per AGENTS.md. MEDIUM appears under a
dedicated subheader. LOW is omitted (statistical anomaly only).
"""

from __future__ import annotations

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


def render_markdown(report: EngagementReport) -> str:
    """Project ``report`` into a Markdown string."""
    parts: list[str] = []
    parts.append("# ARGUS-ENGINE Engagement Report")
    parts.append("")
    parts.append(_render_metadata(report.metadata))
    parts.append("")
    parts.append(_render_summary_tiers(report))
    parts.append("")
    if report.signal_strength_summary:
        parts.append(_render_signal_strength(report.signal_strength_summary))
        parts.append("")
    if report.diversity_stats:
        parts.append(_render_diversity(report.diversity_stats))
        parts.append("")
    if report.carrier_histogram:
        parts.append(_render_carrier(report.carrier_histogram))
        parts.append("")
    if report.arc_summary:
        parts.append(_render_arc(report.arc_summary))
        parts.append("")
    parts.append(_render_headline_findings(report.headline_findings))
    parts.append("")
    parts.append(_render_classes(report.classes))
    parts.append("")
    medium = tuple(f for f in report.findings if f.confidence == "MEDIUM")
    if medium:
        parts.append(_render_medium(medium))
        parts.append("")
    if report.fallbacks:
        parts.append(_render_fallbacks(report.fallbacks))
        parts.append("")
    if report.emergence_links:
        parts.append(_render_emergence(report.emergence_links))
        parts.append("")
    if report.refusals:
        parts.append(_render_refusals(report.refusals))
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


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
    body = ["| Field | Value |", "| --- | --- |"]
    body.extend(f"| {k} | `{_md(v)}` |" for k, v in rows)
    return "## Engagement\n\n" + "\n".join(body)


def _render_summary_tiers(report: EngagementReport) -> str:
    counts = report.overall_tier_counts
    body = ["| Tier | Count |", "| --- | --- |"]
    body.extend(f"| {tier} | {counts.get(tier, 0)} |" for tier in TIER_ORDER)
    return "## Confidence summary\n\n" + "\n".join(body)


def _render_headline_findings(findings: tuple[FindingRow, ...]) -> str:
    if not findings:
        return (
            "## Headline findings (IRREFUTABLE / HIGH)\n\n"
            "_None — no canary echo, OOB callback, or structural leak match observed._"
        )
    body = [
        "| Tier | Class | Variant | Phase | Lethality |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        body.append(
            f"| {f.confidence} | `{_md(f.attack_class)}` | `{_md(f.variant_id)}` | {f.phase} | {f.lethality:.2f} |"
        )
    return "## Headline findings (IRREFUTABLE / HIGH)\n\n" + "\n".join(body)


def _render_classes(classes: tuple[ClassRollup, ...]) -> str:
    if not classes:
        return "## Per-class rollup\n\n_No fires recorded._"
    body = [
        "| Class | Fired | Landed | Rate | Top lethality |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for cls in classes:
        body.append(
            f"| `{_md(cls.attack_class)}` | {cls.fired} | {cls.landed} | "
            f"{cls.landed_rate * 100:.1f}% | {cls.top_lethality:.2f} |"
        )
    return "## Per-class rollup\n\n" + "\n".join(body)


def _render_medium(findings: tuple[FindingRow, ...]) -> str:
    body = [
        "| Class | Variant | Phase | Lethality |",
        "| --- | --- | --- | ---: |",
    ]
    for f in findings:
        body.append(f"| `{_md(f.attack_class)}` | `{_md(f.variant_id)}` | {f.phase} | {f.lethality:.2f} |")
    return "## MEDIUM findings (internal signal)\n\n" + "\n".join(body)


def _render_fallbacks(fallbacks: tuple[FallbackEvent, ...]) -> str:
    body = [
        "| Class | Recon variant | Baseline variant | Recon | Baseline | Margin |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for fb in fallbacks:
        body.append(
            f"| `{_md(fb.attack_class)}` | `{_md(fb.recon_variant_id)}` | "
            f"`{_md(fb.baseline_variant_id)}` | {fb.recon_score:.3f} | "
            f"{fb.baseline_score:.3f} | {fb.margin:.3f} |"
        )
    return "## Recon-plausibility fallbacks (X8 gate)\n\n" + "\n".join(body)


def _render_emergence(links: tuple[ChainEmergenceLink, ...]) -> str:
    body = [
        "| Chain | Producer | Consumer | Slot | Landed |",
        "| --- | --- | --- | --- | --- |",
    ]
    for link in links:
        body.append(
            f"| `{_md(link.chain_id)}` | `{_md(link.producer_class)}` | "
            f"`{_md(link.consumer_class)}` | `{_md(link.slot)}` | "
            f"{'yes' if link.landed else 'no'} |"
        )
    return "## Chain emergence\n\n" + "\n".join(body)


def _render_refusals(refusals: tuple[RefusalRow, ...]) -> str:
    body = ["| Signature | Occurrences |", "| --- | ---: |"]
    for r in refusals:
        body.append(f"| `{_md(r.signature)}` | {r.occurrences} |")
    return "## Refusal-KB hits\n\n" + "\n".join(body)


def _render_signal_strength(summary: dict[str, float]) -> str:
    """Phase N — table the continuous-gradient scoreboard."""
    keys = ("count", "mean", "max", "p50", "p90", "p99")
    body = ["| Stat | Value |", "| --- | ---: |"]
    for key in keys:
        if key not in summary:
            continue
        value = summary[key]
        formatted = f"{int(value)}" if key == "count" else f"{value:.3f}"
        body.append(f"| {key} | {formatted} |")
    return "## Signal-strength gradient (Phase N)\n\n" + "\n".join(body)


def _render_diversity(stats: dict[str, int]) -> str:
    """Phase O — diversity-gate counters."""
    observed = int(stats.get("observed", 0))
    accepted = int(stats.get("accepted", 0))
    rejected = int(stats.get("rejected", 0))
    rate = (rejected / observed) if observed else 0.0
    body = [
        "| Stat | Value |",
        "| --- | ---: |",
        f"| observed | {observed} |",
        f"| accepted | {accepted} |",
        f"| rejected | {rejected} |",
        f"| reject_rate | {rate * 100:.1f}% |",
    ]
    return "## Population diversity (Phase O)\n\n" + "\n".join(body)


def _render_carrier(histogram: dict[str, int]) -> str:
    """Phase P — fires per carrier surface."""
    total = sum(histogram.values()) or 1
    body = [
        "| Carrier | Fires | Share |",
        "| --- | ---: | ---: |",
    ]
    for surface, count in sorted(histogram.items()):
        share = f"{(count / total) * 100:.1f}%"
        body.append(f"| `{_md(surface)}` | {count} | {share} |")
    return "## Carrier surfaces (Phase P)\n\n" + "\n".join(body)


def _render_arc(summary: dict[str, object]) -> str:
    """Phase Q — ARGT multi-call arc-progression aggregate."""
    arcs = int(summary.get("arcs", 0) or 0)
    completed = int(summary.get("completed", 0) or 0)
    aborted = int(summary.get("aborted", 0) or 0)
    total_rewinds = int(summary.get("total_rewinds", 0) or 0)
    head = [
        "| Stat | Value |",
        "| --- | ---: |",
        f"| arcs | {arcs} |",
        f"| completed | {completed} |",
        f"| aborted | {aborted} |",
        f"| rewinds | {total_rewinds} |",
    ]
    stage_reach_raw = summary.get("stage_reach_counts") or {}
    if isinstance(stage_reach_raw, dict) and stage_reach_raw:
        stage_rows = ["", "| Stage | Arcs reaching |", "| --- | ---: |"]
        for stage, count in stage_reach_raw.items():
            stage_rows.append(f"| `{_md(stage)}` | {int(count)} |")
        head.extend(stage_rows)
    return "## Conversation arcs (Phase Q)\n\n" + "\n".join(head)


def _md(value: object) -> str:
    """Escape characters that break in monospaced markdown cells.

    We deliberately keep this small — backticks and pipes are the only
    code-span / table-cell terminators that actually corrupt rendering.
    Everything else (asterisks, underscores, etc.) is safe inside the
    code-span wrappers we already emit at call sites.
    """
    text = str(value)
    return text.replace("`", "\\`").replace("|", "\\|")
