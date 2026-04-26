"""
argus/report/render.py - engagement-dir → report.html renderer.

Pure-Python, zero deps. Reads the artifact package an engagement
wrote and emits a single self-contained HTML file with inline CSS.
The HTML is safe to email, attach to a ticket, or open offline -
no external CDN, no JS runtime.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Severity / harm colour mapping ─────────────────────────────────────────

_SEVERITY_COLORS = {
    "CATASTROPHIC": "#7f1d1d",
    "CRITICAL":     "#b91c1c",
    "HIGH":         "#c2410c",
    "MEDIUM":       "#b45309",
    "LOW":          "#15803d",
    "UNKNOWN":      "#334155",
}


_CSS = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               Helvetica, Arial, sans-serif;
  background: #0b0f1a; color: #e2e8f0; margin: 0; padding: 0;
  line-height: 1.55;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 40px 28px 80px; }
header {
  display: flex; justify-content: space-between; align-items: baseline;
  border-bottom: 1px solid #1e293b; padding-bottom: 24px; margin-bottom: 32px;
}
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 17px; margin: 32px 0 12px; color: #93c5fd;
     text-transform: uppercase; letter-spacing: 0.06em; }
.sub { color: #94a3b8; font-size: 13px; }
.badge {
  display: inline-block; padding: 4px 10px; border-radius: 4px;
  font-size: 12px; font-weight: 600; letter-spacing: 0.02em;
  color: white;
}
.grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px 32px; }
.kv { display: flex; justify-content: space-between;
      border-bottom: 1px dashed #1e293b; padding: 6px 0;
      font-size: 14px; }
.kv b { color: #cbd5e1; font-weight: 500; }
.kv span { color: #e2e8f0; font-family:
  "SF Mono", Menlo, Consolas, monospace; font-size: 13px; }
.step-table { width: 100%; border-collapse: collapse; font-size: 13px;
  margin-top: 12px; }
.step-table td, .step-table th {
  padding: 8px 10px; border-bottom: 1px solid #1e293b;
  text-align: left; vertical-align: top;
}
.step-table th { color: #94a3b8; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.06em; font-size: 11px; }
.owasp { display: inline-block; padding: 2px 6px;
  background: #1e3a8a; color: #bfdbfe; border-radius: 3px;
  font-family: "SF Mono", Menlo, monospace; font-size: 11px; }
.tag { display: inline-block; padding: 2px 6px; border-radius: 3px;
  font-size: 11px; margin-right: 4px; margin-bottom: 4px;
  font-family: "SF Mono", Menlo, monospace; }
.tag.reg { background: #7f1d1d33; color: #fca5a5;
           border: 1px solid #7f1d1d88; }
.tag.data { background: #92400e33; color: #fcd34d;
            border: 1px solid #92400e88; }
.tag.surface { background: #1e40af33; color: #93c5fd;
               border: 1px solid #1e40af88; }
.harm {
  font-size: 56px; font-weight: 700; letter-spacing: -0.02em;
  line-height: 1.0; margin-bottom: 6px;
}
.agents { display: flex; gap: 8px; flex-wrap: wrap; }
.agent-card {
  background: #111827; border: 1px solid #1e293b;
  padding: 10px 14px; border-radius: 6px; font-size: 13px;
  min-width: 120px;
}
.agent-card b { display: block; font-family:
  "SF Mono", Menlo, monospace; color: #93c5fd; margin-bottom: 2px; }
.agent-card.silent { opacity: 0.45; }
pre.scenario {
  white-space: pre-wrap; background: #0f172a; padding: 16px;
  border-left: 3px solid #c2410c; border-radius: 4px;
  font-size: 13px; font-family: "SF Mono", Menlo, monospace;
  color: #fed7aa;
}
footer { margin-top: 48px; padding-top: 20px;
  border-top: 1px solid #1e293b; font-size: 12px; color: #64748b; }
a { color: #93c5fd; }
"""


# ── Loader ─────────────────────────────────────────────────────────────────

@dataclass
class RenderedReport:
    html:          str
    output_path:   Path
    target_id:     str
    harm_score:    int
    severity:      str

    def write(self) -> Path:
        self.output_path.write_text(self.html, encoding="utf-8")
        return self.output_path


def _read_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, FileNotFoundError):
        return default


# ── Renderer ───────────────────────────────────────────────────────────────

def render_html(
    *,
    chain:       dict,
    impact:      dict,
    envelope:    Optional[dict],
    summary_txt: str,
    by_agent:    Optional[dict] = None,
    target_url:  str = "",
    findings:    Optional[list] = None,
) -> str:
    """Compose the report HTML from already-parsed artifact dicts."""
    severity     = (impact or {}).get("severity_label", "UNKNOWN")
    harm         = (impact or {}).get("harm_score", 0)
    sev_color    = _SEVERITY_COLORS.get(severity,
                                        _SEVERITY_COLORS["UNKNOWN"])
    target_id    = (chain or {}).get("target_id") or target_url or "-"
    chain_id     = (chain or {}).get("chain_id", "-")
    cve_id       = (chain or {}).get("cve_draft_id", "-")
    steps        = (chain or {}).get("steps", [])
    owasp_cats   = sorted(set((chain or {}).get("owasp_categories", [])))
    data_classes = sorted((impact or {}).get("data_classes_exposed", {}))
    regulatory   = sorted((impact or {}).get("regulatory_impact", []))
    direct       = (impact or {}).get("directly_reached", [])
    transit      = (impact or {}).get("transitively_reachable", [])
    scenario     = ((impact or {}).get("max_harm_scenario", "")
                    or "-")
    envelope_id  = (envelope or {}).get("envelope_id", "-")
    integrity    = (envelope or {}).get("integrity", "")
    generated    = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC")

    agent_cards = ""
    if by_agent:
        for aid, n in sorted(by_agent.items()):
            css = "agent-card" + (" silent" if n == 0 else "")
            agent_cards += (
                f'<div class="{css}"><b>{html.escape(aid)}</b>'
                f'{n} finding{"" if n == 1 else "s"}</div>'
            )

    steps_html = ""
    for s in steps[:30]:
        steps_html += (
            "<tr>"
            f"<td>{s.get('step','?')}</td>"
            f"<td><span class=\"owasp\">"
            f"{html.escape(s.get('owasp_id','AAI00'))}</span></td>"
            f"<td><b>{html.escape(s.get('vuln_class',''))}</b></td>"
            f"<td>{html.escape(s.get('technique',''))}</td>"
            f"<td><span class=\"tag surface\">"
            f"{html.escape(s.get('surface','-'))}</span></td>"
            f"</tr>"
        )
    if len(steps) > 30:
        steps_html += (
            f'<tr><td colspan="5" style="color:#64748b">'
            f'… and {len(steps) - 30} more step(s)</td></tr>'
        )

    reg_tags = "".join(f'<span class="tag reg">{html.escape(r)}</span>'
                       for r in regulatory) or "-"
    data_tags = "".join(f'<span class="tag data">{html.escape(c)}</span>'
                        for c in data_classes) or "-"
    direct_tags = "".join(
        f'<span class="tag surface">{html.escape(s)}</span>'
        for s in direct
    ) or "-"
    transit_tags = "".join(
        f'<span class="tag surface">{html.escape(s)}</span>'
        for s in transit
    ) or "-"

    # ── Findings table ────────────────────────────────────────────
    findings_html = ""
    if findings:
        _SEV_BADGE = {
            "CRITICAL": "background:#b91c1c;color:#fff",
            "HIGH":     "background:#c2410c;color:#fff",
            "MEDIUM":   "background:#d97706;color:#fff",
            "LOW":      "background:#15803d;color:#fff",
            "INFO":     "background:#374151;color:#fff",
        }
        rows = ""
        for f in sorted(findings,
                        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
                        .index(x.get("severity","INFO"))
                        if x.get("severity","INFO") in
                        ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 5):
            sev = f.get("severity", "INFO")
            confirmed = f.get("exploitability_confirmed", False)
            capped    = f.get("confidence_capped", False)
            badge_style = _SEV_BADGE.get(sev, _SEV_BADGE["INFO"])
            confirm_icon = "✓" if confirmed else ("~" if not capped else "⚑")
            confirm_title = ("Confirmed" if confirmed
                             else ("Capped - needs structural proof" if capped
                                   else "Unconfirmed"))
            evidence_short = html.escape(
                (f.get("delta_evidence") or "")[:120]
            )
            rows += (
                f"<tr>"
                f"<td><span style='{badge_style};"
                f"padding:2px 6px;border-radius:3px;font-size:11px;"
                f"font-weight:700'>{html.escape(sev)}</span></td>"
                f"<td title='{confirm_title}' style='text-align:center;"
                f"font-size:14px'>{'🟢' if confirmed else '🟡' if not capped else '🔴'}"
                f"</td>"
                f"<td><b>{html.escape(f.get('agent_id',''))}</b></td>"
                f"<td>{html.escape(f.get('vuln_class',''))}</td>"
                f"<td>{html.escape(f.get('surface','') or '-')}</td>"
                f"<td style='font-size:11px;color:#6b7280'>{evidence_short}</td>"
                f"</tr>"
            )
        findings_html = f"""
<h2 style="margin-top:2rem">Findings ({len(findings)})</h2>
<table style="width:100%;border-collapse:collapse;font-size:12px">
<thead><tr style="background:#1f2937;color:#fff">
  <th style="padding:6px 8px;text-align:left">Severity</th>
  <th style="padding:6px 8px">✓</th>
  <th style="padding:6px 8px;text-align:left">Agent</th>
  <th style="padding:6px 8px;text-align:left">Vuln Class</th>
  <th style="padding:6px 8px;text-align:left">Surface</th>
  <th style="padding:6px 8px;text-align:left">Evidence</th>
</tr></thead>
<tbody style="border:1px solid #e5e7eb">{rows}</tbody>
</table>
<p style="font-size:11px;color:#6b7280;margin-top:4px">
  🟢 Confirmed exploitation &nbsp; | &nbsp;
  🟡 Unconfirmed &nbsp; | &nbsp;
  🔴 Capped (needs structural proof)
</p>"""

    # ── Dual-axis consent bypass visualization ────────────────────
    # Scatter plot: X = human approval probability, Y = impact score
    # Quadrant IV (high approval, high impact) = bypass zone
    consent_viz_html = ""
    try:
        from argus.consent.bypass_scorer import score_consent_bypass
        probe_data = []
        for f in (findings or []):
            surface = f.get("surface", "") or ""
            tool = surface.split(":")[-1] if ":" in surface else surface
            params = {"path": f.get("delta_evidence", "")[:80] or ""}
            score = score_consent_bypass(tool or "unknown", params)
            probe_data.append((
                f.get("title", "")[:40],
                score.approval_score,
                score.impact_score,
                score.category,
                score.bypass_score,
            ))

        if probe_data:
            # Build SVG scatter plot
            W, H = 480, 360
            PAD = 60
            plot_w = W - PAD * 2
            plot_h = H - PAD * 2

            def _px(ax): return int(PAD + ax * plot_w)
            def _py(ay): return int(H - PAD - ay * plot_h)

            _COLORS = {
                "BYPASS": "#b91c1c",
                "BORDERLINE": "#d97706",
                "FLAGGED": "#1d4ed8",
                "BENIGN": "#15803d",
            }

            dots = ""
            for label, appr, imp, cat, bypass in probe_data:
                cx = _px(appr)
                cy = _py(imp)
                color = _COLORS.get(cat, "#6b7280")
                safe_label = html.escape(label)
                dots += (
                    f'<circle cx="{cx}" cy="{cy}" r="8" fill="{color}" '
                    f'opacity="0.85" stroke="#fff" stroke-width="1">'
                    f'<title>{safe_label}\nApproval: {appr:.0%} | '
                    f'Impact: {imp:.0%} | Score: {bypass:.2f} ({cat})</title>'
                    f'</circle>'
                )

            # Bypass zone rectangle (Q4: high approval, high impact)
            zone_x = _px(0.6)
            zone_w = _px(1.0) - zone_x
            zone_y = PAD
            zone_h = _py(0.6) - PAD

            # Build SVG scatter plot using concatenation (avoids f-string unicode issues)
            x_ticks = "".join(
                f'<text x="{_px(v/10)}" y="{H-PAD+14}" text-anchor="middle"'
                f' font-size="9" fill="#9ca3af">{v*10:.0f}%</text>'
                for v in range(0, 11, 2))
            y_ticks = "".join(
                f'<text x="{PAD-8}" y="{_py(v/10)+4}" text-anchor="end"'
                f' font-size="9" fill="#9ca3af">{v*10:.0f}%</text>'
                for v in range(0, 11, 2))
            legend_items = "".join(
                f'<circle cx="{W-PAD-78}" cy="{PAD+14+i*17}" r="5" fill="{c}"/>'
                f'<text x="{W-PAD-68}" y="{PAD+18+i*17}" font-size="9" fill="#374151">{k}</text>'
                for i, (k, c) in enumerate(_COLORS.items()))
            svg_parts = [
                f'<svg viewBox="0 0 {W} {H}" width="{W}" height="{H}"',
                ' style="border:1px solid #e5e7eb;border-radius:6px;background:#f9fafb"',
                ' xmlns="http://www.w3.org/2000/svg">',
                f'<rect x="{zone_x}" y="{zone_y}" width="{zone_w}" height="{zone_h}"',
                ' fill="#fef2f2" stroke="#fca5a5" stroke-width="1" stroke-dasharray="4"/>',
                f'<text x="{zone_x+6}" y="{zone_y+14}" font-size="10" fill="#b91c1c"',
                ' font-weight="bold">BYPASS ZONE</text>',
                f'<line x1="{PAD}" y1="{PAD}" x2="{PAD}" y2="{H-PAD}"',
                ' stroke="#9ca3af" stroke-width="1"/>',
                f'<line x1="{PAD}" y1="{H-PAD}" x2="{W-PAD}" y2="{H-PAD}"',
                ' stroke="#9ca3af" stroke-width="1"/>',
                f'<text x="{W//2}" y="{H-10}" text-anchor="middle"',
                ' font-size="11" fill="#374151">Human Approval Probability</text>',
                f'<text x="14" y="{H//2}" text-anchor="middle"',
                f' font-size="11" fill="#374151" transform="rotate(-90,14,{H//2})">',
                'Attack Impact</text>',
                x_ticks, y_ticks, dots,
                f'<rect x="{W-PAD-90}" y="{PAD}" width="84" height="80"',
                ' fill="white" stroke="#e5e7eb" rx="3"/>',
                legend_items, '</svg>',
            ]
            svg_str = "".join(svg_parts)
            consent_viz_html = (
                '<h2 style="margin-top:2rem">Consent UI Bypass Analysis</h2>'
                '<p style="font-size:12px;color:#6b7280;margin-bottom:8px">'
                'Dual-axis scoring: X = human approval probability, Y = attack impact. '
                'Findings in the <span style="color:#b91c1c;font-weight:700">red zone</span> '
                '(upper-right) are consent bypass candidates - a human would approve them '
                'without recognizing the malicious effect.</p>' + svg_str
            )
    except Exception:
        consent_viz_html = ""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARGUS Report - {html.escape(target_id)}</title>
<style>{_CSS}</style>
</head><body><div class="wrap">

<header>
  <div>
    <h1>ARGUS engagement report</h1>
    <div class="sub">Target: <b>{html.escape(target_id)}</b></div>
    <div class="sub">Chain: {html.escape(chain_id)}  |  CVE-draft: {html.escape(cve_id)}</div>
  </div>
  <div style="text-align:right">
    <span class="badge" style="background:{sev_color}">
      {html.escape(severity)}
    </span>
    <div class="harm" style="color:{sev_color}; margin-top:12px">{harm}</div>
    <div class="sub">harm score / 100</div>
  </div>
</header>

<h2>Executive summary</h2>
<pre class="scenario">{html.escape(scenario)}</pre>

<h2>Regulatory exposure</h2>
<div>{reg_tags}</div>

<h2>Data classes exposed</h2>
<div>{data_tags}</div>

<h2>OWASP Agentic AI Top-10 coverage</h2>
<div>
{''.join(f'<span class="tag owasp" style="font-size:13px">{html.escape(c)}</span> '
         for c in owasp_cats) or '-'}
</div>

<h2>Per-agent landings</h2>
<div class="agents">{agent_cards or "-"}</div>

<h2>Kill-chain steps (MAAC-ordered)</h2>
<table class="step-table"><thead><tr>
<th>#</th><th>OWASP</th><th>Class</th><th>Technique</th><th>Surface</th>
</tr></thead><tbody>{steps_html}</tbody></table>

<h2>Blast radius</h2>
<div class="grid">
  <div class="kv"><b>Directly reached</b><span>{len(direct)}</span></div>
  <div class="kv"><b>Transitively reachable</b><span>{len(transit)}</span></div>
</div>
<div style="margin-top:12px">{direct_tags}</div>
<div style="margin-top:6px">{transit_tags}</div>

<h2>Wilson bundle + ALEC envelope</h2>
<div class="grid">
  <div class="kv"><b>Envelope id</b><span>{html.escape(envelope_id)}</span></div>
  <div class="kv"><b>Integrity SHA</b><span>
    {html.escape(integrity[:32] + ('…' if len(integrity) > 32 else ''))}
  </span></div>
</div>

<h2>SUMMARY.txt (verbatim)</h2>
<pre class="scenario" style="border-left-color:#334155;color:#cbd5e1">
{html.escape(summary_txt)}</pre>

<footer>
  Generated by ARGUS  |  {html.escape(generated)}  | 
  <a href="https://github.com/crewAIInc/crewAI">
    Autonomous AI Red Team Platform</a>
</footer>

{findings_html}
{consent_viz_html}
</div></body></html>
"""


def render_html_from_dir(
    engagement_dir: str | Path,
    *,
    output:         Optional[str | Path] = None,
) -> RenderedReport:
    """Load an engagement dir and render ``report.html``."""
    engagement_dir = Path(engagement_dir).resolve()
    chain    = _read_json(engagement_dir / "chain.json") or {}
    impact   = _read_json(engagement_dir / "impact.json") or {}
    envelope = _read_json(engagement_dir / "alec_envelope.json")
    summary  = _read_text(engagement_dir / "SUMMARY.txt")
    ledger   = _read_json(engagement_dir / "seed_ledger.json") or {}

    # Append pin command to summary so it's visible in the report.
    if ledger.get("pin_command") and summary:
        summary = (summary or "") + (
            f"\n\nReplay: {ledger['pin_command']}"
        )

    # Collect all findings for the findings table.
    all_findings: list[dict] = []
    by_agent: dict[str, int] = {}
    findings_root = engagement_dir / "findings"
    if findings_root.exists():
        for agent_dir in sorted(findings_root.iterdir()):
            if not agent_dir.is_dir():
                continue
            for json_file in agent_dir.glob("*_findings.json"):
                data = _read_json(json_file) or {}
                aid = data.get("agent_id") or agent_dir.name.upper()
                flist = data.get("findings", [])
                by_agent[aid] = by_agent.get(aid, 0) + int(
                    data.get("total_findings", 0))
                all_findings.extend(flist)

    html_out = render_html(
        chain=chain, impact=impact, envelope=envelope,
        summary_txt=summary, by_agent=by_agent,
        findings=all_findings,
    )

    out_path = (Path(output).resolve() if output
                else engagement_dir / "report.html")
    out_path.write_text(html_out, encoding="utf-8")

    return RenderedReport(
        html=html_out, output_path=out_path,
        target_id=chain.get("target_id", ""),
        harm_score=int((impact or {}).get("harm_score", 0)),
        severity=(impact or {}).get("severity_label", "UNKNOWN"),
    )
