"""
argus/report/render.py — engagement-dir → report.html renderer.

Pure-Python, zero deps. Reads the artifact package an engagement
wrote and emits a single self-contained HTML file with inline CSS.
The HTML is safe to email, attach to a ticket, or open offline —
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
) -> str:
    """Compose the report HTML from already-parsed artifact dicts."""
    severity     = (impact or {}).get("severity_label", "UNKNOWN")
    harm         = (impact or {}).get("harm_score", 0)
    sev_color    = _SEVERITY_COLORS.get(severity,
                                        _SEVERITY_COLORS["UNKNOWN"])
    target_id    = (chain or {}).get("target_id") or target_url or "—"
    chain_id     = (chain or {}).get("chain_id", "—")
    cve_id       = (chain or {}).get("cve_draft_id", "—")
    steps        = (chain or {}).get("steps", [])
    owasp_cats   = sorted(set((chain or {}).get("owasp_categories", [])))
    data_classes = sorted((impact or {}).get("data_classes_exposed", {}))
    regulatory   = sorted((impact or {}).get("regulatory_impact", []))
    direct       = (impact or {}).get("directly_reached", [])
    transit      = (impact or {}).get("transitively_reachable", [])
    scenario     = ((impact or {}).get("max_harm_scenario", "")
                    or "—")
    envelope_id  = (envelope or {}).get("envelope_id", "—")
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
            f"{html.escape(s.get('surface','—'))}</span></td>"
            f"</tr>"
        )
    if len(steps) > 30:
        steps_html += (
            f'<tr><td colspan="5" style="color:#64748b">'
            f'… and {len(steps) - 30} more step(s)</td></tr>'
        )

    reg_tags = "".join(f'<span class="tag reg">{html.escape(r)}</span>'
                       for r in regulatory) or "—"
    data_tags = "".join(f'<span class="tag data">{html.escape(c)}</span>'
                        for c in data_classes) or "—"
    direct_tags = "".join(
        f'<span class="tag surface">{html.escape(s)}</span>'
        for s in direct
    ) or "—"
    transit_tags = "".join(
        f'<span class="tag surface">{html.escape(s)}</span>'
        for s in transit
    ) or "—"

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARGUS Report — {html.escape(target_id)}</title>
<style>{_CSS}</style>
</head><body><div class="wrap">

<header>
  <div>
    <h1>ARGUS engagement report</h1>
    <div class="sub">Target: <b>{html.escape(target_id)}</b></div>
    <div class="sub">Chain: {html.escape(chain_id)} · CVE-draft: {html.escape(cve_id)}</div>
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
         for c in owasp_cats) or '—'}
</div>

<h2>Per-agent landings</h2>
<div class="agents">{agent_cards or "—"}</div>

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
  Generated by ARGUS · {html.escape(generated)} ·
  <a href="https://github.com/crewAIInc/crewAI">
    Autonomous AI Red Team Platform</a>
</footer>

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

    # Reconstruct by_agent from finding subdirs.
    by_agent: dict[str, int] = {}
    findings_root = engagement_dir / "findings"
    if findings_root.exists():
        for agent_dir in findings_root.iterdir():
            if not agent_dir.is_dir():
                continue
            for json_file in agent_dir.glob("*_findings.json"):
                data = _read_json(json_file) or {}
                aid = data.get("agent_id") or agent_dir.name.upper()
                by_agent[aid] = by_agent.get(aid, 0) + int(
                    data.get("total_findings", 0))

    html_out = render_html(
        chain=chain, impact=impact, envelope=envelope,
        summary_txt=summary, by_agent=by_agent,
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
