"""HTML Report Generator for ARGUS.

Produces a standalone HTML executive summary report suitable for
client delivery. Includes:
- Executive summary with risk metrics
- Findings by severity with full attack chains
- OWASP Agentic AI mapping
- Compound attack paths
- CERBERUS detection rules
- Remediation guidance
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any

from argus.orchestrator.engine import ScanResult
from argus.reporting.cerberus_rules import CerberusRuleGenerator


def _esc(text: Any) -> str:
    """HTML-escape a value safely."""
    return html.escape(str(text)) if text else ""


def _severity_color(severity: str) -> str:
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }
    return colors.get(severity.lower(), "#6b7280")


def _severity_bg(severity: str) -> str:
    colors = {
        "critical": "#fef2f2",
        "high": "#fff7ed",
        "medium": "#fffbeb",
        "low": "#eff6ff",
        "info": "#f9fafb",
    }
    return colors.get(severity.lower(), "#f9fafb")


class HTMLReportGenerator:
    """Generate standalone HTML reports from ARGUS scan results."""

    def generate(self, scan_result: ScanResult, target_name: str = "") -> str:
        """Generate a complete HTML report."""
        summary = scan_result.summary()
        target = target_name or "Unknown Target"
        generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Group findings by severity
        findings_by_sev: dict[str, list] = {}
        for f in scan_result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            findings_by_sev.setdefault(sev, []).append(f)

        # Generate CERBERUS rules
        cerberus_gen = CerberusRuleGenerator()
        cerberus_rules = cerberus_gen.generate_rules(scan_result.validated_findings)

        # Risk score (0-100)
        risk_score = self._calculate_risk_score(scan_result)

        sections = [
            self._render_header(target, generated_at, summary, risk_score),
            self._render_executive_summary(summary, risk_score),
            self._render_agent_results(scan_result),
            self._render_findings(findings_by_sev),
            self._render_compound_paths(scan_result.compound_paths),
            self._render_cerberus_rules(cerberus_rules),
            self._render_remediation_summary(scan_result),
            self._render_footer(generated_at),
        ]

        return self._wrap_html(target, "\n".join(sections))

    def _calculate_risk_score(self, scan_result: ScanResult) -> int:
        """Calculate an overall risk score (0-100) from findings."""
        score = 0
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        for f in scan_result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            score += weights.get(sev, 1)
            if f.is_validated():
                score += weights.get(sev, 1)  # Double weight for validated
        return min(score, 100)

    def _render_header(self, target: str, generated_at: str, summary: dict, risk_score: int) -> str:
        risk_color = "#dc2626" if risk_score >= 70 else "#d97706" if risk_score >= 40 else "#16a34a"
        return f"""
        <div class="header">
            <div class="header-brand">
                <div class="logo">&#9673;</div>
                <div>
                    <h1>ARGUS</h1>
                    <p class="subtitle">Autonomous AI Red Team Platform</p>
                </div>
            </div>
            <div class="header-meta">
                <div class="meta-item"><strong>Target:</strong> {_esc(target)}</div>
                <div class="meta-item"><strong>Generated:</strong> {_esc(generated_at)}</div>
                <div class="meta-item"><strong>Scan ID:</strong> {_esc(summary.get('scan_id', 'N/A'))}</div>
                <div class="meta-item"><strong>Duration:</strong> {summary.get('duration_seconds', 0):.1f}s</div>
            </div>
        </div>
        <div class="risk-banner" style="border-left-color: {risk_color};">
            <div class="risk-score" style="color: {risk_color};">{risk_score}</div>
            <div class="risk-label">
                <strong>Overall Risk Score</strong>
                <span>{'CRITICAL' if risk_score >= 70 else 'ELEVATED' if risk_score >= 40 else 'LOW'} RISK</span>
            </div>
        </div>
        """

    def _render_executive_summary(self, summary: dict, risk_score: int) -> str:
        return f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{summary.get('agents_deployed', 0)}</div>
                    <div class="stat-label">Agents Deployed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{summary.get('total_findings', 0)}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #16a34a;">{summary.get('validated_findings', 0)}</div>
                    <div class="stat-label">Validated</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #7c3aed;">{summary.get('compound_attack_paths', 0)}</div>
                    <div class="stat-label">Attack Paths</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{summary.get('signals_exchanged', 0)}</div>
                    <div class="stat-label">Signals</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: {'#dc2626' if risk_score >= 70 else '#d97706' if risk_score >= 40 else '#16a34a'};">{risk_score}/100</div>
                    <div class="stat-label">Risk Score</div>
                </div>
            </div>
        </div>
        """

    def _render_agent_results(self, scan_result: ScanResult) -> str:
        rows = ""
        for ar in scan_result.agent_results:
            status_color = "#16a34a" if ar.status.value == "completed" else "#dc2626"
            rows += f"""
            <tr>
                <td><strong>{_esc(ar.agent_type.value)}</strong></td>
                <td style="color: {status_color};">{_esc(ar.status.value)}</td>
                <td>{ar.techniques_attempted}</td>
                <td>{ar.techniques_succeeded}</td>
                <td>{ar.findings_count}</td>
                <td>{ar.validated_count}</td>
                <td>{ar.duration_seconds:.1f}s</td>
            </tr>
            """
        return f"""
        <div class="section">
            <h2>Agent Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Agent</th>
                        <th>Status</th>
                        <th>Techniques</th>
                        <th>Succeeded</th>
                        <th>Findings</th>
                        <th>Validated</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        """

    def _render_findings(self, findings_by_sev: dict[str, list]) -> str:
        sev_order = ["critical", "high", "medium", "low", "info"]
        content = ""
        for sev in sev_order:
            findings = findings_by_sev.get(sev, [])
            if not findings:
                continue
            content += f"""
            <div class="severity-group" style="border-left: 4px solid {_severity_color(sev)};">
                <h3 style="color: {_severity_color(sev)};">{sev.upper()} — {len(findings)} finding(s)</h3>
            """
            for f in findings:
                validated = "VALIDATED" if f.is_validated() else "UNVALIDATED"
                val_style = "color: #16a34a;" if f.is_validated() else "color: #9ca3af;"

                # Verdict Weight badge
                vw_badge = ""
                if f.verdict_score:
                    cw = f.verdict_score.get("consequence_weight", 0)
                    tier = f.verdict_score.get("action_tier", "")
                    vw_badge = f'<span class="vw-badge">CW {cw:.2f} · {_esc(tier)}</span>'

                # OWASP mapping
                owasp = ""
                if f.owasp_agentic:
                    val = f.owasp_agentic.value if hasattr(f.owasp_agentic, "value") else str(f.owasp_agentic)
                    owasp = f'<div class="finding-owasp">OWASP: {_esc(val)}</div>'

                # Remediation
                remediation = ""
                if f.remediation:
                    remediation = f'<div class="finding-remediation"><strong>Remediation:</strong> {_esc(f.remediation.summary)}</div>'

                # Attack chain
                chain = ""
                if f.attack_chain:
                    steps = ""
                    for step in f.attack_chain:
                        steps += f"<li><strong>Step {step.step_number}:</strong> {_esc(step.description)}</li>"
                    chain = f'<div class="attack-chain"><strong>Attack Chain:</strong><ol>{steps}</ol></div>'

                content += f"""
                <div class="finding-card" style="background: {_severity_bg(sev)};">
                    <div class="finding-header">
                        <span class="severity-badge" style="background: {_severity_color(sev)};">{sev.upper()}</span>
                        <span class="finding-title">{_esc(f.title)}</span>
                        <span style="{val_style}">{validated}</span>
                        {vw_badge}
                    </div>
                    <div class="finding-body">
                        <p>{_esc(f.description)}</p>
                        <div class="finding-meta">
                            <span>Agent: {_esc(f.agent_type)}</span>
                            <span>Surface: {_esc(f.target_surface)}</span>
                            <span>Technique: {_esc(f.technique)}</span>
                        </div>
                        {owasp}
                        {chain}
                        {remediation}
                    </div>
                </div>
                """
            content += "</div>"

        if not content:
            content = '<p class="empty">No findings detected during this scan.</p>'

        return f"""
        <div class="section">
            <h2>Findings</h2>
            {content}
        </div>
        """

    def _render_compound_paths(self, paths: list) -> str:
        if not paths:
            return ""

        content = ""
        for path in paths:
            sev = path.severity.value if hasattr(path.severity, "value") else str(path.severity)
            steps = ""
            for step in path.attack_path_steps:
                steps += f"<li><strong>{_esc(step.agent_type)}:</strong> {_esc(step.description)}</li>"

            owasp_tags = ""
            if path.owasp_agentic:
                tags = [cat.value if hasattr(cat, "value") else str(cat) for cat in path.owasp_agentic]
                owasp_tags = " · ".join(tags)

            content += f"""
            <div class="compound-card" style="border-left: 4px solid {_severity_color(sev)};">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {_severity_color(sev)};">{sev.upper()}</span>
                    <span class="finding-title">{_esc(path.title)}</span>
                </div>
                <p>{_esc(path.compound_impact)}</p>
                <div class="finding-meta">
                    <span>Exploitability: {path.exploitability_score}/10</span>
                    <span>Detectability: {path.detectability_score}/10</span>
                </div>
                {'<div class="finding-owasp">' + _esc(owasp_tags) + '</div>' if owasp_tags else ''}
                <ol>{steps}</ol>
            </div>
            """

        return f"""
        <div class="section">
            <h2>Compound Attack Paths</h2>
            <p>Multi-agent attack chains that combine individual findings into higher-severity exploits.</p>
            {content}
        </div>
        """

    def _render_cerberus_rules(self, rules: list) -> str:
        if not rules:
            return ""

        rows = ""
        for rule in rules:
            rows += f"""
            <tr>
                <td><code>{_esc(rule.rule_id)}</code></td>
                <td>{_esc(rule.title)}</td>
                <td style="color: {_severity_color(rule.severity.lower())};">{_esc(rule.severity)}</td>
                <td>{_esc(rule.agent_source)}</td>
                <td>{_esc(rule.recommended_action[:100])}</td>
            </tr>
            """

        return f"""
        <div class="section">
            <h2>CERBERUS Detection Rules</h2>
            <p>Auto-generated detection rules for defensive deployment. {len(rules)} rule(s) produced.</p>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Source Agent</th>
                        <th>Recommended Action</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        """

    def _render_remediation_summary(self, scan_result: ScanResult) -> str:
        findings_with_remediation = [f for f in scan_result.findings if f.remediation]
        if not findings_with_remediation:
            return ""

        items = ""
        for f in findings_with_remediation:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            items += f"""
            <div class="remediation-item">
                <span class="severity-badge" style="background: {_severity_color(sev)};">{sev.upper()}</span>
                <strong>{_esc(f.title)}</strong>
                <p>{_esc(f.remediation.summary)}</p>
            </div>
            """

        return f"""
        <div class="section">
            <h2>Remediation Summary</h2>
            <p>Prioritized remediation actions for all findings with guidance.</p>
            {items}
        </div>
        """

    def _render_footer(self, generated_at: str) -> str:
        return f"""
        <div class="footer">
            <p><strong>ARGUS</strong> — Autonomous AI Red Team Platform</p>
            <p>Odingard Security · Six Sense Enterprise Services</p>
            <p>Report generated: {_esc(generated_at)}</p>
            <p class="disclaimer">This report contains security-sensitive information. Handle according to your organization's data classification policy.</p>
        </div>
        """

    def _wrap_html(self, title: str, body: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARGUS Report — {_esc(title)}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, 'Inter', 'Segoe UI', system-ui, sans-serif; font-size: 14px; color: #1a1a2e; background: #f8f9fa; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
.header {{ display: flex; justify-content: space-between; align-items: flex-start; padding: 32px; background: linear-gradient(135deg, #1a1530 0%, #2d1f5e 100%); color: white; border-radius: 12px; margin-bottom: 24px; }}
.header-brand {{ display: flex; align-items: center; gap: 16px; }}
.header-brand h1 {{ font-size: 28px; letter-spacing: 1px; }}
.logo {{ width: 48px; height: 48px; background: linear-gradient(135deg, #8b5cf6, #ec4899); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 28px; }}
.subtitle {{ color: #a5b4fc; font-size: 13px; }}
.header-meta {{ text-align: right; font-size: 12px; color: #c4b5fd; }}
.header-meta .meta-item {{ margin-bottom: 4px; }}
.risk-banner {{ display: flex; align-items: center; gap: 20px; padding: 20px 28px; background: white; border-radius: 12px; border-left: 6px solid; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.risk-score {{ font-size: 48px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
.risk-label {{ font-size: 14px; }}
.risk-label span {{ display: block; font-size: 12px; color: #6b7280; margin-top: 2px; }}
.section {{ background: white; border-radius: 12px; padding: 28px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.section h2 {{ font-size: 20px; margin-bottom: 16px; color: #1a1530; border-bottom: 2px solid #f3f4f6; padding-bottom: 8px; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; }}
.stat-card {{ text-align: center; padding: 16px; background: #f8f9fa; border-radius: 8px; }}
.stat-value {{ font-size: 32px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
.stat-label {{ font-size: 12px; color: #6b7280; margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; padding: 10px 12px; background: #f8f9fa; border-bottom: 2px solid #e5e7eb; font-weight: 600; color: #374151; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #f3f4f6; }}
tr:hover td {{ background: #f9fafb; }}
.severity-group {{ padding: 16px; margin-bottom: 16px; border-radius: 8px; }}
.severity-group h3 {{ margin-bottom: 12px; font-size: 16px; }}
.finding-card {{ padding: 16px; border-radius: 8px; margin-bottom: 12px; border: 1px solid #e5e7eb; }}
.finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }}
.severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
.finding-title {{ font-weight: 600; }}
.finding-body p {{ color: #4b5563; margin-bottom: 8px; }}
.finding-meta {{ display: flex; gap: 16px; font-size: 12px; color: #6b7280; flex-wrap: wrap; margin-bottom: 8px; }}
.finding-owasp {{ font-size: 12px; color: #7c3aed; margin-bottom: 8px; }}
.finding-remediation {{ font-size: 13px; background: #f0fdf4; padding: 8px 12px; border-radius: 6px; border-left: 3px solid #16a34a; }}
.attack-chain {{ margin: 8px 0; }}
.attack-chain ol {{ padding-left: 20px; font-size: 13px; color: #4b5563; }}
.vw-badge {{ font-size: 11px; background: #ede9fe; color: #6d28d9; padding: 2px 8px; border-radius: 4px; font-family: monospace; }}
.compound-card {{ padding: 16px; margin-bottom: 12px; border-radius: 8px; background: #faf5ff; border: 1px solid #e9d5ff; }}
.compound-card ol {{ padding-left: 20px; margin-top: 8px; font-size: 13px; }}
.remediation-item {{ padding: 12px; margin-bottom: 8px; border-radius: 8px; background: #f0fdf4; border: 1px solid #bbf7d0; }}
.remediation-item p {{ color: #166534; margin-top: 4px; font-size: 13px; }}
.footer {{ text-align: center; padding: 24px; color: #9ca3af; font-size: 12px; }}
.disclaimer {{ margin-top: 12px; padding: 12px; background: #fef3c7; color: #92400e; border-radius: 6px; font-size: 11px; }}
.empty {{ color: #9ca3af; font-style: italic; padding: 20px; text-align: center; }}
code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
@media print {{ body {{ background: white; }} .container {{ padding: 0; }} .section {{ box-shadow: none; border: 1px solid #e5e7eb; }} }}
</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>"""
