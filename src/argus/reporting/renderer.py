"""Report Renderer.

Produces structured finding reports with full attack chains,
reproduction steps, OWASP Agentic AI mapping, and CERBERUS
detection rule recommendations.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from argus.models.findings import Finding, FindingSeverity
from argus.orchestrator.engine import ScanResult


class ReportRenderer:
    """Renders ARGUS scan results into structured reports."""

    def render_json(self, scan_result: ScanResult) -> str:
        """Render full scan result as JSON."""
        return json.dumps(self._build_report(scan_result), indent=2, default=str)

    def render_summary(self, scan_result: ScanResult) -> str:
        """Render a human-readable summary."""
        s = scan_result.summary()
        lines = [
            "=" * 70,
            "  ARGUS — Autonomous AI Red Team — Scan Report",
            "=" * 70,
            f"  Scan ID:            {scan_result.scan_id}",
            f"  Duration:           {s['duration_seconds']:.1f}s" if s['duration_seconds'] else "",
            f"  Agents Deployed:    {s['agents_deployed']}",
            f"  Agents Completed:   {s['agents_completed']}",
            f"  Agents Failed:      {s['agents_failed']}",
            "",
            f"  Total Findings:     {s['total_findings']}",
            f"  Validated:          {s['validated_findings']}",
            f"  Compound Paths:     {s['compound_attack_paths']}",
            f"  Signals Exchanged:  {s['signals_exchanged']}",
            "=" * 70,
        ]

        # Findings by severity
        validated = scan_result.validated_findings
        if validated:
            lines.append("\n  VALIDATED FINDINGS")
            lines.append("  " + "-" * 66)

            by_severity = self._group_by_severity(validated)
            sev_order = [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW]
            for severity in sev_order:
                findings = by_severity.get(severity, [])
                if findings:
                    lines.append(f"\n  [{severity.value.upper()}] — {len(findings)} finding(s)")
                    for f in findings:
                        lines.append(f"    • {f.title}")
                        lines.append(f"      Agent: {f.agent_type} | Surface: {f.target_surface}")
                        if f.owasp_agentic:
                            lines.append(f"      OWASP: {f.owasp_agentic.value}")

        # Compound attack paths
        if scan_result.compound_paths:
            lines.append("\n  COMPOUND ATTACK PATHS")
            lines.append("  " + "-" * 66)
            for path in scan_result.compound_paths:
                lines.append(f"\n  [{path.severity.value.upper()}] {path.title}")
                lines.append(f"    Impact: {path.compound_impact}")
                lines.append(f"    Steps: {len(path.attack_path_steps)}")
                lines.append(f"    Exploitability: {path.exploitability_score}/10")

        lines.append("\n" + "=" * 70)
        lines.append("  ARGUS — Odingard Security — Six Sense Enterprise Services")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _build_report(self, scan_result: ScanResult) -> dict[str, Any]:
        return {
            "argus_version": "0.1.0",
            "report_generated": datetime.now(UTC).isoformat(),
            "scan": scan_result.summary(),
            "findings": [f.model_dump() for f in scan_result.findings],
            "compound_attack_paths": [p.model_dump() for p in scan_result.compound_paths],
            "agent_results": [r.model_dump() for r in scan_result.agent_results],
        }

    def _group_by_severity(self, findings: list[Finding]) -> dict[FindingSeverity, list[Finding]]:
        groups: dict[FindingSeverity, list[Finding]] = {}
        for f in findings:
            groups.setdefault(f.severity, []).append(f)
        return groups
