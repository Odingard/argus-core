"""Report Renderer.

Produces structured finding reports with full attack chains,
reproduction steps, OWASP Agentic AI mapping, and CERBERUS
detection rule recommendations.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus import __version__
from argus.models.agents import AgentStatus
from argus.models.findings import Finding, FindingSeverity
from argus.orchestrator.engine import ScanResult
from argus.ui.colors import agent_color_by_value


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
            f"  Duration:           {s['duration_seconds']:.1f}s" if s["duration_seconds"] else "",
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

    def render_rich_summary(self, scan_result: ScanResult, console: Console) -> None:
        """Render a Rich-formatted summary with color-coded agents."""
        s = scan_result.summary()

        # Header
        header = Text()
        header.append("ARGUS SCAN COMPLETE\n", style="bold red")
        header.append(f"Scan ID: {scan_result.scan_id[:8]}  ", style="dim")
        if s["duration_seconds"]:
            header.append(f"Duration: {s['duration_seconds']:.1f}s  ", style="bold white")
        header.append(f"Findings: {s['total_findings']}  ", style="bold yellow")
        header.append(f"Validated: {s['validated_findings']}  ", style="bold green")
        header.append(f"Compound Paths: {s['compound_attack_paths']}", style="bold magenta")

        # Agent results table
        agent_table = Table(title="Agent Results", expand=True, border_style="red")
        agent_table.add_column("Agent", style="bold")
        agent_table.add_column("Status", justify="center")
        agent_table.add_column("Findings", justify="right")
        agent_table.add_column("Validated", justify="right")
        agent_table.add_column("Techniques", justify="right")
        agent_table.add_column("Duration", justify="right")

        for ar in scan_result.agent_results:
            color = agent_color_by_value(ar.agent_type.value)
            status_style = {
                AgentStatus.COMPLETED: "green",
                AgentStatus.FAILED: "red",
                AgentStatus.TIMED_OUT: "yellow",
                AgentStatus.SKIPPED: "dim",
            }.get(ar.status, "white")
            status_icon = {
                AgentStatus.COMPLETED: "\u2713",
                AgentStatus.FAILED: "\u2717",
                AgentStatus.TIMED_OUT: "\u2298",
                AgentStatus.SKIPPED: "\u2014",
            }.get(ar.status, "?")
            dur = f"{ar.duration_seconds:.1f}s" if ar.duration_seconds else "-"
            agent_table.add_row(
                Text(ar.agent_type.value, style=f"bold {color}"),
                Text(f"{status_icon} {ar.status.value}", style=status_style),
                Text(str(ar.findings_count), style="yellow" if ar.findings_count else "dim"),
                Text(str(ar.validated_count), style="green" if ar.validated_count else "dim"),
                f"{ar.techniques_succeeded}/{ar.techniques_attempted}",
                dur,
            )

        # Severity styles — shared by findings and compound paths tables
        sev_styles = {
            FindingSeverity.CRITICAL: "bold red reverse",
            FindingSeverity.HIGH: "bold red",
            FindingSeverity.MEDIUM: "bold yellow",
            FindingSeverity.LOW: "cyan",
            FindingSeverity.INFO: "dim",
        }

        # Findings by severity
        findings_table = None
        validated = scan_result.validated_findings
        if validated:
            findings_table = Table(title="Validated Findings", expand=True, border_style="yellow")
            findings_table.add_column("Severity", justify="center", width=10)
            findings_table.add_column("Agent", width=22)
            findings_table.add_column("Title")
            findings_table.add_column("Evidence", max_width=60)

            for f in sorted(validated, key=lambda x: list(FindingSeverity).index(x.severity)):
                sev_style = sev_styles.get(f.severity, "white")
                agent_color = agent_color_by_value(f.agent_type)
                # Surface extracted secrets prominently
                evidence_text = ""
                proof = getattr(f, "proof_of_exploitation", "") or ""
                if proof.startswith("[EXTRACTED]"):
                    evidence_text = proof.split("\n")[0]
                elif f.raw_response:
                    evidence_text = f.raw_response[:80] + ("..." if len(f.raw_response) > 80 else "")
                findings_table.add_row(
                    Text(f.severity.value.upper(), style=sev_style),
                    Text(f.agent_type, style=f"bold {agent_color}"),
                    f.title,
                    Text(evidence_text, style="bold green" if "[EXTRACTED]" in evidence_text else "dim"),
                )

        # Assemble output
        console.print(Panel(header, border_style="red", title="[bold red]ARGUS[/]"))
        console.print(agent_table)
        if findings_table:
            console.print(findings_table)

        # Compound paths
        if scan_result.compound_paths:
            paths_table = Table(title="Compound Attack Paths", expand=True, border_style="magenta")
            paths_table.add_column("Severity", justify="center", width=10)
            paths_table.add_column("Title")
            paths_table.add_column("Steps", justify="right")
            paths_table.add_column("Exploitability", justify="right")
            for path in scan_result.compound_paths:
                sev_style = sev_styles.get(path.severity, "white")
                paths_table.add_row(
                    Text(path.severity.value.upper(), style=sev_style),
                    path.title,
                    str(len(path.attack_path_steps)),
                    f"{path.exploitability_score}/10",
                )
            console.print(paths_table)

        return None  # already printed everything above

    def _build_report(self, scan_result: ScanResult) -> dict[str, Any]:
        return {
            "argus_version": __version__,
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
