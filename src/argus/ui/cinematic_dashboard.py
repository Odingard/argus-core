"""ARGUS Cinematic Dashboard.

A Shannon-style retro-terminal live dashboard. Single bordered window
with a scrolling activity log, phase transition banners, and a caption
strip narrating what ARGUS is doing in plain English.

Designed to be GIF-recorded for the launch demo.

Visual style:
- Dark navy background
- Orange double-line border frame (CRT terminal aesthetic)
- Cyan log text with amber highlights for findings
- Phase banners that transition between attack stages
- Bottom caption strip narrates each phase
"""

from __future__ import annotations

import asyncio
import time

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from argus.models.agents import TargetConfig
from argus.orchestrator.engine import Orchestrator, ScanResult
from argus.orchestrator.signal_bus import Signal, SignalType

# Shannon-inspired color palette
COLOR_BORDER = "dark_orange"
COLOR_BG = "grey3"
COLOR_TIMESTAMP = "grey50"
COLOR_BULLET = "dark_orange"
COLOR_INFO = "cyan"
COLOR_ACTION = "bright_cyan"
COLOR_FINDING = "bright_yellow"
COLOR_CRITICAL = "bold red"
COLOR_VALIDATED = "bold bright_green"
COLOR_PHASE = "black on dark_orange"
COLOR_NARRATION = "italic grey70"


BANNER = r"""[bold dark_orange]
                    █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
                   ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
                   ███████║██████╔╝██║  ███╗██║   ██║███████╗
                   ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
                   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
                   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝
[/bold dark_orange][bright_yellow]
                AUTONOMOUS  AI  RED  TEAM  PLATFORM[/bright_yellow]
[grey50]                    Odingard Security · Six Sense[/grey50]
"""


# Plain-English narration for each phase of the scan
PHASE_NARRATIONS = {
    "init": "Loading attack corpus and connecting to target environment...",
    "deploy": "Deploying specialized offensive AI agents simultaneously at T=0...",
    "tool_scan": "Scanning MCP tool definitions for hidden adversarial content...",
    "injection": "Firing prompt injection payloads across every input surface...",
    "supply_chain": "Analyzing supply chain trust and dependency confusion risks...",
    "validation": "Validating findings with reproducible proof-of-exploitation...",
    "complete": "Scan complete. Generating final report.",
}


# Phase mapping based on what activity is happening
def _detect_phase(agent_type: str, action: str) -> str:
    if "scan" in action.lower() and "tool" in action.lower():
        return "tool_scan"
    if agent_type == "prompt_injection_hunter":
        return "injection"
    if agent_type == "supply_chain":
        return "supply_chain"
    if agent_type == "tool_poisoning":
        return "tool_scan"
    return "deploy"


class LogEntry:
    """A single line in the scrolling activity log."""

    def __init__(
        self,
        timestamp: float,
        kind: str,
        text: str,
        color: str | None = None,
    ) -> None:
        self.timestamp = timestamp
        self.kind = kind  # "info", "action", "finding", "critical", "phase"
        self.text = text
        self.color = color or COLOR_INFO

    def render(self, scan_start: float) -> Text:
        elapsed = self.timestamp - scan_start
        ts = f"[{int(elapsed // 60):02d}:{int(elapsed % 60):02d}]"

        bullet_map = {
            "info": "▸",
            "action": "◆",
            "finding": "⚠",
            "critical": "✗",
            "validated": "✓",
            "phase": "█",
        }
        bullet = bullet_map.get(self.kind, "·")

        line = Text()
        line.append(f"{ts} ", style=COLOR_TIMESTAMP)
        line.append(f"{bullet} ", style=COLOR_BULLET)
        line.append(self.text, style=self.color)
        return line


class CinematicDashboard:
    """Shannon-style retro-terminal live dashboard for ARGUS scans."""

    def __init__(self, console: Console | None = None, max_log_lines: int = 24) -> None:
        self.console = console or Console()
        self.max_log_lines = max_log_lines
        self.log: list[LogEntry] = []
        self.scan_started: float | None = None
        self.target_name: str = ""
        self.target_urls: list[str] = []
        self.current_phase: str = "init"
        self.current_narration: str = PHASE_NARRATIONS["init"]
        self.total_findings = 0
        self.total_validated = 0
        self.total_signals = 0
        self.agents_running = 0
        self.agents_completed = 0
        self.agents_total = 0

    def _add_log(self, kind: str, text: str, color: str | None = None) -> None:
        entry = LogEntry(time.monotonic(), kind, text, color)
        self.log.append(entry)
        if len(self.log) > self.max_log_lines * 3:
            self.log = self.log[-self.max_log_lines * 2 :]

    def _set_phase(self, phase: str) -> None:
        if phase != self.current_phase:
            self.current_phase = phase
            self.current_narration = PHASE_NARRATIONS.get(phase, "")
            self._add_log("phase", phase.upper().replace("_", " "), color="bold dark_orange")

    async def _on_signal(self, signal: Signal) -> None:
        """Handler attached to the signal bus."""
        self.total_signals += 1

        if signal.signal_type == SignalType.AGENT_STATUS:
            status = signal.data.get("status", "")
            agent = signal.source_agent
            if status == "running":
                self.agents_running += 1
                self._add_log("action", f"{agent} deployed", color=COLOR_ACTION)
            elif status == "completed":
                self.agents_running = max(0, self.agents_running - 1)
                self.agents_completed += 1
                count = signal.data.get("findings_count", 0)
                self._add_log(
                    "validated",
                    f"{agent} complete — {count} findings",
                    color=COLOR_VALIDATED,
                )

        elif signal.signal_type == SignalType.FINDING:
            self.total_findings += 1
            finding_data = signal.data.get("finding", {})
            title = finding_data.get("title", "")
            severity = finding_data.get("severity", "info")
            agent = finding_data.get("agent_type", signal.source_agent)
            validated = finding_data.get("status") == "validated"
            verdict = finding_data.get("verdict_score") or {}
            cw = verdict.get("consequence_weight")

            if validated:
                self.total_validated += 1

            color = COLOR_FINDING
            if severity == "critical":
                color = COLOR_CRITICAL
            elif severity == "high":
                color = COLOR_FINDING

            kind = "finding" if not validated else "validated"
            cw_badge = f"CW={cw:.2f} " if cw is not None else ""
            self._add_log(kind, f"{cw_badge}{agent}: {title[:70]}", color=color)
            self._set_phase(_detect_phase(agent, title))

        elif signal.signal_type == SignalType.PARTIAL_FINDING:
            agent = signal.source_agent
            data_str = str(signal.data.get("type", "probing"))[:60]
            self._add_log("info", f"{agent} probing: {data_str}", color=COLOR_INFO)

    def _build_log_panel(self) -> Panel:
        scan_start = self.scan_started or time.monotonic()
        recent = self.log[-self.max_log_lines :]

        if not recent:
            content = Align.center(Text("Initializing...", style="dim"))
        else:
            lines = []
            for entry in recent:
                if entry.kind == "phase":
                    # Phase banner — full-width colored bar
                    banner = Text()
                    banner.append("  ", style=COLOR_PHASE)
                    banner.append(f"  {entry.text}  ", style=COLOR_PHASE)
                    banner.append("  ", style=COLOR_PHASE)
                    lines.append(banner)
                else:
                    lines.append(entry.render(scan_start))

            content = Group(*lines)

        return Panel(
            content,
            title="[bold dark_orange]◆  ATTACK STREAM  ◆[/]",
            border_style=COLOR_BORDER,
            padding=(0, 2),
            style=COLOR_BG,
        )

    def _build_status_strip(self) -> Panel:
        elapsed = time.monotonic() - self.scan_started if self.scan_started else 0.0

        target_line = Text()
        target_line.append("◉ TARGET  ", style="bold dark_orange")
        target_line.append(f"{self.target_name}", style="bold white")
        if self.target_urls:
            target_line.append("   ", style="dim")
            target_line.append(f"({len(self.target_urls)} endpoints)", style="grey50")
        target_line.append("    \u2502    ", style="grey30")
        target_line.append("VERDICT WEIGHT\u2122", style="bold dark_orange")
        target_line.append(" scored", style="grey50")

        stats_line = Text()
        stats_line.append("ELAPSED ", style="grey50")
        stats_line.append(f"{elapsed:>6.1f}s", style="bold cyan")
        stats_line.append("    AGENTS ", style="grey50")
        stats_line.append(
            f"{self.agents_completed}/{self.agents_total}",
            style="bold bright_green" if self.agents_completed == self.agents_total else "bold yellow",
        )
        stats_line.append("    FINDINGS ", style="grey50")
        stats_line.append(f"{self.total_findings}", style="bold yellow")
        stats_line.append("    VALIDATED ", style="grey50")
        stats_line.append(f"{self.total_validated}", style="bold bright_green")
        stats_line.append("    SIGNALS ", style="grey50")
        stats_line.append(f"{self.total_signals}", style="bold magenta")

        return Panel(
            Group(target_line, Text(""), stats_line),
            border_style=COLOR_BORDER,
            padding=(0, 2),
            style=COLOR_BG,
        )

    def _build_narration(self) -> Panel:
        text = Text()
        text.append("⌖  ", style=COLOR_BULLET)
        text.append(self.current_narration, style=COLOR_NARRATION)
        return Panel(
            Align.center(text),
            border_style=COLOR_BORDER,
            padding=(0, 2),
            style=COLOR_BG,
        )

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="status", size=5),
            Layout(name="log"),
            Layout(name="narration", size=3),
        )
        layout["status"].update(self._build_status_strip())
        layout["log"].update(self._build_log_panel())
        layout["narration"].update(self._build_narration())
        return layout

    async def run(
        self,
        orchestrator: Orchestrator,
        target: TargetConfig,
        timeout: float = 300.0,
        refresh_per_second: int = 12,
        demo_pace_seconds: float = 0.4,
    ) -> ScanResult:
        """Run a scan with the cinematic dashboard active."""
        self.target_name = target.name
        self.target_urls = list(target.mcp_server_urls)
        if target.agent_endpoint:
            self.target_urls.append(target.agent_endpoint)
        self.scan_started = time.monotonic()
        self.agents_total = len(orchestrator.get_registered_agents())

        # Pre-flight log entries
        self._add_log("info", "Loading attack corpus...", color=COLOR_INFO)
        self._add_log("info", f"Connecting to target: {target.name}", color=COLOR_INFO)
        for url in self.target_urls:
            self._add_log("info", f"Discovered endpoint: {url}", color=COLOR_INFO)
        self._add_log("info", f"Initializing {self.agents_total} attack agents", color=COLOR_INFO)
        self._set_phase("deploy")

        # Subscribe to signal bus
        await orchestrator.signal_bus.subscribe_broadcast(self._on_signal)

        # Print banner
        self.console.print(BANNER)
        self.console.print()

        with Live(
            self._build_layout(),
            console=self.console,
            refresh_per_second=refresh_per_second,
            screen=False,
            transient=False,
        ) as live:
            scan_task = asyncio.create_task(
                orchestrator.run_scan(
                    target=target,
                    timeout=timeout,
                    demo_pace_seconds=demo_pace_seconds,
                )
            )

            while not scan_task.done():
                live.update(self._build_layout())
                await asyncio.sleep(1.0 / refresh_per_second)

            # Final state
            self._set_phase("complete")
            live.update(self._build_layout())
            result = await scan_task

            # Hold the final frame for 2 seconds so it's visible in recordings
            for _ in range(refresh_per_second * 2):
                live.update(self._build_layout())
                await asyncio.sleep(1.0 / refresh_per_second)

        self._print_final(result)
        return result

    def _print_final(self, result: ScanResult) -> None:
        summary = result.summary()
        self.console.print()
        final = Text()
        final.append("◆  SCAN COMPLETE  ◆  ", style="bold dark_orange")
        final.append(f"{summary['duration_seconds']:.2f}s  ", style="bold cyan")
        final.append("·  ", style="grey50")
        final.append(f"{summary['total_findings']} findings  ", style="bold yellow")
        final.append("·  ", style="grey50")
        final.append(f"{summary['validated_findings']} validated  ", style="bold bright_green")
        final.append("·  ", style="grey50")
        final.append(f"{summary['signals_exchanged']} signals", style="bold magenta")
        self.console.print(
            Panel(
                Align.center(final),
                border_style=COLOR_BORDER,
                padding=(1, 2),
                style=COLOR_BG,
            )
        )
