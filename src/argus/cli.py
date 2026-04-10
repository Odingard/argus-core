"""ARGUS CLI — command-line interface for the autonomous AI red team platform.

Security: validates all user input (URLs, file paths) before use.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus import __version__
from argus.agents import (
    ContextWindowAgent,
    CrossAgentExfilAgent,
    IdentitySpoofAgent,
    MemoryBoundaryCollapseAgent,
    MemoryPoisoningAgent,
    ModelExtractionAgent,
    PersonaHijackingAgent,
    PrivilegeEscalationAgent,
    PromptInjectionHunter,
    RaceConditionAgent,
    SupplyChainAgent,
    ToolPoisoningAgent,
)
from argus.corpus.manager import AttackCorpus
from argus.db.repository import APIKeyRepository, ScanRepository, TargetRepository
from argus.db.scan_persistence import ScanPersistence
from argus.db.session import init_db
from argus.models.agents import AgentType, TargetConfig
from argus.orchestrator.engine import Orchestrator
from argus.reporting.alec_export import ALECEvidenceExporter
from argus.reporting.renderer import ReportRenderer


def _create_orchestrator() -> Orchestrator:
    """Create an orchestrator with all attack agents registered."""
    orch = Orchestrator()
    # Phase 1
    orch.register_agent(AgentType.PROMPT_INJECTION, PromptInjectionHunter)
    orch.register_agent(AgentType.TOOL_POISONING, ToolPoisoningAgent)
    orch.register_agent(AgentType.SUPPLY_CHAIN, SupplyChainAgent)
    # Phase 2
    orch.register_agent(AgentType.MEMORY_POISONING, MemoryPoisoningAgent)
    orch.register_agent(AgentType.IDENTITY_SPOOF, IdentitySpoofAgent)
    # Phase 3
    orch.register_agent(AgentType.CONTEXT_WINDOW, ContextWindowAgent)
    orch.register_agent(AgentType.CROSS_AGENT_EXFIL, CrossAgentExfilAgent)
    orch.register_agent(AgentType.PRIVILEGE_ESCALATION, PrivilegeEscalationAgent)
    orch.register_agent(AgentType.RACE_CONDITION, RaceConditionAgent)
    # Phase 4
    orch.register_agent(AgentType.MODEL_EXTRACTION, ModelExtractionAgent)
    # Phase 5
    orch.register_agent(AgentType.PERSONA_HIJACKING, PersonaHijackingAgent)
    orch.register_agent(AgentType.MEMORY_BOUNDARY_COLLAPSE, MemoryBoundaryCollapseAgent)
    return orch


console = Console()

ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


BANNER = r"""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗    ║
    ║    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝    ║
    ║    ███████║██████╔╝██║  ███╗██║   ██║███████╗    ║
    ║    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║    ║
    ║    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║    ║
    ║    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝    ║
    ║                                                   ║
    ║       Autonomous AI Red Team Platform             ║
    ║       Odingard Security · Six Sense               ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
"""


def _validate_url(url: str) -> None:
    """Validate URL has allowed scheme and valid hostname. Prevents SSRF."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise click.BadParameter(f"URL scheme '{parsed.scheme}' not allowed. Use http:// or https://")
    if not parsed.netloc:
        raise click.BadParameter("URL must have a valid hostname")


def _validate_output_path(path_str: str) -> Path:
    """Validate output file path — must be within CWD, no symlink attacks."""
    output_path = Path(path_str).resolve()
    cwd = Path.cwd().resolve()

    if not str(output_path).startswith(str(cwd)):
        raise click.BadParameter(f"Output path must be within current directory ({cwd})")

    # Reject if parent directory is a symlink
    if output_path.parent.is_symlink():
        raise click.BadParameter("Output path parent is a symlink")

    return output_path


@click.group()
@click.version_option(version=__version__, prog_name="ARGUS")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(verbose: bool) -> None:
    """ARGUS — Autonomous AI Red Team Platform."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@main.command()
def banner() -> None:
    """Display the ARGUS banner."""
    console.print(BANNER, style="bold red")


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind the web server to")
@click.option("--port", default=8765, help="Port to bind the web server to")
@click.option("--reload", is_flag=True, help="Enable auto-reload (development)")
def serve(host: str, port: int, reload: bool) -> None:
    """Launch the ARGUS web dashboard.

    Starts the FastAPI server with the live web UI for running scans
    and watching results in real time. Open http://localhost:8765 in
    your browser after starting.
    """
    import uvicorn

    console.print(BANNER, style="bold red")
    console.print(f"\n[bold]ARGUS Web Dashboard[/] starting on [cyan]http://{host}:{port}[/]\n")
    console.print("[dim]Make sure benchmark containers are running:[/]")
    console.print("[dim]  docker compose -f benchmark/docker-compose.yml up -d[/]\n")

    uvicorn.run(
        "argus.web.server:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
        log_level="info",
    )


@main.command()
def status() -> None:
    """Show ARGUS system status."""
    orch = _create_orchestrator()
    agent_count = len(orch.get_registered_agents())
    agent_names = [a.value for a in orch.get_registered_agents()]

    console.print(
        Panel.fit(
            f"[bold red]ARGUS[/] v{__version__}\n\n"
            f"[bold]Phase:[/] 1 — First Wave Agents\n"
            f"[bold]Agents Registered:[/] {agent_count}\n"
            f"[bold]Agents:[/] {', '.join(agent_names)}\n"
            "[bold]Corpus Status:[/] Checking...",
            title="System Status",
        )
    )

    corpus = AttackCorpus()
    corpus.load()
    stats = corpus.stats()

    table = Table(title="Attack Corpus")
    table.add_column("Category", style="cyan")
    table.add_column("Patterns", justify="right", style="green")
    for cat, num in sorted(stats["by_category"].items()):
        table.add_row(cat, str(num))
    table.add_row("[bold]Total[/]", f"[bold]{stats['total_patterns']}[/]")
    console.print(table)


@main.command()
@click.argument("target_name")
@click.option("--mcp-url", multiple=True, help="MCP server URL(s) to test")
@click.option("--agent-endpoint", help="Target agent endpoint URL")
@click.option("--timeout", default=600, help="Scan timeout in seconds")
@click.option(
    "--demo",
    is_flag=True,
    help="Enable demo pacing (0.4s between findings) so updates are visible",
)
@click.option(
    "--pace",
    type=float,
    default=0.0,
    help="Custom inter-event delay in seconds (overrides --demo)",
)
@click.option(
    "--cinematic",
    is_flag=True,
    help="Use the cinematic retro-terminal dashboard (for demos/recordings)",
)
def live(
    target_name: str,
    mcp_url: tuple[str, ...],
    agent_endpoint: str | None,
    timeout: int,
    demo: bool,
    pace: float,
    cinematic: bool,
) -> None:
    """Run an ARGUS scan with the LIVE streaming dashboard.

    Watch the attack swarm work in real time — agent status, findings,
    signal bus events, all updating live in your terminal.

    --cinematic switches to the retro-terminal cinematic dashboard
    designed for screen recording and demo capture.
    """
    for url in mcp_url:
        _validate_url(url)
    if agent_endpoint:
        _validate_url(agent_endpoint)

    target = TargetConfig(
        name=target_name,
        mcp_server_urls=list(mcp_url),
        agent_endpoint=agent_endpoint,
    )

    from argus.ui import CinematicDashboard, LiveDashboard

    orchestrator = _create_orchestrator()
    pace_seconds = pace if pace > 0 else (0.4 if demo or cinematic else 0.0)

    if cinematic:
        dashboard = CinematicDashboard(console=console)
    else:
        dashboard = LiveDashboard(console=console)

    asyncio.run(
        dashboard.run(
            orchestrator,
            target,
            timeout=float(timeout),
            demo_pace_seconds=pace_seconds,
        )
    )


@main.command()
@click.argument("target_name")
@click.option("--mcp-url", multiple=True, help="MCP server URL(s) to test")
@click.option("--agent-endpoint", help="Target agent endpoint URL")
@click.option("--timeout", default=600, help="Scan timeout in seconds")
@click.option("--output", "-o", help="Output file path for JSON report")
def scan(
    target_name: str,
    mcp_url: tuple[str, ...],
    agent_endpoint: str | None,
    timeout: int,
    output: str | None,
) -> None:
    """Run an ARGUS scan against a target AI system."""
    # Validate all URLs
    for url in mcp_url:
        _validate_url(url)
    if agent_endpoint:
        _validate_url(agent_endpoint)

    # Validate output path
    output_path = None
    if output:
        output_path = _validate_output_path(output)

    console.print(BANNER, style="bold red")
    console.print(f"\n[bold]Target:[/] {target_name}")
    console.print(f"[bold]MCP URLs:[/] {', '.join(mcp_url) if mcp_url else 'None'}")
    console.print(f"[bold]Agent Endpoint:[/] {agent_endpoint or 'None'}")
    console.print(f"[bold]Timeout:[/] {timeout}s\n")

    target = TargetConfig(
        name=target_name,
        mcp_server_urls=list(mcp_url),
        agent_endpoint=agent_endpoint,
    )

    orchestrator = _create_orchestrator()
    registered = orchestrator.get_registered_agents()

    console.print(f"[bold]Deploying {len(registered)} agents simultaneously...[/]\n")

    result = asyncio.run(orchestrator.run_scan(target=target, timeout=timeout))

    # Persist scan results to database
    try:
        persistence = ScanPersistence()
        try:
            persistence.save(scan_result=result, target_name=target_name, initiated_by="cli")
        finally:
            persistence.close()
        console.print("[dim]Scan persisted to database[/]")
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not persist scan: {type(exc).__name__}[/]")

    renderer = ReportRenderer()
    console.print(renderer.render_summary(result))

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(renderer.render_json(result))
        console.print(f"\n[green]Full report written to {output_path}[/]")


@main.command(name="alec-export")
@click.argument("target_name")
@click.option("--mcp-url", multiple=True, help="MCP server URL(s) to test")
@click.option("--agent-endpoint", help="Target agent endpoint URL")
@click.option("--timeout", default=600, help="Scan timeout in seconds")
@click.option("--output", "-o", required=True, help="Output file path for ALEC evidence package")
def alec_export(
    target_name: str,
    mcp_url: tuple[str, ...],
    agent_endpoint: str | None,
    timeout: int,
    output: str,
) -> None:
    """Run a scan and export an ALEC evidence package.

    Produces a structured evidence package compatible with ALEC
    (Autonomous Legal Evidence Chain) for legal-grade incident
    documentation. Includes SHA-256 integrity hashes, chain-of-custody
    metadata, and CERBERUS cross-references.
    """
    for url in mcp_url:
        _validate_url(url)
    if agent_endpoint:
        _validate_url(agent_endpoint)

    output_path = _validate_output_path(output)

    console.print(BANNER, style="bold red")
    console.print("\n[bold]ALEC Evidence Export[/]")
    console.print(f"[bold]Target:[/] {target_name}")
    console.print(f"[bold]Output:[/] {output_path}\n")

    target = TargetConfig(
        name=target_name,
        mcp_server_urls=list(mcp_url),
        agent_endpoint=agent_endpoint,
    )

    orchestrator = _create_orchestrator()
    result = asyncio.run(orchestrator.run_scan(target=target, timeout=timeout))

    exporter = ALECEvidenceExporter()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(exporter.export_json(result))

    console.print(f"\n[green]ALEC evidence package written to {output_path}[/]")
    console.print(f"[dim]Validated findings: {len(result.validated_findings)}[/]")
    console.print(f"[dim]Compound paths: {len(result.compound_paths)}[/]")


@main.command()
def corpus() -> None:
    """Show attack corpus statistics."""
    c = AttackCorpus()
    c.load()
    stats = c.stats()

    console.print(
        Panel.fit(
            f"[bold]Total Patterns:[/] {stats['total_patterns']}\n"
            f"[bold]With Usage Data:[/] {stats['patterns_with_usage']}",
            title="Attack Corpus v0.1",
        )
    )

    table = Table(title="Patterns by Category")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="green")
    for cat, num in sorted(stats["by_category"].items()):
        table.add_row(cat, str(num))
    console.print(table)


@main.command()
@click.argument("mcp_url")
def probe(mcp_url: str) -> None:
    """Probe an MCP server — enumerate tools and scan for hidden content."""
    _validate_url(mcp_url)

    from argus.mcp_client import MCPAttackClient, MCPServerConfig

    config = MCPServerConfig(
        name="probe-target",
        transport="streamable-http",
        url=mcp_url,
    )

    async def _probe() -> None:
        client = MCPAttackClient(config)
        try:
            await client.connect()
            tools = await client.enumerate_tools()

            table = Table(title=f"MCP Tools — {mcp_url}")
            table.add_column("Tool", style="cyan")
            table.add_column("Description", style="white", max_width=50)
            table.add_column("Params", justify="right")
            table.add_column("Hidden Content", style="red")

            for tool in tools:
                table.add_row(
                    tool.name,
                    (tool.description or "")[:50],
                    str(len(tool.parameters)),
                    "YES" if tool.hidden_content_detected else "-",
                )

            console.print(table)

            hidden = [t for t in tools if t.hidden_content_detected]
            if hidden:
                console.print(f"\n[bold red]{len(hidden)} tool(s) with hidden content detected![/]")
                for t in hidden:
                    console.print(f"  - {t.name}: {t.hidden_content}")

        finally:
            await client.disconnect()

    asyncio.run(_probe())


# ---------------------------------------------------------------------------
# Target management commands
# ---------------------------------------------------------------------------


@main.group()
def target() -> None:
    """Manage client scan targets."""
    init_db()


@target.command(name="create")
@click.argument("name")
@click.option("--mcp-url", multiple=True, help="MCP server URL(s)")
@click.option("--agent-endpoint", help="Agent endpoint URL")
@click.option("--environment", default="staging", help="Target environment")
@click.option("--description", default="", help="Target description")
@click.option("--rpm", default=60, help="Max requests per minute")
@click.option("--client-name", default="", help="Client organization name")
def target_create(
    name: str,
    mcp_url: tuple[str, ...],
    agent_endpoint: str | None,
    environment: str,
    description: str,
    rpm: int,
    client_name: str,
) -> None:
    """Register a new client target for scanning."""
    for url in mcp_url:
        _validate_url(url)
    if agent_endpoint:
        _validate_url(agent_endpoint)

    repo = TargetRepository()
    t = repo.create(
        name=name,
        mcp_server_urls=list(mcp_url),
        agent_endpoint=agent_endpoint,
        environment=environment,
        description=description,
        max_requests_per_minute=rpm,
        client_name=client_name,
    )
    repo.close()
    console.print(f"[green]Target created:[/] {t['name']} (id={t['id'][:8]}...)")


@target.command(name="list")
def target_list() -> None:
    """List all registered targets."""
    repo = TargetRepository()
    targets = repo.list_all()
    repo.close()

    if not targets:
        console.print("[dim]No targets registered. Use 'argus target create' to add one.[/]")
        return

    table = Table(title="Registered Targets")
    table.add_column("ID", style="dim", max_width=10)
    table.add_column("Name", style="cyan")
    table.add_column("Environment", style="yellow")
    table.add_column("MCP URLs", justify="right")
    table.add_column("RPM", justify="right")
    table.add_column("Client")
    for t in targets:
        table.add_row(
            t["id"][:8] + "...",
            t["name"],
            t["environment"],
            str(len(t.get("mcp_server_urls", []))),
            str(t["max_requests_per_minute"]),
            t.get("client_name", ""),
        )
    console.print(table)


@target.command(name="show")
@click.argument("target_id")
def target_show(target_id: str) -> None:
    """Show details for a specific target."""
    repo = TargetRepository()
    t = repo.get(target_id)
    repo.close()

    if t is None:
        console.print(f"[red]Target not found:[/] {target_id}")
        return

    console.print(
        Panel.fit(
            f"[bold]Name:[/] {t['name']}\n"
            f"[bold]ID:[/] {t['id']}\n"
            f"[bold]Environment:[/] {t['environment']}\n"
            f"[bold]Description:[/] {t['description'] or 'N/A'}\n"
            f"[bold]MCP URLs:[/] {', '.join(t.get('mcp_server_urls', [])) or 'None'}\n"
            f"[bold]Agent Endpoint:[/] {t.get('agent_endpoint') or 'None'}\n"
            f"[bold]Max RPM:[/] {t['max_requests_per_minute']}\n"
            f"[bold]Non-destructive:[/] {t['non_destructive']}\n"
            f"[bold]Client:[/] {t.get('client_name') or 'N/A'}\n"
            f"[bold]Created:[/] {t['created_at']}",
            title="Target Details",
        )
    )


@target.command(name="delete")
@click.argument("target_id")
@click.confirmation_option(prompt="Are you sure you want to delete this target?")
def target_delete(target_id: str) -> None:
    """Delete a target (soft delete)."""
    repo = TargetRepository()
    if repo.delete(target_id):
        console.print(f"[green]Target deleted:[/] {target_id}")
    else:
        console.print(f"[red]Target not found:[/] {target_id}")
    repo.close()


# ---------------------------------------------------------------------------
# Scan history commands
# ---------------------------------------------------------------------------


@main.group(name="history")
def history_group() -> None:
    """View scan history and past results."""
    init_db()


@history_group.command(name="list")
@click.option("--limit", default=20, help="Max results to show")
@click.option("--target-id", help="Filter by target ID")
@click.option("--status", "scan_status", help="Filter by status")
def history_list(limit: int, target_id: str | None, scan_status: str | None) -> None:
    """List past scans."""
    repo = ScanRepository()
    scans = repo.list_scans(limit=limit, target_id=target_id, status=scan_status)
    repo.close()

    if not scans:
        console.print("[dim]No scans found. Run 'argus scan' to start one.[/]")
        return

    table = Table(title=f"Scan History ({len(scans)} results)")
    table.add_column("Scan ID", style="dim", max_width=10)
    table.add_column("Target", style="cyan")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Validated", justify="right", style="green")
    table.add_column("Paths", justify="right", style="magenta")
    table.add_column("Duration")
    table.add_column("Date")

    for s in scans:
        status_style = "green" if s["status"] == "completed" else "red" if s["status"] == "failed" else "yellow"
        table.add_row(
            s["id"][:8] + "...",
            s.get("target_name", "N/A"),
            f"[{status_style}]{s['status']}[/{status_style}]",
            str(s.get("total_findings", 0)),
            str(s.get("validated_findings", 0)),
            str(s.get("compound_paths_count", 0)),
            f"{s.get('duration_seconds', 0) or 0:.1f}s",
            str(s.get("started_at", ""))[:19],
        )
    console.print(table)


@history_group.command(name="show")
@click.argument("scan_id")
def history_show(scan_id: str) -> None:
    """Show details for a specific scan."""
    repo = ScanRepository()
    scan = repo.get_scan(scan_id)
    if scan is None:
        console.print(f"[red]Scan not found:[/] {scan_id}")
        repo.close()
        return

    findings = repo.get_scan_findings(scan_id)
    agents = repo.get_scan_agents(scan_id)
    repo.close()

    console.print(
        Panel.fit(
            f"[bold]Scan ID:[/] {scan['id']}\n"
            f"[bold]Target:[/] {scan.get('target_name', 'N/A')}\n"
            f"[bold]Status:[/] {scan['status']}\n"
            f"[bold]Started:[/] {scan.get('started_at', 'N/A')}\n"
            f"[bold]Duration:[/] {scan.get('duration_seconds', 0) or 0:.1f}s\n"
            f"[bold]Agents:[/] {scan.get('agents_deployed', 0)} deployed, {scan.get('agents_completed', 0)} completed\n"
            f"[bold]Findings:[/] {scan.get('total_findings', 0)} total, {scan.get('validated_findings', 0)} validated\n"
            f"[bold]Compound Paths:[/] {scan.get('compound_paths_count', 0)}\n"
            f"[bold]Initiated By:[/] {scan.get('initiated_by', 'N/A')}",
            title="Scan Details",
        )
    )

    if agents:
        agent_table = Table(title="Agent Results")
        agent_table.add_column("Agent", style="cyan")
        agent_table.add_column("Status")
        agent_table.add_column("Findings", justify="right")
        agent_table.add_column("Validated", justify="right")
        agent_table.add_column("Duration")
        for a in agents:
            agent_table.add_row(
                a["agent_type"],
                a["status"],
                str(a.get("findings_count", 0)),
                str(a.get("validated_count", 0)),
                f"{a.get('duration_seconds', 0) or 0:.1f}s",
            )
        console.print(agent_table)

    if findings:
        finding_table = Table(title=f"Findings ({len(findings)})")
        finding_table.add_column("Severity", style="bold")
        finding_table.add_column("Title")
        finding_table.add_column("Agent")
        finding_table.add_column("Status")
        for f_item in findings[:20]:  # Show first 20
            sev = f_item.get("severity", "info")
            sev_style = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "dim")
            finding_table.add_row(
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                (f_item.get("title", "") or "")[:60],
                f_item.get("agent_type", ""),
                f_item.get("status", ""),
            )
        if len(findings) > 20:
            console.print(f"[dim]... and {len(findings) - 20} more findings[/]")
        console.print(finding_table)


@history_group.command(name="report")
@click.argument("scan_id")
@click.option("--output", "-o", required=True, help="Output file path for HTML report")
def history_report(scan_id: str, output: str) -> None:
    """Export an HTML report for a past scan."""
    output_path = _validate_output_path(output)

    repo = ScanRepository()
    scan = repo.get_scan(scan_id)
    if scan is None:
        console.print(f"[red]Scan not found:[/] {scan_id}")
        repo.close()
        return

    html = scan.get("report_html")
    if not html:
        console.print("[yellow]No HTML report stored for this scan.[/]")
        repo.close()
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    repo.close()
    console.print(f"[green]HTML report written to {output_path}[/]")


# ---------------------------------------------------------------------------
# Auth / API key commands
# ---------------------------------------------------------------------------


@main.group()
def auth() -> None:
    """Manage API keys and authentication."""
    init_db()


@auth.command(name="create-key")
@click.argument("name")
@click.option("--role", default="viewer", type=click.Choice(["admin", "operator", "viewer"]), help="Role for the key")
def auth_create_key(name: str, role: str) -> None:
    """Create a new API key."""
    repo = APIKeyRepository()
    key = repo.create(name=name, role=role)
    repo.close()

    console.print(f"[green]API key created:[/] {key['name']} (role={key['role']})")
    console.print("\n[bold yellow]Key (store securely — shown once):[/]")
    console.print(f"  {key['raw_key']}")
    console.print(f"\n[dim]Prefix: {key['key_prefix']}[/]")


@auth.command(name="list-keys")
def auth_list_keys() -> None:
    """List all API keys."""
    repo = APIKeyRepository()
    keys = repo.list_all()
    repo.close()

    if not keys:
        console.print("[dim]No API keys created. Use 'argus auth create-key' to create one.[/]")
        return

    table = Table(title="API Keys")
    table.add_column("ID", style="dim", max_width=10)
    table.add_column("Name", style="cyan")
    table.add_column("Role", style="yellow")
    table.add_column("Prefix")
    table.add_column("Active", justify="center")
    table.add_column("Last Used")
    for k in keys:
        table.add_row(
            k["id"][:8] + "...",
            k["name"],
            k["role"],
            k["key_prefix"],
            "[green]Yes[/]" if k["is_active"] else "[red]No[/]",
            str(k.get("last_used_at") or "Never")[:19],
        )
    console.print(table)


@auth.command(name="revoke-key")
@click.argument("key_id")
@click.confirmation_option(prompt="Are you sure you want to revoke this key?")
def auth_revoke_key(key_id: str) -> None:
    """Revoke an API key."""
    repo = APIKeyRepository()
    if repo.revoke(key_id):
        console.print(f"[green]Key revoked:[/] {key_id}")
    else:
        console.print(f"[red]Key not found:[/] {key_id}")
    repo.close()


# ---------------------------------------------------------------------------
# Database status command
# ---------------------------------------------------------------------------


@main.command(name="db-status")
def db_status() -> None:
    """Show database status and table counts."""
    init_db()
    repo = ScanRepository()
    target_repo = TargetRepository()

    scan_count = repo.get_scan_count()
    targets = target_repo.list_all()
    target_repo.close()
    repo.close()

    console.print(
        Panel.fit(
            f"[bold]Targets:[/] {len(targets)}\n[bold]Scans:[/] {scan_count}\n[bold]Database:[/] SQLite (WAL mode)",
            title="Database Status",
        )
    )


# ---------------------------------------------------------------------------
# Test target commands
# ---------------------------------------------------------------------------


@main.group(name="test-target")
def test_target() -> None:
    """Manage the ARGUS mock vulnerable AI target for testing."""


@test_target.command(name="start")
@click.option("--host", default="127.0.0.1", help="Host to bind")
@click.option("--port", default=9999, help="Port to bind")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def test_target_start(host: str, port: int, reload: bool) -> None:
    """Start the mock vulnerable AI target.

    Launches a FastAPI server that simulates a vulnerable AI agent
    with intentional security flaws for each ARGUS attack agent to
    find. Use this for local development and testing.

    Then run a scan against it:
        ARGUS_WEB_ALLOW_PRIVATE=1 argus scan mock-target \\
            --agent-endpoint http://localhost:9999/chat
    """
    import uvicorn

    console.print(BANNER, style="bold red")
    console.print("\n[bold yellow]ARGUS Test Target[/] (mock vulnerable AI agent)")
    console.print(f"Starting on [cyan]http://{host}:{port}[/]")
    console.print("\n[bold red]WARNING:[/] This is an intentionally vulnerable target.")
    console.print("[bold red]DO NOT expose to the internet.[/]\n")
    console.print("[dim]To scan against it:[/]")
    console.print(
        f"[dim]  ARGUS_WEB_ALLOW_PRIVATE=1 argus scan mock-target --agent-endpoint http://{host}:{port}/chat[/]\n"
    )

    uvicorn.run(
        "argus.test_harness.mock_target:create_mock_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
        log_level="info",
    )


@test_target.command(name="status")
@click.option("--port", default=9999, help="Port to check")
def test_target_status(port: int) -> None:
    """Check if the mock target is running."""
    import httpx

    try:
        resp = httpx.get(f"http://127.0.0.1:{port}/health", timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"[green]Mock target is running[/] on port {port}")
            console.print(f"[dim]Service: {data.get('service', 'unknown')}[/]")
        else:
            console.print(f"[yellow]Mock target responded with status {resp.status_code}[/]")
    except httpx.HTTPError:
        console.print(f"[red]Mock target is not running[/] on port {port}")
        console.print("[dim]Start it with: argus test-target start[/]")


if __name__ == "__main__":
    main()
