"""ARGUS-ENGINE command-line interface.

Three output channels (per the adversary-grade CLI spec):

* **stdout (JSONL):** every finding emitted as a single-line JSON object.
  Pipeable into ``grep IRREFUTABLE``, ``jq``, downstream tools.
* **stderr (Inner Monologue):** supervisor reasoning, phase transitions,
  refusal-KB hits, progress lines. Kept separate from data.
* **TUI (Cockpit):** ``rich.live`` dashboard with three panes — Battle Feed
  (variant fires), Strategy Trace (supervisor thoughts), Lethality Meter
  (per-class success rates + counters). On IRREFUTABLE, breaks the scroll
  with a ``pyfiglet`` BREACH banner and bell.

Subcommands::

    argus-engine generate --layer 1 --out corpus.jsonl
    argus-engine recon --mcp http://target/mcp
    argus-engine discover --scope scope.txt --out surface_map.json
    argus-engine engage --target ... --transport openai --tui
    argus-engine engage --target ... --transport openai --json   # headless pipe
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import json
import logging
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import click

from .core.plugins import PLUGIN_GROUP, autoload_plugins
from .core.registry import all_classes, classes_in_layer
from .core.scaffold import LAYER_SLUGS, ScaffoldError, validate_spec, write_scaffold
from .reporting import parse_jsonl, render_html, render_markdown
from .runtime.dispatch import auto_dispatch


def _sanitize(value: Any, _seen: set[int] | None = None, _depth: int = 0) -> Any:
    """JSON-safe traversal that breaks cycles introduced by schema mutators."""
    if _depth > 64:
        return "<truncated:depth>"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if _seen is None:
        _seen = set()
    if isinstance(value, (list, tuple, dict)):
        ident = id(value)
        if ident in _seen:
            return "<cycle>"
        _seen = _seen | {ident}
    if isinstance(value, dict):
        return {str(k): _sanitize(v, _seen, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v, _seen, _depth + 1) for v in value]
    return str(value)


logger = logging.getLogger("argus.engine.cli")


# ---------------------------------------------------------------------------
# Heat-map / styling
# ---------------------------------------------------------------------------

_STYLE = {
    "noise": "grey50",
    "drift": "yellow",
    "arc": "bold magenta",
    "lethal": "white on red blink",
    "thought": "italic cyan",
    "phase": "bold cyan",
    "refusal": "dim",
}


def _style_for(event: dict[str, Any]) -> str:
    if event.get("type") == "finding":
        conf = event.get("confidence", "")
        if conf == "IRREFUTABLE":
            return _STYLE["lethal"]
        if conf == "HIGH":
            return _STYLE["arc"]
        return _STYLE["drift"]
    if event.get("type") == "fire":
        score = float(event.get("lethality") or 0)
        if score >= 0.8:
            return _STYLE["lethal"]
        if score >= 0.5:
            return _STYLE["arc"]
        if score >= 0.2:
            return _STYLE["drift"]
        return _STYLE["noise"]
    if event.get("type") == "thought":
        return _STYLE["thought"]
    if event.get("type") == "phase":
        return _STYLE["phase"]
    if event.get("type") == "refusal":
        return _STYLE["refusal"]
    return ""


# ---------------------------------------------------------------------------
# Output sinks
# ---------------------------------------------------------------------------


def _default_run_path(seed: int) -> Path:
    """Default forensic-persistence path: ``~/.argus-engine/runs/<UTC>-<seed>.jsonl``.

    Every engagement is auto-persisted here so finding histories survive
    TUI refresh, terminal scrollback truncation, and accidental loss of
    a piped ``tee`` redirect. Override with ``--out PATH`` or disable
    with ``--no-persist``.
    """
    stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    base = Path.home() / ".argus-engine" / "runs"
    return base / f"{stamp}-seed{seed}.jsonl"


class _PersistingSink:
    """Wraps an inner sink and tees every event line to a JSONL file.

    Engagements emit ``finding`` / ``thought`` / ``phase`` / ``refusal``
    / ``mutation`` events through the supervisor. The inner sink (TUI or
    JSONL) handles live display; this wrapper records the full event
    stream to disk so a run is always recoverable post-hoc.
    """

    def __init__(self, inner: Any, path: Path) -> None:
        self._inner = inner
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        # Truncate on open so reruns of the same path don't append stale data.
        self._fh = path.open("w", encoding="utf-8")

    @property
    def path(self) -> Path:
        return self._path

    @property
    def findings(self) -> list[dict[str, Any]]:
        return getattr(self._inner, "findings", [])

    def __call__(self, event: dict[str, Any]) -> None:
        try:
            self._fh.write(json.dumps(event, default=str) + "\n")
            self._fh.flush()
        except (OSError, ValueError):
            # Persistence is best-effort — never break the live engagement
            # because of disk-full / handle-closed issues.
            pass
        self._inner(event)

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self._fh.close()
        if hasattr(self._inner, "stop"):
            self._inner.stop()


class _JsonlSink:
    """Headless sink: findings → stdout JSONL, monologue → stderr."""

    def __init__(self) -> None:
        self.findings: list[dict[str, Any]] = []

    def __call__(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "finding":
            self.findings.append(event)
            sys.stdout.write(json.dumps(event, default=str) + "\n")
            sys.stdout.flush()
            if event.get("confidence") == "IRREFUTABLE":
                sys.stderr.write("\a")  # terminal bell
                sys.stderr.flush()
        elif kind == "thought":
            sys.stderr.write(f"<thought> {event.get('text', '')}\n")
            sys.stderr.flush()
        elif kind == "phase":
            sys.stderr.write(f"[phase] {event.get('phase')} {event.get('classes', '')}\n")
            sys.stderr.flush()
        elif kind == "refusal":
            sys.stderr.write(f"[refusal] sig={event.get('signature')} kb={event.get('kb_size')}\n")
            sys.stderr.flush()
        elif kind == "mutation":
            sys.stderr.write(
                f"[mutation] gen={event.get('generation')} "
                f"survivors={event.get('survivor_count')} "
                f"best={event.get('best_score'):.2f}\n"
            )
            sys.stderr.flush()


class _TuiSink:
    """Cockpit sink: rich.live dashboard with three panes + breach banner."""

    def __init__(self, *, max_variants: int = 0) -> None:
        from collections import deque

        from rich.console import Console
        from rich.live import Live

        self._console = Console(stderr=True, force_terminal=True)
        self._stdout_console = Console()
        self._battle: list[tuple[str, str]] = []
        self._monologue: list[str] = []
        self._fires_per_class: Counter[str] = Counter()
        self._lands_per_class: Counter[str] = Counter()
        self._fired = 0
        self._landed = 0
        self._phase = "init"
        self._tools: list[str] = []
        self.findings: list[dict[str, Any]] = []
        self._max_variants = max(int(max_variants), 0)
        self._start_time = time.monotonic()
        # Rolling 30-second window of (timestamp, fired_at_ts) for rate.
        self._rate_samples: deque[tuple[float, int]] = deque(maxlen=240)
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=8,
            transient=False,
        )
        self._live.start()

    @staticmethod
    def _fmt_hms(seconds: float) -> str:
        seconds = max(int(seconds), 0)
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _current_rate(self) -> float:
        """Fires per second over the last 30s rolling window."""
        if len(self._rate_samples) < 2:
            return 0.0
        now, latest = self._rate_samples[-1]
        cutoff = now - 30.0
        # Walk forward until inside the window.
        for ts, fired_then in self._rate_samples:
            if ts >= cutoff:
                dt = now - ts
                df = latest - fired_then
                return df / dt if dt > 0 else 0.0
        return 0.0

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self._live.stop()

    def _render(self):
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        layout = Layout()
        layout.split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["left"].split_column(
            Layout(name="battle", ratio=3),
            Layout(name="strategy", ratio=2),
        )

        battle = Text()
        for style, line in self._battle[-30:]:
            battle.append(line + "\n", style=style or "")
        layout["left"]["battle"].update(Panel(battle, title="[bold red]BATTLE FEED", border_style="red"))

        mono = Text()
        for line in self._monologue[-20:]:
            mono.append(line + "\n", style=_STYLE["thought"])
        layout["left"]["strategy"].update(Panel(mono, title="[bold cyan]STRATEGY TRACE", border_style="cyan"))

        meter = Table.grid(padding=(0, 1))
        meter.add_column(style="bold")
        meter.add_column()
        meter.add_row("phase", f"[bold cyan]{self._phase}")

        elapsed = time.monotonic() - self._start_time
        rate = self._current_rate()
        meter.add_row("elapsed", self._fmt_hms(elapsed))
        if rate > 0:
            rate_color = "white"
            # If rate has dropped to <50% of the all-time average, flag in red
            avg = self._fired / elapsed if elapsed > 0 else 0.0
            if avg > 0 and rate < avg * 0.5:
                rate_color = "red"
            meter.add_row("rate", f"[{rate_color}]{rate:.2f} fires/sec")
        else:
            meter.add_row("rate", "—")
        if self._max_variants and rate > 0 and self._fired < self._max_variants:
            remaining = (self._max_variants - self._fired) / rate
            meter.add_row("ETA", self._fmt_hms(remaining))

        meter.add_row("fired", f"{self._fired} / {self._max_variants or '∞'}")
        meter.add_row("landed", f"[bold green]{self._landed}")
        if self._tools:
            meter.add_row("tools", ", ".join(self._tools[:8]))
        meter.add_row("", "")
        meter.add_row("[bold]class", "[bold]fired / landed")
        for cls, fired in self._fires_per_class.most_common(10):
            landed = self._lands_per_class.get(cls, 0)
            color = "green" if landed else "white"
            meter.add_row(cls, f"[{color}]{fired} / {landed}")
        layout["right"].update(Panel(meter, title="[bold yellow]LETHALITY METER", border_style="yellow"))
        return layout

    def _push_battle(self, line: str, style: str) -> None:
        self._battle.append((style, line))

    def _breach_banner(self, event: dict[str, Any]) -> None:
        try:
            import pyfiglet

            banner = pyfiglet.figlet_format("BREACH", font="slant")
        except Exception:  # noqa: BLE001
            banner = "*** BREACH ***"
        self._live.stop()
        self._console.print(f"[bold white on red blink]{banner}[/]")
        self._console.print(
            f"[bold red]🚨 IRREFUTABLE  class={event.get('attack_class')}  "
            f"variant={event.get('variant_id')}  lethality={event.get('lethality'):.2f}[/]"
        )
        self._console.print(f"[bold red]   evidence={event.get('evidence')}[/]")
        self._console.bell()
        self._live.start()

    def __call__(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "phase":
            self._phase = event.get("phase", "?")
            if event.get("phase") == "recon":
                self._tools = list(event.get("tool_names") or [])
            classes = event.get("classes")
            if classes:
                self._monologue.append(f"[phase] {self._phase} → {classes}")
        elif kind == "thought":
            self._monologue.append(event.get("text", ""))
        elif kind == "refusal":
            self._monologue.append(f"[refusal] sig={event.get('signature')} kb={event.get('kb_size')}")
        elif kind == "mutation":
            self._monologue.append(
                f"[mutation] gen={event.get('generation')} "
                f"survivors={event.get('survivor_count')} best={event.get('best_score'):.2f}"
            )
        elif kind == "fire":
            self._fired += 1
            self._rate_samples.append((time.monotonic(), self._fired))
            cls = event.get("attack_class", "?")
            self._fires_per_class[cls] += 1
            score = float(event.get("lethality") or 0)
            line = f"[FIRE] {cls} {event.get('variant_id')[:10]} score={score:.2f} verdict={event.get('verdict')}"
            self._push_battle(line, _style_for(event))
        elif kind == "finding":
            self._landed += 1
            cls = event.get("attack_class", "?")
            self._lands_per_class[cls] += 1
            self.findings.append(event)
            sys.stdout.write(json.dumps(event, default=str) + "\n")
            sys.stdout.flush()
            line = (
                f"[LAND] {cls} {event.get('variant_id')[:10]} "
                f"score={event.get('lethality'):.2f} "
                f"conf={event.get('confidence')}"
            )
            self._push_battle(line, _style_for(event))
            if event.get("confidence") == "IRREFUTABLE":
                self._breach_banner(event)
        elif kind == "done":
            self._monologue.append(
                f"[done] fired={event.get('fired')} findings={event.get('findings')} dur={event.get('duration'):.1f}s"
            )
        with contextlib.suppress(Exception):
            self._live.update(self._render())


def _final_panel(findings: list[dict[str, Any]], fired: int, duration: float) -> None:
    """Render the Lethality Summary panel."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console(stderr=True)
    table = Table(
        show_header=True,
        header_style="bold gold1",
        border_style="gold1",
        title_style="bold white on red",
    )
    table.add_column("variant_id", style="white")
    table.add_column("attack_class", style="white")
    table.add_column("conf", style="bold white")
    table.add_column("score", style="bold white")
    table.add_column("evidence", style="white", overflow="fold")
    irrefutable = [f for f in findings if f.get("confidence") == "IRREFUTABLE"]
    for f in irrefutable:
        table.add_row(
            (f.get("variant_id") or "")[:12],
            f.get("attack_class") or "",
            f.get("confidence") or "",
            f"{f.get('lethality'):.2f}",
            json.dumps(f.get("evidence") or {})[:80],
        )
    title = f"LETHAL PATHS  ({len(irrefutable)} of {len(findings)} findings, {fired} fired, {duration:.1f}s)"
    console.print(
        Panel(
            table if irrefutable else "[dim]no IRREFUTABLE findings this run[/]",
            title=f"[bold white]{title}",
            border_style="gold1",
            style="on dark_red",
        )
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.group()
@click.option("-v", "--verbose", count=True, help="Increase log verbosity (-v, -vv).")
@click.option(
    "--no-plugins",
    is_flag=True,
    default=False,
    help=(
        "Skip third-party plugin auto-discovery. Built-in classes still "
        "register normally. Use this when a misbehaving downstream plugin "
        "is blocking the CLI."
    ),
)
@click.pass_context
def main(ctx: click.Context, verbose: int, no_plugins: bool) -> None:
    """ARGUS-ENGINE — autonomous structural exploit framework."""
    level = logging.WARNING if verbose == 0 else logging.INFO if verbose == 1 else logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s")
    # ensure layers are imported (registers all classes)
    import argus.engine  # noqa: F401

    ctx.ensure_object(dict)
    if no_plugins:
        ctx.obj["plugin_report"] = None
        return
    report = autoload_plugins()
    ctx.obj["plugin_report"] = report
    log = logging.getLogger("argus.engine.plugins")
    for class_id in report.registered:
        log.info("loaded plugin class %s", class_id)
    for failure in report.failures:
        # Rule #9 — never silent. Surface broken plugins on stderr at WARNING
        # so the user notices even at default verbosity.
        log.warning(
            "plugin %s failed to load (%s): %s",
            failure.entry_point,
            failure.error_type,
            failure.error_message,
        )


@main.command("list-classes")
@click.option(
    "--layer",
    type=click.Choice(
        [
            "all",
            "layer1_tool_poisoning",
            "layer2_contextual_injection",
            "layer3_cognitive",
            "layer4_extraction",
            "layer5_orchestration",
        ]
    ),
    default="all",
)
def list_classes(layer: str) -> None:
    """List every registered attack class with its variant target."""
    iterator = all_classes() if layer == "all" else classes_in_layer(layer)  # type: ignore[arg-type]
    total = 0
    for cls in iterator:
        click.echo(f"{cls.layer:34s}  {cls.class_id:30s} target={cls.target_variants:5d}  {cls.title}")
        total += cls.target_variants
    click.echo(f"TOTAL target variants: {total}")


@main.command()
@click.option("--layer", required=True, help="Layer id, e.g. layer1_tool_poisoning")
@click.option("--out", required=True, type=click.Path(dir_okay=False, writable=True))
@click.option("--seed", type=int, default=42)
@click.option("--class", "class_filter", default=None, help="Restrict to a single class id.")
def generate(layer: str, out: str, seed: int, class_filter: str | None) -> None:
    """Emit deterministic variants for ``layer`` as JSONL."""
    written = 0
    with open(out, "w", encoding="utf-8") as fh:
        for cls in classes_in_layer(layer):  # type: ignore[arg-type]
            if class_filter and cls.class_id != class_filter:
                continue
            for variant in cls.factory(seed_value=seed).generate():
                row = {
                    "variant_id": variant.variant_id,
                    "seed_id": variant.seed_id,
                    "attack_class": variant.attack_class,
                    "layer": variant.layer,
                    "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "parameters_schema": _sanitize(t.parameters_schema),
                        }
                        for t in variant.tools
                    ],
                    "resources": [
                        {
                            "uri": r.uri,
                            "mime_type": r.mime_type,
                            "description": r.description,
                        }
                        for r in variant.resources
                    ],
                    "rag_corpus": list(variant.rag_corpus),
                    "canary_primary": (variant.canaries.primary if variant.canaries else None),
                    "matcher_ids": list(variant.matcher_ids),
                    "mutator_chain": list(variant.mutator_chain),
                }
                fh.write(json.dumps(row, default=str) + "\n")
                written += 1
    click.echo(f"wrote {written} variants to {out}", err=True)


@main.command()
@click.option("--mcp", "mcp_url", required=True, help="MCP endpoint URL")
@click.option("--out", default=None, type=click.Path(dir_okay=False, writable=True))
def recon(mcp_url: str, out: str | None) -> None:
    """Tier-A introspection — enumerate tools/resources/prompts via MCP."""

    async def _go() -> None:
        from .recon.mcp_introspect import McpIntrospector

        manifest = await McpIntrospector(mcp_url).introspect()
        payload = {
            "endpoint": mcp_url,
            "tools": [t.__dict__ for t in manifest.tools],
            "resources": [r.__dict__ for r in manifest.resources],
            "prompts": [p.__dict__ for p in manifest.prompts],
            "high_value_chains": list(manifest.high_value_chains),
        }
        text = json.dumps(payload, default=str, indent=2)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            click.echo(f"wrote manifest to {out}", err=True)
        else:
            click.echo(text)

    asyncio.run(_go())


_VALID_SOURCES = ("crt.sh", "hackertarget", "wayback")


@main.command()
@click.option(
    "--scope",
    "scope_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help=(
        "Path to a scope file (FQDN / wildcard / CIDR allowlist, one per "
        "line). Mandatory — passive recon will not run without explicit "
        "operator authorisation."
    ),
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write JSON surface map to this path. Defaults to stdout.",
)
@click.option(
    "--source",
    "sources",
    type=click.Choice(_VALID_SOURCES),
    multiple=True,
    default=_VALID_SOURCES,
    show_default=True,
    help="Restrict to a subset of recon sources. Repeatable.",
)
@click.option(
    "--active/--passive",
    default=False,
    help=(
        "Active probing sends one HEAD + one path probe per in-scope host "
        "to fingerprint the AI surface. Default is passive — no packets to "
        "the targets themselves; only third-party indexes are queried."
    ),
)
@click.option(
    "--concurrency",
    type=int,
    default=8,
    show_default=True,
    help="Max concurrent active probes (only used with --active).",
)
def discover(
    scope_path: Path,
    out_path: Path | None,
    sources: tuple[str, ...],
    active: bool,
    concurrency: int,
) -> None:
    """Passive surface mapping — discover AI endpoints across a scoped estate.

    Walks Certificate Transparency (crt.sh), passive DNS (HackerTarget)
    and the Wayback Machine to enumerate every host ever observed under
    the operator's authorised zones, filters every result through the
    scope allowlist, fingerprints each host as chat / agent / mcp / rag /
    tool / api / unknown, and emits a ranked attack-surface map. Hosts
    outside scope are recorded for audit but never probed.
    """
    from .recon.passive import discover as run_discover
    from .recon.scope import load as load_scope

    try:
        scope = load_scope(scope_path)
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    surface_map = asyncio.run(
        run_discover(
            scope,
            sources=sources or _VALID_SOURCES,
            active=active,
            concurrency=concurrency,
        )
    )

    payload = surface_map.to_json()
    text = json.dumps(payload, indent=2, default=str)
    if out_path is not None:
        out_path.write_text(text + "\n", encoding="utf-8")
        click.echo(
            f"discovered {len(surface_map.hosts)} in-scope host(s); "
            f"{len(surface_map.out_of_scope)} filtered out of scope; "
            f"surface map -> {out_path}",
            err=True,
        )
    else:
        click.echo(text)
    if surface_map.source_errors:
        click.echo(
            f"note: {len(surface_map.source_errors)} source error(s) (see source_errors[] in output)",
            err=True,
        )


@main.command()
@click.option("--target", required=True, help="Target endpoint URL or model id")
@click.option(
    "--transport",
    type=click.Choice(["auto", "openai", "anthropic", "ollama", "argt"]),
    default="auto",
    show_default=True,
    help=(
        "Transport to fire variants over. ``auto`` (default) inspects the "
        "target string and picks ``argt`` for URLs, ``anthropic`` for "
        "``claude*`` model ids, ``ollama`` for open-weights tags, and "
        "``openai`` for everything else (gpt-*, o*)."
    ),
)
@click.option(
    "--session-mode",
    type=click.Choice(["single-call", "multi-call"]),
    default="single-call",
    help=(
        "ARGT transport only. ``multi-call`` issues one POST per "
        "user-role turn and threads server state via auto-detected "
        "cookie / X-Session-Id / conversation_id. Required for c04 / "
        "c08 / c09 (session_state-gated classes). Default "
        "``single-call`` flattens variant.messages into a single "
        "POST and is byte-equivalent to the pre-PR-#5 behaviour."
    ),
)
@click.option(
    "--layer",
    default="layer1_tool_poisoning",
    help="Which layer's attack classes to engage with",
)
@click.option("--seed", type=int, default=42)
@click.option("--max-variants", type=int, default=2000, help="Hard cap on total fires.")
@click.option("--max-per-class", type=int, default=200)
@click.option("--max-generations", type=int, default=5)
@click.option(
    "--concurrency",
    type=int,
    default=16,
    help="Max in-flight fires per class. Higher = faster, but watch target rate limits.",
)
@click.option(
    "--early-stop-after",
    type=int,
    default=30,
    help=("Per-class: exit early if this many fires produce zero drift and the refusal-KB has stagnated. 0 disables."),
)
@click.option(
    "--kb-short-circuit",
    type=float,
    default=0.55,
    help=(
        "Skip-fire variants whose payload overlaps known-refusal "
        "vocabulary above this threshold (0.0-1.0). 1.0 disables."
    ),
)
@click.option("--tui/--no-tui", default=True, help="Legacy 3-pane cockpit (default; superseded by --hud).")
@click.option(
    "--hud",
    is_flag=True,
    default=False,
    help=(
        "Phase R cockpit: 4-pane Rich layout with class heatmap, "
        "signal-strength bars, fire ticker, and landings feed. "
        "Implies --no-tui."
    ),
)
@click.option(
    "--narrate",
    is_flag=True,
    default=False,
    help=(
        "Emit plain-English event narration to stderr. Composes with "
        "--hud, --json, or runs standalone. Useful for demo recordings "
        "and non-engineer audiences."
    ),
)
@click.option(
    "--demo-pace",
    "demo_pace",
    type=click.FloatRange(min=0.0, max=10.0),
    default=0.0,
    show_default=True,
    help=(
        "Per-event sleep in seconds. Slows the live feed so screen "
        "recordings (LinkedIn / Discord) are readable. 0 disables."
    ),
)
@click.option("--json", "json_only", is_flag=True, help="Headless JSONL pipe (disables TUI / HUD).")
@click.option("--api-key", default=None, help="Override transport API key.")
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help=(
        "Forensic JSONL output path. Defaults to "
        "~/.argus-engine/runs/<UTC>-seed<seed>.jsonl. Use --no-persist "
        "to disable disk writes entirely (CI / smoke runs)."
    ),
)
@click.option(
    "--no-persist",
    is_flag=True,
    default=False,
    help="Disable forensic JSONL persistence (TUI / stdout only).",
)
@click.option(
    "--html-out",
    "html_out",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help=(
        "After the engagement ends, render an offline single-file HTML "
        "report from the forensic JSONL to this path. Implies --out is "
        "persisted."
    ),
)
@click.option(
    "--md-out",
    "md_out",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help=(
        "After the engagement ends, render a CI-friendly Markdown "
        "summary from the forensic JSONL to this path. Implies --out is "
        "persisted."
    ),
)
def engage(
    target: str,
    transport: str,
    session_mode: str,
    layer: str,
    seed: int,
    max_variants: int,
    max_per_class: int,
    max_generations: int,
    concurrency: int,
    early_stop_after: int,
    kb_short_circuit: float,
    tui: bool,
    hud: bool,
    narrate: bool,
    demo_pace: float,
    json_only: bool,
    api_key: str | None,
    out_path: Path | None,
    no_persist: bool,
    html_out: Path | None,
    md_out: Path | None,
) -> None:
    """Run the autonomous SSAE engagement loop against ``target``."""
    from .recon.mcp_introspect import TargetManifest
    from .runtime.reward import ShadowModel
    from .runtime.supervisor import Supervisor

    resolved_transport = transport
    if transport == "auto":
        decision = auto_dispatch(target)
        resolved_transport = decision.transport
        sys.stderr.write(
            f"[dispatch] {decision.reason} -> transport={decision.transport} mcp_capable={decision.mcp_capable}\n"
        )
        sys.stderr.flush()

    if session_mode != "single-call" and resolved_transport != "argt":
        raise click.UsageError(
            f"--session-mode={session_mode!r} is only valid with --transport=argt; "
            f"resolved transport is {resolved_transport!r}. Other transports always use "
            "the provider's native chat completion (single call)."
        )
    if (html_out is not None or md_out is not None) and no_persist:
        raise click.UsageError(
            "--html-out / --md-out require a persisted forensic JSONL; remove --no-persist or drop the report flags."
        )
    transport_obj = _build_transport(resolved_transport, target, api_key, session_mode=session_mode)

    # NOTE: real recon is performed when --transport mcp is added; for raw
    # chat targets we synthesize an empty manifest — strategy navigator runs
    # on the registered attack classes regardless.
    manifest = TargetManifest(
        endpoint=target,
        framework="unknown",
        tools=(),
        resources=(),
        prompts=(),
        high_value_chains=(),
    )
    shadow = ShadowModel(
        authorized_tools=frozenset({t.name for t in manifest.tools}),
        legal_transitions=frozenset(),
        forbidden_states=frozenset({"system_prompt_leak", "secret_exfil"}),
        forbidden_content_patterns=(),
        expected_refusal_rate=0.6,
    )

    if json_only:
        tui = False
        hud = False

    inner_sink: Any
    if hud and sys.stderr.isatty():
        from .reporting.hud import HudSink

        inner_sink = HudSink(demo_pace=demo_pace if not narrate else 0.0)
    elif tui and sys.stderr.isatty():
        inner_sink = _TuiSink(max_variants=max_variants)
    else:
        inner_sink = _JsonlSink()

    if narrate:
        from .reporting.hud import HudSink
        from .reporting.narrate import NarrateSink

        # When chained with a HUD, the HUD already renders Rich banner
        # panels — suppress duplicate banner lines in the narrator. The
        # legacy _TuiSink and the JSONL sink don't emit banners, so we
        # keep them on for those cases.
        emit_banners = not isinstance(inner_sink, HudSink)
        inner_sink = NarrateSink(
            stream=sys.stderr,
            demo_pace=demo_pace,
            emit_banners=emit_banners,
            inner=inner_sink,
        )

    sink: Any = inner_sink
    persisted_path: Path | None = None
    if not no_persist:
        persisted_path = out_path or _default_run_path(seed)
        sink = _PersistingSink(inner_sink, persisted_path)
        sys.stderr.write(f"[persist] forensic JSONL → {persisted_path}\n")
        sys.stderr.flush()

    supervisor = Supervisor(
        transport=transport_obj,
        manifest=manifest,
        shadow=shadow,
        layer=layer,  # type: ignore[arg-type]
        seed_value=seed,
        max_variants_per_class=max_per_class,
        max_total_variants=max_variants,
        max_generations=max_generations,
        concurrency=concurrency,
        early_stop_after=early_stop_after,
        kb_short_circuit_threshold=kb_short_circuit,
        on_event=sink,
    )

    try:
        report = asyncio.run(supervisor.run())
    finally:
        if hasattr(sink, "stop"):
            sink.stop()

    _final_panel(
        list(getattr(sink, "findings", [])),
        report.total_variants_fired,
        report.duration_seconds,
    )
    if persisted_path is not None:
        sys.stderr.write(f"[persist] run saved to {persisted_path}\n")
        sys.stderr.flush()
        if html_out is not None or md_out is not None:
            _emit_reports(persisted_path, html_out, md_out)


def _emit_reports(jsonl_path: Path, html_out: Path | None, md_out: Path | None) -> None:
    """Render Phase M HTML / Markdown artefacts from a persisted JSONL run.

    Pure side-effect helper so unit tests can exercise it directly
    without standing up a full Supervisor (AGENTS.md rule #7 — the
    renderers are deterministic given a JSONL file).
    """
    report = parse_jsonl(jsonl_path)
    if html_out is not None:
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(render_html(report), encoding="utf-8")
        sys.stderr.write(f"[report] HTML -> {html_out}\n")
    if md_out is not None:
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(render_markdown(report), encoding="utf-8")
        sys.stderr.write(f"[report] Markdown -> {md_out}\n")
    sys.stderr.flush()


def _build_transport(
    name: str,
    target: str,
    api_key: str | None,
    *,
    session_mode: str = "single-call",
):
    from .transports.anthropic_transport import AnthropicTransport
    from .transports.argt_transport import ArgtTransport
    from .transports.ollama_transport import OllamaTransport
    from .transports.openai_transport import OpenAIChatTransport

    if name == "openai":
        return OpenAIChatTransport(
            model=target,
            api_key=api_key or os.environ.get("OPENAI_API_KEY", ""),
        )
    if name == "anthropic":
        return AnthropicTransport(
            model=target,
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", ""),
        )
    if name == "ollama":
        return OllamaTransport(model=target)
    if name == "argt":
        return ArgtTransport(
            target=target,
            api_key=api_key or os.environ.get("ARGT_API_KEY", ""),
            session_mode=session_mode,
        )
    raise click.UsageError(f"unknown transport: {name}")


@main.command("new-class")
@click.option(
    "--layer",
    required=True,
    type=click.Choice(sorted(LAYER_SLUGS)),
    help="Layer key (L1..L5). Determines the directory the scaffold lands in.",
)
@click.option(
    "--class-id",
    required=True,
    help=(
        "Full kebab-case class id, e.g. ``tp-my-new-class``. Must start "
        "with the layer's prefix (tp- ci- cog- ext- mas-)."
    ),
)
@click.option(
    "--title",
    required=True,
    help="One-line human title rendered into the registry and docstring.",
)
@click.option(
    "--variants",
    "target_variants",
    type=int,
    default=100,
    show_default=True,
    help="Number of deterministic variants the scaffold mutator emits.",
)
@click.option(
    "--file-index",
    type=int,
    required=True,
    help="Ordinal that prefixes the new module file, e.g. ``15`` -> ``c15_*.py``.",
)
@click.option(
    "--repo-root",
    type=click.Path(file_okay=False, exists=True, path_type=Path),
    default=Path.cwd(),
    show_default=True,
    help="Repository root to scaffold into. Defaults to the current directory.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Allow overwriting existing class / test files (DANGEROUS).",
)
def new_class(
    layer: str,
    class_id: str,
    title: str,
    target_variants: int,
    file_index: int,
    repo_root: Path,
    overwrite: bool,
) -> None:
    """Scaffold a new attack class + its contract test (rule #8)."""
    try:
        spec = validate_spec(
            layer=layer,
            class_id=class_id,
            title=title,
            target_variants=target_variants,
            file_index=file_index,
        )
    except ScaffoldError as exc:
        raise click.UsageError(str(exc)) from exc

    try:
        class_path, test_path = write_scaffold(spec, repo_root=repo_root, overwrite=overwrite)
    except (FileExistsError, FileNotFoundError) as exc:
        raise click.UsageError(str(exc)) from exc

    click.echo(f"wrote {class_path}")
    click.echo(f"wrote {test_path}")
    click.echo(
        f"next: register {spec.class_filename[:-3]} in "
        f"src/argus/engine/layers/{spec.layer_slug}/__init__.py, "
        f"customize the mutator + seeds, then run `pytest -k {spec.slug}`."
    )


@main.command("list-plugins")
@click.pass_context
def list_plugins(ctx: click.Context) -> None:
    """Show the third-party plugin auto-load report (rule #9)."""
    report = ctx.obj.get("plugin_report") if ctx.obj else None
    if report is None:
        click.echo(f"plugin auto-load was disabled (--no-plugins). Plugin group: {PLUGIN_GROUP}")
        return
    click.echo(f"plugin group: {PLUGIN_GROUP}")
    click.echo(f"discovered: {len(report.discovered)}")
    for name in report.discovered:
        click.echo(f"  {name}")
    click.echo(f"registered this run: {len(report.registered)}")
    for class_id in report.registered:
        click.echo(f"  + {class_id}")
    click.echo(f"skipped (already present): {len(report.skipped_existing)}")
    for class_id in report.skipped_existing:
        click.echo(f"  = {class_id}")
    click.echo(f"failures: {len(report.failures)}")
    for failure in report.failures:
        click.echo(f"  ! {failure.entry_point} -> {failure.value} ({failure.error_type}: {failure.error_message})")


@main.command("report")
@click.option(
    "--in",
    "jsonl_in",
    type=click.Path(dir_okay=False, exists=True, readable=True, path_type=Path),
    required=True,
    help="Forensic JSONL run-log produced by `argus-engine engage --out PATH`.",
)
@click.option(
    "--html",
    "html_out",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write an offline single-file HTML report to this path.",
)
@click.option(
    "--md",
    "md_out",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write a CI-friendly Markdown summary to this path.",
)
def report_cmd(
    jsonl_in: Path,
    html_out: Path | None,
    md_out: Path | None,
) -> None:
    """Render Phase M reports from a forensic JSONL run-log.

    Pure projection: same input file -> same output bytes (rule #7).
    At least one of ``--html`` / ``--md`` must be supplied.
    """
    if html_out is None and md_out is None:
        raise click.UsageError("at least one of --html or --md must be specified")
    _emit_reports(jsonl_in, html_out, md_out)


if __name__ == "__main__":
    main()
