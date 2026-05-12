"""HUD cockpit — Phase R-2 live dashboard.

The legacy ``_TuiSink`` in ``cli.py`` is a 3-pane Rich Live view
(battle / strategy / meter). It works, but the wall-of-text problem
called out in Phase R is real — non-engineers watching a live
engagement can't see the *gradient* the engine is climbing.

This module ships a richer 4-pane cockpit that adds Phase N's
``signal_strength`` gradient as a visual heat band per class, plus a
landings feed with tier glyphs, plus a one-shot tier-escalation
banner overlay driven by :class:`TierEscalationTracker`.

Design notes
============

* The sink is callable — ``sink(event)`` — to match the existing
  supervisor ``on_event`` callback shape.
* It accepts an optional injected ``console`` so tests can drive it
  with a buffered ``rich.console.Console(record=True)`` and assert on
  the rendered output deterministically (rule #7).
* When the target console is *not* a TTY, the constructor returns a
  plain-text fallback callable instead of a Rich Live view — rule #9
  (no silent failures, no garbled escape codes in CI logs).
* The HUD never mutates engine state. It is read-only.
* All ordering inside panels is deterministic — classes sorted by
  highest ``signal_strength`` then by id; ticker keeps insertion
  order with a bounded ring buffer.
"""

from __future__ import annotations

import contextlib
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .narrator import format_signal_bar
from .tier_tracker import TIER_RANK, TierEscalationTracker, TierMilestone

if TYPE_CHECKING:  # pragma: no cover - imports only used for typing
    from rich.console import Console
    from rich.layout import Layout

__all__ = ["HudSink", "HudState", "render_hud_layout"]


_HEAT_STYLE: dict[str, str] = {
    "LOW": "white",
    "MEDIUM": "yellow",
    "HIGH": "orange3",
    "IRREFUTABLE": "bold red",
}


_TIER_GLYPH: dict[str, str] = {
    "IRREFUTABLE": "🚨",
    "HIGH": "⚠",
    "MEDIUM": "•",
    "LOW": "·",
}


_TICKER_LIMIT = 24
_LANDING_LIMIT = 12
_BANNER_LIMIT = 6


@dataclass
class HudState:
    """Pure state captured by the HUD from the event stream.

    Kept separate from the Rich rendering so unit tests can feed
    events through the state object and assert on plain values
    without instantiating a console.
    """

    phase: str = "init"
    target: str | None = None
    tools: list[str] = field(default_factory=list)
    fired: int = 0
    landed: int = 0
    start_time: float = field(default_factory=time.monotonic)
    fires_per_class: Counter[str] = field(default_factory=Counter)
    lands_per_class: Counter[str] = field(default_factory=Counter)
    best_signal_per_class: dict[str, float] = field(default_factory=dict)
    ticker: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=_TICKER_LIMIT))
    landings: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=_LANDING_LIMIT))
    banners: deque[TierMilestone] = field(default_factory=lambda: deque(maxlen=_BANNER_LIMIT))
    signal_summary: dict[str, float] = field(default_factory=dict)
    diversity_stats: dict[str, int] = field(default_factory=dict)
    carrier_histogram: dict[str, int] = field(default_factory=dict)
    arc_summary: dict[str, Any] = field(default_factory=dict)

    def absorb(self, event: dict[str, Any], milestone: TierMilestone | None) -> None:
        """Update state from a single event + optional milestone."""
        kind = event.get("type")
        if kind == "phase":
            phase = event.get("phase")
            if isinstance(phase, str):
                self.phase = phase
            tool_names = event.get("tool_names")
            if isinstance(tool_names, (list, tuple)):
                self.tools = [str(t) for t in tool_names]
            target = event.get("target") or event.get("target_url")
            if isinstance(target, str) and target:
                self.target = target
        elif kind == "fire":
            self.fired += 1
            cls = _coerce_str(event.get("attack_class"))
            self.fires_per_class[cls] += 1
            score = _coerce_score(event)
            prev = self.best_signal_per_class.get(cls, 0.0)
            if score > prev:
                self.best_signal_per_class[cls] = score
            self.ticker.append(
                {
                    "attack_class": cls,
                    "variant_id": _coerce_str(event.get("variant_id")),
                    "signal_strength": score,
                    "verdict": _coerce_str(event.get("verdict")) or "—",
                }
            )
        elif kind == "finding":
            self.landed += 1
            cls = _coerce_str(event.get("attack_class"))
            self.lands_per_class[cls] += 1
            score = _coerce_score(event)
            prev = self.best_signal_per_class.get(cls, 0.0)
            if score > prev:
                self.best_signal_per_class[cls] = score
            self.landings.append(
                {
                    "attack_class": cls,
                    "variant_id": _coerce_str(event.get("variant_id")),
                    "tier": _coerce_str(event.get("confidence") or event.get("verdict")) or "?",
                    "lethality": score,
                }
            )
        elif kind == "signal_strength_summary":
            for key in ("count", "mean", "max", "p50", "p90", "p99"):
                raw = event.get(key)
                if raw is None:
                    continue
                try:
                    self.signal_summary[key] = float(raw)
                except (TypeError, ValueError):
                    continue
        elif kind == "diversity_stats":
            for key in (
                "observed",
                "accepted",
                "rejected",
                "rejected_distance",
                "rejected_capacity",
            ):
                raw = event.get(key)
                if raw is None:
                    continue
                try:
                    self.diversity_stats[key] = int(raw)
                except (TypeError, ValueError):
                    continue
        elif kind == "carrier_histogram":
            histogram = event.get("histogram")
            if isinstance(histogram, dict):
                cleaned: dict[str, int] = {}
                for k, v in histogram.items():
                    try:
                        cleaned[str(k)] = int(v)
                    except (TypeError, ValueError):
                        continue
                self.carrier_histogram = cleaned
        elif kind == "arc_summary":
            for key in ("completed", "aborted", "total_rewinds"):
                raw = event.get(key)
                if raw is None:
                    continue
                try:
                    self.arc_summary[key] = int(raw)
                except (TypeError, ValueError):
                    continue

        if milestone is not None:
            self.banners.append(milestone)


def render_hud_layout(state: HudState) -> Layout:
    """Build a Rich ``Layout`` from a :class:`HudState` snapshot.

    Public so tests can capture the rendered output via a recording
    console without going through the live sink.
    """
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    layout = Layout()
    layout.split_column(
        Layout(name="top", ratio=2),
        Layout(name="bottom", ratio=3),
    )
    layout["top"].split_row(
        Layout(name="recon", ratio=1),
        Layout(name="heatmap", ratio=2),
    )
    layout["bottom"].split_row(
        Layout(name="ticker", ratio=2),
        Layout(name="landings", ratio=1),
    )

    # --- recon panel -------------------------------------------------
    recon = Table.grid(padding=(0, 1))
    recon.add_column(style="bold cyan")
    recon.add_column()
    recon.add_row("phase", state.phase)
    if state.target:
        recon.add_row("target", state.target)
    elapsed = max(time.monotonic() - state.start_time, 0.0)
    recon.add_row("elapsed", _fmt_hms(elapsed))
    recon.add_row("fired", str(state.fired))
    recon.add_row(
        "landed",
        f"[bold green]{state.landed}[/]" if state.landed else "0",
    )
    if state.tools:
        tools_shown = ", ".join(state.tools[:6])
        if len(state.tools) > 6:
            tools_shown += f" (+{len(state.tools) - 6} more)"
        recon.add_row("tools", tools_shown)
    if state.diversity_stats:
        ds = state.diversity_stats
        recon.add_row(
            "diversity",
            f"obs={ds.get('observed', 0)} acc={ds.get('accepted', 0)} rej={ds.get('rejected', 0)}",
        )
    if state.signal_summary:
        ss = state.signal_summary
        mean = ss.get("mean", 0.0)
        mx = ss.get("max", 0.0)
        recon.add_row("signal", f"mean={mean:.2f} max={mx:.2f}")
    if state.carrier_histogram:
        top = sorted(
            state.carrier_histogram.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )[:3]
        recon.add_row(
            "carriers",
            " ".join(f"{k}:{v}" for k, v in top),
        )
    layout["top"]["recon"].update(Panel(recon, title="[bold cyan]RECON / TARGET", border_style="cyan"))

    # --- heatmap panel ----------------------------------------------
    heatmap = Table.grid(padding=(0, 1))
    heatmap.add_column(style="bold", no_wrap=True)
    heatmap.add_column(no_wrap=True)
    heatmap.add_column(no_wrap=True)
    heatmap.add_column(justify="right")
    heatmap.add_row(
        "[dim]class[/]",
        "[dim]signal[/]",
        "[dim]tier[/]",
        "[dim]fires / lands[/]",
    )
    ordered = sorted(
        state.best_signal_per_class.items(),
        key=lambda kv: (-kv[1], kv[0]),
    )
    for cls, score in ordered[:12]:
        tier = _tier_for_score(score)
        bar = format_signal_bar(score)
        style = _HEAT_STYLE.get(tier, "white")
        fires = state.fires_per_class.get(cls, 0)
        lands = state.lands_per_class.get(cls, 0)
        heatmap.add_row(
            cls,
            f"[{style}]{bar} {score:.2f}[/]",
            f"[{style}]{tier}[/]",
            f"{fires} / {lands}",
        )
    if not ordered:
        heatmap.add_row("[dim]…awaiting first fire…[/]", "", "", "")
    layout["top"]["heatmap"].update(Panel(heatmap, title="[bold magenta]CLASS HEATMAP", border_style="magenta"))

    # --- ticker panel ------------------------------------------------
    ticker = Text()
    for row in list(state.ticker)[-_TICKER_LIMIT:]:
        score = row.get("signal_strength", 0.0)
        try:
            score_f = float(score)
        except (TypeError, ValueError):
            score_f = 0.0
        tier = _tier_for_score(score_f)
        style = _HEAT_STYLE.get(tier, "white")
        vid = row.get("variant_id") or "?"
        vid_short = vid[:10] if isinstance(vid, str) else "?"
        bar = format_signal_bar(score_f)
        ticker.append(
            f"{row.get('attack_class', '?'):<32} {vid_short:<10} ",
            style="white",
        )
        ticker.append(f"{bar} {score_f:.2f}\n", style=style)
    if not state.ticker:
        ticker.append("[dim]…awaiting first fire…[/]", style="dim")
    layout["bottom"]["ticker"].update(Panel(ticker, title="[bold red]VARIANT FIRE TICKER", border_style="red"))

    # --- landings panel ---------------------------------------------
    landings = Text()
    for row in list(state.landings)[-_LANDING_LIMIT:]:
        tier = row.get("tier", "?")
        glyph = _TIER_GLYPH.get(tier, "•")
        style = _HEAT_STYLE.get(tier, "white")
        cls = row.get("attack_class", "?")
        vid = row.get("variant_id") or "?"
        vid_short = vid[:10] if isinstance(vid, str) else "?"
        try:
            score_f = float(row.get("lethality", 0.0))
        except (TypeError, ValueError):
            score_f = 0.0
        landings.append(f"{glyph} ", style=style)
        landings.append(
            f"[{tier}] {cls} via {vid_short} ({score_f:.2f})\n",
            style=style,
        )
    if not state.landings:
        landings.append("…no landings yet…", style="dim")
    title = "[bold green]LANDINGS"
    if state.banners:
        latest = state.banners[-1]
        title = f"[{_HEAT_STYLE.get(latest.tier, 'white')}]LANDINGS — {latest.tier} cross on {latest.attack_class}"
    layout["bottom"]["landings"].update(Panel(landings, title=title, border_style="green"))

    return layout


class HudSink:
    """Live Rich cockpit subscriber for ARGUS engagement events.

    Constructor is intentionally permissive — if the destination
    console isn't a TTY (or Rich isn't usable), the sink degrades
    to a plain-text fallback that just prints landings and tier
    milestones one line at a time. Rule #9 — never go silent.
    """

    def __init__(
        self,
        *,
        console: Console | None = None,
        force_terminal: bool | None = None,
        refresh_per_second: int = 6,
        demo_pace: float = 0.0,
    ) -> None:
        self._state = HudState()
        self._tracker = TierEscalationTracker()
        self.findings: list[dict[str, Any]] = []
        self._demo_pace = max(float(demo_pace), 0.0)
        self._closed = False
        self._live = None

        try:
            from rich.console import Console as _Console
            from rich.live import Live as _Live
        except Exception:  # noqa: BLE001 - rich import failure → fallback
            self._console = None
            self._fallback = True
            return

        if console is not None:
            self._console = console
        else:
            tty_default = bool(getattr(sys.stderr, "isatty", lambda: False)())
            force = tty_default if force_terminal is None else bool(force_terminal)
            self._console = _Console(stderr=True, force_terminal=force)
        self._fallback = not bool(getattr(self._console, "is_terminal", True))
        if self._fallback:
            return
        try:
            self._live = _Live(
                render_hud_layout(self._state),
                console=self._console,
                refresh_per_second=max(int(refresh_per_second), 1),
                transient=False,
            )
            self._live.start()
        except Exception:  # noqa: BLE001
            self._live = None
            self._fallback = True

    # ------------------------------------------------------------------
    # Sink contract
    # ------------------------------------------------------------------

    def __call__(self, event: dict[str, Any]) -> None:
        if self._closed or not isinstance(event, dict):
            return
        milestone = self._tracker.observe(event)
        self._state.absorb(event, milestone)
        if event.get("type") == "finding":
            self.findings.append(event)
        if milestone is not None and not self._fallback:
            self._emit_banner(milestone)
        if self._live is not None:
            with contextlib.suppress(Exception):
                self._live.update(render_hud_layout(self._state))
        elif self._fallback:
            self._emit_fallback_line(event, milestone)
        if self._demo_pace > 0:
            time.sleep(self._demo_pace)

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._live is not None:
            with contextlib.suppress(Exception):
                self._live.stop()

    # Context-manager sugar so callers can ``with HudSink() as sink:``.
    def __enter__(self) -> HudSink:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _emit_banner(self, milestone: TierMilestone) -> None:
        if self._console is None:
            return
        try:
            from rich.panel import Panel
        except Exception:  # noqa: BLE001
            return
        style = _HEAT_STYLE.get(milestone.tier, "white")
        glyph = _TIER_GLYPH.get(milestone.tier, "•")
        body = (
            f"{glyph}  [bold]{milestone.tier}[/]  crossed on "
            f"[bold]{milestone.attack_class}[/]  "
            f"(signal {milestone.score:.2f}, variant "
            f"{(milestone.variant_id or '?')[:10]})"
        )
        if self._live is not None:
            # Stop / print / resume so the panel anchors above the live view.
            with contextlib.suppress(Exception):
                self._live.stop()
        try:
            self._console.print(Panel(body, border_style=style, expand=False))
            if milestone.tier == "IRREFUTABLE":
                with contextlib.suppress(Exception):
                    self._console.bell()
        finally:
            if self._live is not None:
                with contextlib.suppress(Exception):
                    self._live.start()

    def _emit_fallback_line(self, event: dict[str, Any], milestone: TierMilestone | None) -> None:
        """Plain-text fallback when stderr isn't a TTY.

        Prints only the high-signal events (landings + tier
        milestones). Other events are absorbed into state but not
        echoed, keeping non-TTY logs readable (rule #9).
        """
        if self._console is None:
            return
        if milestone is not None:
            self._console.print(
                f"[{milestone.tier}] {milestone.attack_class} "
                f"crossed at signal={milestone.score:.2f} "
                f"variant={(milestone.variant_id or '?')[:10]}"
            )
        if event.get("type") == "finding":
            cls = event.get("attack_class") or "?"
            tier = event.get("confidence") or event.get("verdict") or "?"
            vid = event.get("variant_id") or "?"
            vid_short = vid[:10] if isinstance(vid, str) else "?"
            self._console.print(f"LANDING [{tier}] {cls} via {vid_short}")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _coerce_str(raw: Any) -> str:
    if isinstance(raw, str):
        return raw
    if raw is None:
        return ""
    return str(raw)


def _coerce_score(event: dict[str, Any]) -> float:
    for key in ("signal_strength", "lethality"):
        raw = event.get(key)
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return 0.0


def _fmt_hms(seconds: float) -> str:
    s = max(int(seconds), 0)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def _tier_for_score(score: float) -> str:
    if score >= 0.99:
        return "IRREFUTABLE"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.45:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "LOW"


# Sanity check: ensure tier strings here align with the tracker. Raised at
# import time so a future drift between this module and tier_tracker.py is
# caught immediately rather than silently producing miscolored output
# (rule #9 — no silent failures).
if not set(_HEAT_STYLE).issubset(TIER_RANK):
    raise RuntimeError(
        f"HUD heat style keys must be a subset of TIER_RANK: unknown tiers {sorted(set(_HEAT_STYLE) - set(TIER_RANK))}"
    )
