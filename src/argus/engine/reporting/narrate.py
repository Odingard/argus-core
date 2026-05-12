"""NarrateSink — supervisor-event subscriber that prints English.

Phase R-1 — ``--narrate`` mode.

Wraps :class:`~argus.engine.reporting.narrator.EventNarrator` so it
can be passed directly as a supervisor ``on_event`` callback. Also
emits tier-escalation banners (Phase R-3) inline so a ``--narrate``
run on its own (without ``--hud``) still gets the story beats.

The sink takes an optional ``demo_pace`` argument — a per-line sleep
in seconds — used when recording demo videos for LinkedIn / Discord.
Per the user's standing demo-video preferences the default terminal
speed is far too fast for readable recordings.
"""

from __future__ import annotations

import contextlib
import sys
import time
from typing import IO, Any

from .narrator import EventNarrator
from .tier_tracker import TierEscalationTracker, TierMilestone

__all__ = ["NarrateSink"]


_TIER_GLYPH: dict[str, str] = {
    "IRREFUTABLE": "🚨",
    "HIGH": "⚠",
    "MEDIUM": "•",
    "LOW": "·",
}


class NarrateSink:
    """Emit one plain-English sentence per supervisor event.

    Constructor
    -----------
    narrator
        Optional pre-configured :class:`EventNarrator`. A default
        instance is created if none is supplied.
    stream
        Destination text stream — defaults to ``sys.stderr`` so the
        narration doesn't collide with structured JSONL on stdout.
    demo_pace
        Per-line sleep in seconds. ``0`` (the default) prints at
        terminal speed. Anything positive slows the feed for screen
        recordings.
    emit_banners
        If ``True`` (default), banner lines render whenever a class
        first crosses a tier boundary. ``False`` is useful when
        ``NarrateSink`` is chained with ``HudSink`` — the HUD already
        renders Rich banner panels and we don't want duplicate
        announcements.
    inner
        Optional second sink chained after narration. ``HudSink``
        is the canonical pairing — ``NarrateSink(inner=HudSink())``
        gives both English narration on stderr and the Rich cockpit.
    """

    def __init__(
        self,
        *,
        narrator: EventNarrator | None = None,
        stream: IO[str] | None = None,
        demo_pace: float = 0.0,
        emit_banners: bool = True,
        inner: Any | None = None,
    ) -> None:
        self._narrator = narrator if narrator is not None else EventNarrator()
        self._stream = stream if stream is not None else sys.stderr
        self._demo_pace = max(float(demo_pace), 0.0)
        self._tracker = TierEscalationTracker() if emit_banners else None
        self._inner = inner
        self._closed = False
        self.findings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Sink contract
    # ------------------------------------------------------------------

    def __call__(self, event: dict[str, Any]) -> None:
        if self._closed or not isinstance(event, dict):
            return

        line = self._narrator.narrate(event)
        if line is not None:
            self._write(line)

        if self._tracker is not None:
            milestone = self._tracker.observe(event)
            if milestone is not None:
                self._write(self._format_banner(milestone))

        if event.get("type") == "finding":
            self.findings.append(event)

        if self._inner is not None:
            with contextlib.suppress(Exception):
                self._inner(event)

        if self._demo_pace > 0:
            time.sleep(self._demo_pace)

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._inner is not None and hasattr(self._inner, "stop"):
            with contextlib.suppress(Exception):
                self._inner.stop()

    # Context-manager sugar.
    def __enter__(self) -> NarrateSink:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _write(self, line: str) -> None:
        # Destination stream errors must not bubble — sink is best-effort
        # (rule #9 — narrator never breaks the live engagement).
        with contextlib.suppress(Exception):
            self._stream.write(line + "\n")
            flush = getattr(self._stream, "flush", None)
            if callable(flush):
                flush()

    @staticmethod
    def _format_banner(milestone: TierMilestone) -> str:
        glyph = _TIER_GLYPH.get(milestone.tier, "•")
        return (
            f"{glyph} ── {milestone.tier} crossed on {milestone.attack_class} "
            f"(signal {milestone.score:.2f}, variant "
            f"{(milestone.variant_id or '?')[:10]}) ──"
        )
