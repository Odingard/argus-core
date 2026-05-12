"""Plain-English narration of supervisor events.

Phase R-1 — ``--narrate`` mode.

The engine's JSONL event stream is rich but reads like a packet trace.
Operators watching a live engagement want sentences, not structured logs.
This module converts each supervisor event into a single, plain-English
line a non-engineer can follow ("Firing variant #1873 of
cog-chain-of-thought-hijack against /chat... target softened (0.42).").

Design notes
============

* **Pure function** (rules #3 + #7). ``EventNarrator.narrate(event)``
  takes a dict and returns either a string or ``None`` (no narration).
  Same input → same output, every time. No I/O, no globals.
* **Deterministic** ordering of fields when interpolating numeric
  values — every dict access uses ``.get`` with explicit fallbacks so
  malformed events never crash the narrator (rule #9).
* **Unknown event types** return ``None`` rather than raising — keeps
  the narrator forward-compatible with future event additions.
* **Verdict labels** use the same ladder the report renderers use
  (IRREFUTABLE / HIGH / MEDIUM / LOW) so the narration matches the
  HTML / Markdown report a viewer would later see.

The narrator is intentionally chatty for screen-recording / demo use
but every sentence carries one concrete observation — class id,
variant id, signal_strength, tier, or arc stage — so it's also useful
as a forensic replay log when ``--narrate`` is set on a real
engagement.
"""

from __future__ import annotations

from typing import Any

__all__ = ["EventNarrator", "format_signal_bar"]


_TIER_GLYPH: dict[str, str] = {
    "IRREFUTABLE": "🚨",
    "HIGH": "⚠",
    "MEDIUM": "•",
    "LOW": "·",
}


def format_signal_bar(value: float, width: int = 8) -> str:
    """Render a continuous ``[0,1]`` value as a unicode block bar.

    Used by both the narrator (inline in sentences) and the HUD
    (in the class heatmap panel). The bar is deterministic — same
    value + width → same string — and never overflows the requested
    width.

    A value of 0.0 renders as ``░░░░░░░░`` (empty), 1.0 as
    ``████████`` (full). Out-of-range inputs are clamped to ``[0,1]``
    so an erroneous signal_strength score above 1.0 never produces a
    longer-than-``width`` bar (rule #9).
    """
    if width <= 0:
        return ""
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = 0.0
    v = max(0.0, min(1.0, v))
    filled = int(round(v * width))
    return ("█" * filled) + ("░" * (width - filled))


def _shorten(text: str, limit: int = 64) -> str:
    """Truncate ``text`` to ``limit`` chars with an ellipsis if needed."""
    if not isinstance(text, str):
        return ""
    text = text.replace("\n", " ").replace("\r", " ").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _variant_short(variant_id: Any) -> str:
    if not isinstance(variant_id, str):
        return "?"
    return variant_id[:10] if len(variant_id) > 10 else variant_id


class EventNarrator:
    """Convert supervisor events to plain-English sentences.

    Usage::

        narrator = EventNarrator()
        for line in narrator.narrate_stream(event_iter):
            print(line)

    Or one event at a time::

        line = narrator.narrate(event)
        if line is not None:
            sys.stderr.write(line + "\\n")
    """

    def __init__(self, *, signal_bar_width: int = 8) -> None:
        self._signal_bar_width = max(int(signal_bar_width), 1)

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def narrate(self, event: dict[str, Any]) -> str | None:
        """Map a single supervisor event to a sentence.

        Returns ``None`` for events that should not be narrated (e.g.
        ``done`` summary events, unknown types) — the caller is
        expected to filter ``None`` out. This avoids a forced "no-op"
        line that would pollute the live feed.
        """
        if not isinstance(event, dict):
            return None
        kind = event.get("type")
        if not isinstance(kind, str):
            return None
        handler = self._DISPATCH.get(kind)
        if handler is None:
            return None
        return handler(self, event)

    def narrate_stream(self, events: Any) -> Any:
        """Yield narrations for every event that produces one.

        Generator helper for callers that want a clean iterator
        without manually filtering ``None``.
        """
        for event in events:
            line = self.narrate(event)
            if line is not None:
                yield line

    # ------------------------------------------------------------------
    # Per-event handlers — each returns a sentence or None
    # ------------------------------------------------------------------

    def _on_phase(self, event: dict[str, Any]) -> str | None:
        phase = event.get("phase", "?")
        classes = event.get("classes")
        if phase == "recon":
            tools = event.get("tool_names") or ()
            if tools:
                shown = ", ".join(str(t) for t in tools[:3])
                more = "" if len(tools) <= 3 else f" (+{len(tools) - 3} more)"
                return f"Recon complete — mapped {len(tools)} tool(s): {shown}{more}."
            return "Recon complete — no tools surfaced."
        if classes:
            count = len(classes) if hasattr(classes, "__len__") else "?"
            return f"Entering phase '{phase}' with {count} candidate class(es)."
        return f"Entering phase '{phase}'."

    def _on_thought(self, event: dict[str, Any]) -> str | None:
        text = event.get("text") or ""
        text = _shorten(text, limit=120)
        if not text:
            return None
        return f"Strategy: {text}"

    def _on_fire(self, event: dict[str, Any]) -> str | None:
        cls = event.get("attack_class") or "?"
        vid = _variant_short(event.get("variant_id"))
        score = event.get("signal_strength")
        if score is None:
            score = event.get("lethality") or 0.0
        try:
            score_f = float(score)
        except (TypeError, ValueError):
            score_f = 0.0
        bar = format_signal_bar(score_f, width=self._signal_bar_width)
        verdict = event.get("verdict") or "—"
        gloss = self._gloss_for_signal(score_f, verdict)
        return f"Fire {vid} [{cls}] signal {score_f:.2f} {bar} verdict={verdict} — {gloss}"

    def _on_finding(self, event: dict[str, Any]) -> str | None:
        cls = event.get("attack_class") or "?"
        vid = _variant_short(event.get("variant_id"))
        tier = event.get("confidence") or event.get("verdict") or "?"
        glyph = _TIER_GLYPH.get(tier, "•")
        lethality = event.get("lethality")
        try:
            leth_f = float(lethality) if lethality is not None else None
        except (TypeError, ValueError):
            leth_f = None
        if leth_f is None:
            return f"{glyph} LANDED [{tier}] {cls} via {vid}."
        return f"{glyph} LANDED [{tier}] {cls} via {vid} (lethality {leth_f:.2f})."

    def _on_refusal(self, event: dict[str, Any]) -> str | None:
        sig = event.get("signature") or "?"
        kb = event.get("kb_size")
        if kb is None:
            return f"Refusal observed (signature {sig})."
        return f"Refusal observed (signature {sig}); refusal KB now {kb} entries."

    def _on_mutation(self, event: dict[str, Any]) -> str | None:
        gen = event.get("generation")
        survivors = event.get("survivor_count")
        best = event.get("best_score")
        try:
            best_f = float(best) if best is not None else None
        except (TypeError, ValueError):
            best_f = None
        if gen is None or survivors is None or best_f is None:
            return None
        return f"Generation {gen}: {survivors} survivor(s); best signal {best_f:.2f}. Evolving."

    def _on_arc_outcome(self, event: dict[str, Any]) -> str | None:
        completed = bool(event.get("completed"))
        aborted = bool(event.get("aborted"))
        rewinds = event.get("rewinds")
        try:
            rw = int(rewinds) if rewinds is not None else 0
        except (TypeError, ValueError):
            rw = 0
        topic = _shorten(str(event.get("topic") or ""), limit=32)
        persona = _shorten(str(event.get("persona") or ""), limit=32)
        prefix = f"Arc (topic='{topic}', persona='{persona}')"
        if completed:
            return f"{prefix} completed all 5 stages with {rw} rewind(s)."
        if aborted:
            reason = event.get("abort_reason") or "unknown"
            return f"{prefix} aborted at stage — reason: {reason}."
        return f"{prefix} ended without completion ({rw} rewind(s))."

    def _on_signal_strength_summary(self, event: dict[str, Any]) -> str | None:
        count = event.get("count")
        mean = event.get("mean")
        mx = event.get("max")
        try:
            mean_f = float(mean) if mean is not None else None
            mx_f = float(mx) if mx is not None else None
        except (TypeError, ValueError):
            return None
        if count is None or mean_f is None or mx_f is None:
            return None
        return f"Signal-strength summary: {count} samples, mean {mean_f:.2f}, max {mx_f:.2f}."

    def _on_diversity_stats(self, event: dict[str, Any]) -> str | None:
        observed = event.get("observed")
        accepted = event.get("accepted")
        rejected = event.get("rejected")
        if observed is None or accepted is None or rejected is None:
            return None
        return f"Diversity gate: observed {observed}, accepted {accepted}, rejected {rejected}."

    def _on_carrier_histogram(self, event: dict[str, Any]) -> str | None:
        histogram = event.get("histogram")
        if not isinstance(histogram, dict) or not histogram:
            return None
        ordered = sorted(histogram.items(), key=lambda kv: (-int(kv[1]), kv[0]))
        top = ", ".join(f"{k}={v}" for k, v in ordered[:4])
        more = "" if len(ordered) <= 4 else f" (+{len(ordered) - 4} more)"
        return f"Carrier surface mix — {top}{more}."

    def _on_arc_summary(self, event: dict[str, Any]) -> str | None:
        completed = event.get("completed")
        aborted = event.get("aborted")
        total_rewinds = event.get("total_rewinds")
        if completed is None or aborted is None or total_rewinds is None:
            return None
        return f"Arc summary: {completed} completed, {aborted} aborted, {total_rewinds} total rewind(s)."

    def _on_early_stop(self, event: dict[str, Any]) -> str | None:
        cls = event.get("attack_class") or "?"
        count = event.get("count")
        return f"Early-stop on '{cls}' after {count} landing(s)."

    def _on_emergence_report(self, event: dict[str, Any]) -> str | None:
        chain_id = event.get("chain_id") or "?"
        links = event.get("link_count")
        if links is None:
            return f"Emergence chain '{chain_id}' captured."
        return f"Emergence chain '{chain_id}' captured ({links} producer→consumer links)."

    def _on_recon_plausibility_fallback(self, event: dict[str, Any]) -> str | None:
        cls = event.get("attack_class") or "?"
        reason = event.get("reason") or "plausibility-gate"
        return f"Recon-aware fallback on '{cls}': {reason}."

    def _on_engagement_memory_persisted(self, event: dict[str, Any]) -> str | None:
        fingerprint = event.get("fingerprint") or "?"
        landed = event.get("landed_class_count")
        if landed is None:
            return f"Engagement memory persisted for target {fingerprint[:12]}."
        return f"Engagement memory persisted for target {fingerprint[:12]} ({landed} landed class(es) carried forward)."

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _gloss_for_signal(score: float, verdict: str) -> str:
        """Map a continuous signal_strength to a short adjective.

        Mirrors the verdict ladder but for the *gradient*, so even a
        non-landing variant earns a descriptive word. The gradient is
        bounded by Phase N's composite cap of 0.85 — a 1.0 reading
        means a canary echo or matcher hit (which the verdict
        captures directly).
        """
        if verdict == "IRREFUTABLE":
            return "canary echoed; ground-truth leak"
        if verdict == "HIGH":
            return "structural-matcher hit"
        if score >= 0.65:
            return "boundary erosion — strong soft-signal"
        if score >= 0.45:
            return "topic acknowledged; partial engagement"
        if score >= 0.25:
            return "mild softening; refusal kept intact"
        return "flat refusal or no engagement"

    # Dispatch table populated after class body so methods are bound.
    _DISPATCH: dict[str, Any] = {}


EventNarrator._DISPATCH = {
    "phase": EventNarrator._on_phase,
    "thought": EventNarrator._on_thought,
    "fire": EventNarrator._on_fire,
    "finding": EventNarrator._on_finding,
    "refusal": EventNarrator._on_refusal,
    "mutation": EventNarrator._on_mutation,
    "arc_outcome": EventNarrator._on_arc_outcome,
    "signal_strength_summary": EventNarrator._on_signal_strength_summary,
    "diversity_stats": EventNarrator._on_diversity_stats,
    "carrier_histogram": EventNarrator._on_carrier_histogram,
    "arc_summary": EventNarrator._on_arc_summary,
    "early_stop": EventNarrator._on_early_stop,
    "emergence_report": EventNarrator._on_emergence_report,
    "recon_plausibility_fallback": EventNarrator._on_recon_plausibility_fallback,
    "engagement_memory_persisted": EventNarrator._on_engagement_memory_persisted,
}
