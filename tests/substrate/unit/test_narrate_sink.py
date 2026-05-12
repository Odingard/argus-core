"""Phase R-1 — NarrateSink integration tests.

The sink itself is a thin shell around :class:`EventNarrator` +
:class:`TierEscalationTracker`. These tests pin the wiring so the
public CLI surface stays predictable.
"""

from __future__ import annotations

import io
from typing import Any

from argus.engine.reporting.narrate import NarrateSink


def test_sink_writes_one_line_per_narratable_event() -> None:
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=False)
    sink({"type": "phase", "phase": "recon", "tool_names": ["t"]})
    sink(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v0001",
            "signal_strength": 0.42,
            "verdict": "LOW",
        }
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 2
    assert "Recon" in lines[0]
    assert "0.42" in lines[1]


def test_sink_skips_unknown_event_types_silently() -> None:
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=False)
    sink({"type": "this-is-not-known"})
    sink({"random": "garbage"})
    assert buf.getvalue() == ""


def test_sink_emits_banner_on_first_tier_crossing() -> None:
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=True)
    sink(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v",
            "signal_strength": 0.5,
        }
    )
    out = buf.getvalue()
    # Two lines: the fire narration + the MEDIUM banner.
    assert "MEDIUM crossed on foo" in out
    assert "Fire" in out


def test_sink_does_not_re_emit_same_tier() -> None:
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=True)
    sink(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v1",
            "signal_strength": 0.5,
        }
    )
    sink(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v2",
            "signal_strength": 0.55,
        }
    )
    assert buf.getvalue().count("MEDIUM crossed on foo") == 1


def test_sink_with_emit_banners_disabled_does_not_emit_banner_lines() -> None:
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=False)
    sink(
        {
            "type": "fire",
            "attack_class": "foo",
            "variant_id": "v",
            "signal_strength": 0.99,
        }
    )
    assert "crossed on" not in buf.getvalue()


def test_sink_tracks_findings() -> None:
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=False)
    finding = {
        "type": "finding",
        "attack_class": "x",
        "variant_id": "v",
        "confidence": "HIGH",
        "lethality": 0.7,
    }
    sink(finding)
    assert sink.findings == [finding]


def test_sink_chains_inner_sink() -> None:
    seen: list[dict[str, Any]] = []

    class _Cap:
        def __call__(self, event: dict[str, Any]) -> None:
            seen.append(event)

        def stop(self) -> None:
            seen.append({"_stopped": True})

    buf = io.StringIO()
    inner = _Cap()
    sink = NarrateSink(stream=buf, emit_banners=False, inner=inner)
    sink({"type": "phase", "phase": "init"})
    assert seen == [{"type": "phase", "phase": "init"}]
    sink.stop()
    assert seen[-1] == {"_stopped": True}


def test_sink_inner_failure_does_not_break_outer() -> None:
    class _Boom:
        def __call__(self, event: dict[str, Any]) -> None:
            raise RuntimeError("kaboom")

    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=False, inner=_Boom())
    # Should not raise — rule #9: never break the live engagement.
    sink({"type": "phase", "phase": "init"})
    assert "init" in buf.getvalue()


def test_sink_safe_with_non_dict_event() -> None:
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, emit_banners=True)
    sink("not-a-dict")  # type: ignore[arg-type]
    sink(None)  # type: ignore[arg-type]
    assert buf.getvalue() == ""


def test_sink_demo_pace_does_not_break_behaviour() -> None:
    # We don't assert timing (flaky); just make sure positive demo_pace
    # doesn't change the visible output.
    buf = io.StringIO()
    sink = NarrateSink(stream=buf, demo_pace=0.0001, emit_banners=False)
    sink({"type": "phase", "phase": "init"})
    assert "init" in buf.getvalue()


def test_sink_idempotent_stop() -> None:
    sink = NarrateSink(stream=io.StringIO(), emit_banners=False)
    sink.stop()
    sink.stop()
