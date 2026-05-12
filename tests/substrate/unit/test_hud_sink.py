"""Phase R-2 — HudSink + render_hud_layout unit tests.

The HUD is a Rich Live view, but the *state* it renders is a plain
dataclass — :class:`HudState` — so we can exercise it without touching
a TTY. For the rendered output we use a recording
``rich.console.Console`` and assert on the captured text, which is
deterministic over a fixed state (rule #7).
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from argus.engine.reporting.hud import (
    HudSink,
    HudState,
    render_hud_layout,
)

# ---------------------------------------------------------------------------
# HudState absorption
# ---------------------------------------------------------------------------


def test_state_absorbs_fire_event() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "fire",
            "attack_class": "cog-foo",
            "variant_id": "v01",
            "signal_strength": 0.42,
            "verdict": "LOW",
        },
        milestone=None,
    )
    assert state.fired == 1
    assert state.fires_per_class["cog-foo"] == 1
    assert state.best_signal_per_class["cog-foo"] == pytest.approx(0.42)
    assert list(state.ticker)[-1]["attack_class"] == "cog-foo"


def test_state_keeps_best_signal_per_class_monotonic() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": 0.3,
        },
        None,
    )
    state.absorb(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": 0.7,
        },
        None,
    )
    state.absorb(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": 0.4,
        },
        None,
    )
    assert state.best_signal_per_class["x"] == pytest.approx(0.7)


def test_state_absorbs_finding_event() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "finding",
            "attack_class": "ext-leak",
            "variant_id": "v01",
            "confidence": "HIGH",
            "lethality": 0.9,
        },
        None,
    )
    assert state.landed == 1
    assert state.lands_per_class["ext-leak"] == 1
    assert list(state.landings)[-1]["tier"] == "HIGH"


def test_state_absorbs_signal_summary() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "signal_strength_summary",
            "count": 50,
            "mean": 0.31,
            "max": 0.85,
            "p99": 0.79,
        },
        None,
    )
    assert state.signal_summary["count"] == pytest.approx(50)
    assert state.signal_summary["mean"] == pytest.approx(0.31)


def test_state_absorbs_diversity_stats() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "diversity_stats",
            "observed": 100,
            "accepted": 80,
            "rejected": 20,
        },
        None,
    )
    assert state.diversity_stats == {"observed": 100, "accepted": 80, "rejected": 20}


def test_state_absorbs_carrier_histogram() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "carrier_histogram",
            "histogram": {"user_turn": 5, "tool_result": 2, "bogus": "oops"},
        },
        None,
    )
    # Bogus values are dropped; valid pairs survive.
    assert state.carrier_histogram == {"user_turn": 5, "tool_result": 2}


def test_state_absorbs_phase() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "phase",
            "phase": "exploitation",
            "tool_names": ("memory", "calc"),
            "target": "https://target/chat",
        },
        None,
    )
    assert state.phase == "exploitation"
    assert state.tools == ["memory", "calc"]
    assert state.target == "https://target/chat"


def test_state_records_banner_milestones() -> None:
    from argus.engine.reporting.tier_tracker import TierMilestone

    state = HudState()
    milestone = TierMilestone(
        attack_class="x",
        tier="MEDIUM",
        variant_id="v",
        score=0.5,
    )
    state.absorb({"type": "fire", "attack_class": "x"}, milestone)
    assert state.banners[-1] is milestone


def test_state_ticker_is_bounded() -> None:
    state = HudState()
    for i in range(200):
        state.absorb(
            {
                "type": "fire",
                "attack_class": "x",
                "variant_id": f"v{i:04d}",
                "signal_strength": 0.1,
            },
            None,
        )
    assert state.fired == 200
    # ticker is a deque bounded to _TICKER_LIMIT (24).
    assert len(state.ticker) <= 24


# ---------------------------------------------------------------------------
# render_hud_layout — Rich console capture
# ---------------------------------------------------------------------------


def _record(state: HudState) -> str:
    console = Console(
        file=io.StringIO(),
        width=120,
        record=True,
        force_terminal=False,
        color_system=None,
    )
    layout = render_hud_layout(state)
    console.print(layout)
    return console.export_text()


def test_layout_empty_state_renders_without_error() -> None:
    out = _record(HudState())
    assert "RECON" in out
    assert "CLASS HEATMAP" in out
    assert "VARIANT FIRE TICKER" in out
    assert "LANDINGS" in out


def test_layout_includes_class_after_fire() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "fire",
            "attack_class": "cog-chain-of-thought-hijack",
            "variant_id": "v0123456789abc",
            "signal_strength": 0.42,
            "verdict": "LOW",
        },
        None,
    )
    out = _record(state)
    assert "cog-chain-of-thought-hijack" in out
    assert "0.42" in out


def test_layout_includes_landing_with_tier() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "finding",
            "attack_class": "ext-system-prompt-leak",
            "variant_id": "v0001",
            "confidence": "IRREFUTABLE",
            "lethality": 1.0,
        },
        None,
    )
    out = _record(state)
    assert "ext-system-prompt-leak" in out
    assert "IRREFUTABLE" in out


def test_layout_includes_target_when_set() -> None:
    state = HudState()
    state.absorb(
        {
            "type": "phase",
            "phase": "recon",
            "target": "https://target.example/chat",
            "tool_names": [],
        },
        None,
    )
    out = _record(state)
    assert "target.example" in out


def test_layout_is_deterministic_for_same_state() -> None:
    state = HudState(start_time=1000.0)
    state.absorb(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": 0.5,
        },
        None,
    )
    state.absorb(
        {
            "type": "finding",
            "attack_class": "x",
            "variant_id": "v",
            "confidence": "HIGH",
            "lethality": 0.7,
        },
        None,
    )

    # Force a stable start_time so the elapsed-seconds row doesn't drift.
    def render() -> str:
        snap = HudState(
            phase=state.phase,
            target=state.target,
            tools=list(state.tools),
            fired=state.fired,
            landed=state.landed,
            start_time=1000.0,
            fires_per_class=state.fires_per_class.copy(),
            lands_per_class=state.lands_per_class.copy(),
            best_signal_per_class=dict(state.best_signal_per_class),
            ticker=state.ticker.copy(),
            landings=state.landings.copy(),
            banners=state.banners.copy(),
            signal_summary=dict(state.signal_summary),
            diversity_stats=dict(state.diversity_stats),
            carrier_histogram=dict(state.carrier_histogram),
            arc_summary=dict(state.arc_summary),
        )
        # Pin elapsed by monkey-patching time briefly — easier to just
        # render twice in a row and accept the small elapsed drift
        # affects only one row. Strip that row before comparison.
        out = _record(snap)
        return "\n".join(line for line in out.splitlines() if "elapsed" not in line)

    assert render() == render()


# ---------------------------------------------------------------------------
# HudSink
# ---------------------------------------------------------------------------


def test_sink_falls_back_when_not_tty() -> None:
    console = Console(
        file=io.StringIO(),
        width=80,
        force_terminal=False,
        color_system=None,
    )
    sink = HudSink(console=console)
    assert sink._fallback is True
    assert sink._live is None


def test_sink_records_findings_for_fallback() -> None:
    console = Console(
        file=io.StringIO(),
        width=80,
        force_terminal=False,
        color_system=None,
    )
    sink = HudSink(console=console)
    sink(
        {
            "type": "finding",
            "attack_class": "x",
            "variant_id": "v",
            "confidence": "HIGH",
            "lethality": 0.7,
        }
    )
    sink.stop()
    assert len(sink.findings) == 1
    out = console.file.getvalue()
    assert "LANDING" in out
    assert "x" in out


def test_sink_emits_tier_milestone_in_fallback() -> None:
    console = Console(
        file=io.StringIO(),
        width=80,
        force_terminal=False,
        color_system=None,
    )
    sink = HudSink(console=console)
    sink(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": 0.5,
        }
    )
    sink.stop()
    out = console.file.getvalue()
    assert "MEDIUM" in out
    assert "x" in out


def test_sink_is_safe_with_non_dict_event() -> None:
    sink = HudSink(
        console=Console(
            file=io.StringIO(),
            width=80,
            force_terminal=False,
            color_system=None,
        )
    )
    sink("not-a-dict")  # type: ignore[arg-type]
    sink(None)  # type: ignore[arg-type]
    sink.stop()
    assert sink.findings == []


def test_sink_context_manager_stops_cleanly() -> None:
    console = Console(
        file=io.StringIO(),
        width=80,
        force_terminal=False,
        color_system=None,
    )
    with HudSink(console=console) as sink:
        sink(
            {
                "type": "fire",
                "attack_class": "x",
                "variant_id": "v",
                "signal_strength": 0.1,
            }
        )
    # Idempotent stop
    sink.stop()
