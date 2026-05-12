"""Phase R-1 — EventNarrator unit tests.

Pure functions are easy to pin down: same dict in → same string out, on
every call, on every interpreter run (rule #7). These tests cover every
supported event type plus the deterministic/forward-compatible failure
modes.
"""

from __future__ import annotations

import pytest

from argus.engine.reporting.narrator import EventNarrator, format_signal_bar


@pytest.fixture
def narrator() -> EventNarrator:
    return EventNarrator()


# ---------------------------------------------------------------------------
# format_signal_bar
# ---------------------------------------------------------------------------


def test_signal_bar_zero_is_all_empty() -> None:
    assert format_signal_bar(0.0, width=8) == "░" * 8


def test_signal_bar_one_is_all_full() -> None:
    assert format_signal_bar(1.0, width=8) == "█" * 8


def test_signal_bar_half_is_half_full() -> None:
    bar = format_signal_bar(0.5, width=8)
    assert bar.count("█") == 4
    assert bar.count("░") == 4
    assert len(bar) == 8


def test_signal_bar_clamps_out_of_range_inputs() -> None:
    # Values outside [0,1] must not produce a longer-than-width bar (rule #9).
    assert format_signal_bar(2.5, width=6) == "█" * 6
    assert format_signal_bar(-0.5, width=6) == "░" * 6


def test_signal_bar_handles_non_numeric_input() -> None:
    assert format_signal_bar("nope", width=4) == "░" * 4  # type: ignore[arg-type]


def test_signal_bar_zero_width() -> None:
    assert format_signal_bar(0.7, width=0) == ""


def test_signal_bar_deterministic() -> None:
    a = format_signal_bar(0.37, width=12)
    b = format_signal_bar(0.37, width=12)
    assert a == b


# ---------------------------------------------------------------------------
# narrate dispatch — unknown / malformed
# ---------------------------------------------------------------------------


def test_narrate_returns_none_for_unknown_event_type(narrator: EventNarrator) -> None:
    assert narrator.narrate({"type": "this-doesnt-exist"}) is None


def test_narrate_returns_none_for_non_dict_input(narrator: EventNarrator) -> None:
    assert narrator.narrate("not-a-dict") is None  # type: ignore[arg-type]
    assert narrator.narrate(None) is None  # type: ignore[arg-type]
    assert narrator.narrate(42) is None  # type: ignore[arg-type]


def test_narrate_returns_none_when_type_missing(narrator: EventNarrator) -> None:
    assert narrator.narrate({"attack_class": "foo"}) is None


# ---------------------------------------------------------------------------
# phase events
# ---------------------------------------------------------------------------


def test_phase_recon_with_tools(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "phase",
            "phase": "recon",
            "tool_names": ["search", "calc", "memory"],
        }
    )
    assert line is not None
    assert "Recon complete" in line
    assert "search" in line
    assert "3 tool" in line


def test_phase_recon_with_no_tools(narrator: EventNarrator) -> None:
    line = narrator.narrate({"type": "phase", "phase": "recon", "tool_names": []})
    assert line == "Recon complete — no tools surfaced."


def test_phase_with_classes(narrator: EventNarrator) -> None:
    line = narrator.narrate({"type": "phase", "phase": "probing", "classes": ["a", "b", "c"]})
    assert line is not None
    assert "probing" in line
    assert "3 candidate" in line


def test_phase_fallback(narrator: EventNarrator) -> None:
    line = narrator.narrate({"type": "phase", "phase": "exploitation"})
    assert line == "Entering phase 'exploitation'."


# ---------------------------------------------------------------------------
# fire events
# ---------------------------------------------------------------------------


def test_fire_event_carries_signal_strength(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "fire",
            "attack_class": "cog-chain-of-thought-hijack",
            "variant_id": "v0123456789abcdef",
            "signal_strength": 0.42,
            "verdict": "LOW",
        }
    )
    assert line is not None
    assert "cog-chain-of-thought-hijack" in line
    assert "0.42" in line
    assert "v012345678" in line  # truncated to 10 chars


def test_fire_event_falls_back_to_lethality_when_signal_missing(
    narrator: EventNarrator,
) -> None:
    line = narrator.narrate(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "lethality": 0.61,
            "verdict": "MEDIUM",
        }
    )
    assert line is not None
    assert "0.61" in line


def test_fire_event_gloss_for_irrefutable(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": 1.0,
            "verdict": "IRREFUTABLE",
        }
    )
    assert line is not None
    assert "canary" in line.lower()


def test_fire_event_gloss_for_flat_refusal(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": 0.05,
            "verdict": "LOW",
        }
    )
    assert line is not None
    assert "refusal" in line.lower() or "flat" in line.lower()


def test_fire_event_handles_bad_score_gracefully(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "fire",
            "attack_class": "x",
            "variant_id": "v",
            "signal_strength": "not-a-number",
            "verdict": "LOW",
        }
    )
    assert line is not None
    assert "0.00" in line


# ---------------------------------------------------------------------------
# finding events
# ---------------------------------------------------------------------------


def test_finding_event_renders_with_tier(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "finding",
            "attack_class": "ext-system-prompt-leak",
            "variant_id": "v0123456789",
            "confidence": "IRREFUTABLE",
            "lethality": 1.0,
        }
    )
    assert line is not None
    assert "IRREFUTABLE" in line
    assert "ext-system-prompt-leak" in line


def test_finding_event_omits_lethality_when_missing(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "finding",
            "attack_class": "x",
            "variant_id": "v",
            "confidence": "HIGH",
        }
    )
    assert line is not None
    assert "lethality" not in line


# ---------------------------------------------------------------------------
# refusal / mutation / arc / summaries
# ---------------------------------------------------------------------------


def test_refusal_with_kb_size(narrator: EventNarrator) -> None:
    line = narrator.narrate({"type": "refusal", "signature": "I can't help", "kb_size": 7})
    assert line == "Refusal observed (signature I can't help); refusal KB now 7 entries."


def test_refusal_without_kb_size(narrator: EventNarrator) -> None:
    line = narrator.narrate({"type": "refusal", "signature": "sorry"})
    assert line == "Refusal observed (signature sorry)."


def test_mutation_event(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "mutation",
            "generation": 3,
            "survivor_count": 12,
            "best_score": 0.58,
        }
    )
    assert line is not None
    assert "Generation 3" in line
    assert "12 survivor" in line
    assert "0.58" in line


def test_mutation_event_drops_when_field_missing(narrator: EventNarrator) -> None:
    assert narrator.narrate({"type": "mutation", "generation": 1, "survivor_count": 4}) is None


def test_arc_outcome_completed(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "arc_outcome",
            "completed": True,
            "aborted": False,
            "rewinds": 1,
            "topic": "exfil",
            "persona": "developer",
        }
    )
    assert line is not None
    assert "completed all 5 stages" in line
    assert "1 rewind" in line


def test_arc_outcome_aborted(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "arc_outcome",
            "completed": False,
            "aborted": True,
            "abort_reason": "refusal_during_rapport",
            "topic": "x",
            "persona": "y",
        }
    )
    assert line is not None
    assert "aborted" in line
    assert "refusal_during_rapport" in line


def test_signal_summary_event(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "signal_strength_summary",
            "count": 100,
            "mean": 0.21,
            "max": 0.84,
            "p99": 0.79,
        }
    )
    assert line is not None
    assert "100" in line and "0.21" in line and "0.84" in line


def test_diversity_stats_event(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "diversity_stats",
            "observed": 200,
            "accepted": 150,
            "rejected": 50,
        }
    )
    assert line is not None
    assert "200" in line and "150" in line and "50" in line


def test_carrier_histogram_event(narrator: EventNarrator) -> None:
    line = narrator.narrate(
        {
            "type": "carrier_histogram",
            "histogram": {"user_turn": 10, "tool_result": 4, "rag_document": 1},
        }
    )
    assert line is not None
    assert "user_turn=10" in line


def test_carrier_histogram_empty_returns_none(narrator: EventNarrator) -> None:
    assert narrator.narrate({"type": "carrier_histogram", "histogram": {}}) is None


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        {
            "type": "fire",
            "attack_class": "c1",
            "variant_id": "v1234567890abc",
            "signal_strength": 0.42,
            "verdict": "LOW",
        },
        {
            "type": "finding",
            "attack_class": "c2",
            "variant_id": "v",
            "confidence": "HIGH",
            "lethality": 0.8,
        },
        {"type": "refusal", "signature": "no", "kb_size": 3},
        {
            "type": "mutation",
            "generation": 2,
            "survivor_count": 5,
            "best_score": 0.3,
        },
    ],
)
def test_narration_is_deterministic_across_repeated_calls(event: dict) -> None:
    narrator = EventNarrator()
    first = narrator.narrate(event)
    again = EventNarrator().narrate(event)
    once_more = narrator.narrate(event)
    assert first == again == once_more


# ---------------------------------------------------------------------------
# stream helper
# ---------------------------------------------------------------------------


def test_narrate_stream_skips_none(narrator: EventNarrator) -> None:
    events = [
        {"type": "phase", "phase": "init"},
        {"type": "this-doesnt-exist"},
        {"type": "refusal", "signature": "no"},
    ]
    lines = list(narrator.narrate_stream(events))
    assert len(lines) == 2
    assert "init" in lines[0]
    assert "Refusal" in lines[1]
