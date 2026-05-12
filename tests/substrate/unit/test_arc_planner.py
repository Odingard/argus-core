"""Phase Q — deterministic 5-stage arc-planner tests.

Pins:

* AGENTS.md #7 — deterministic. Same variant + same recon inputs →
  byte-identical :class:`Arc`. Same scripted probe sequence →
  byte-identical :class:`ArcExecutionResult`.
* AGENTS.md #5 — refusal handling. A refusal at stage K rewinds to
  stage K-1; refusal at stage 0 (rapport) aborts cleanly with an
  explicit ``abort_reason`` (rule #9 — never silent).
* Stage progression — five canonical stages in canonical order.
* Multi-call transcript — rewinds truncate the assistant transcript
  so the rewound prompt doesn't see the refused turn.
"""

from __future__ import annotations

import asyncio

from argus.engine.core.canary import CanarySet
from argus.engine.core.variant import Message, Variant
from argus.engine.grading.matcher import ProbeResult
from argus.engine.runtime.arc_planner import (
    CANONICAL_STAGES,
    Arc,
    ArcPlanner,
    ArcRunner,
    StageOutcome,
    summarise_arc_outcomes,
)


def _v(variant_id: str = "v-1") -> Variant:
    return Variant(
        variant_id=variant_id,
        seed_id="seed-1",
        attack_class="ci-multi-turn-erosion",
        layer="layer2_contextual",
        messages=(Message(role="user", content="discuss authentication boundaries please"),),
        canaries=CanarySet(primary="ARGT-CANARY-MULTI"),
        metadata={},
    )


def _probe(text: str = "ok", *, refused: bool = False) -> ProbeResult:
    return ProbeResult(
        variant_id="v-1",
        seed_id="seed-1",
        attack_class="ci-multi-turn-erosion",
        response_text=text,
        tool_calls=(),
        state_transitions=(),
        oob_hits=(),
        refused=refused,
    )


def _run_runner(arc: Arc, replies):
    """Run an ArcRunner with a scripted reply sequence."""
    queue = list(replies)

    async def probe_callable(_messages):
        return queue.pop(0)

    runner = ArcRunner(probe_callable=probe_callable)
    return asyncio.run(runner.run(arc)), runner


# --- planner shape -------------------------------------------------


def test_canonical_arc_has_five_stages() -> None:
    assert CANONICAL_STAGES == (
        "rapport",
        "persona_seed",
        "boundary_probe",
        "boundary_erode",
        "extract",
    )
    planner = ArcPlanner()
    arc = planner.plan(_v())
    assert tuple(s.stage_id for s in arc.stages) == CANONICAL_STAGES


def test_arc_carries_topic_and_persona() -> None:
    planner = ArcPlanner()
    arc = planner.plan(_v())
    assert arc.topic
    assert arc.persona


def test_arc_stage_payloads_are_non_empty() -> None:
    planner = ArcPlanner()
    arc = planner.plan(_v())
    for stage in arc.stages:
        assert stage.payload.strip() != ""


def test_rapport_stage_has_rewind_disabled() -> None:
    """Rapport is stage 0 — refusal there aborts, never rewinds."""
    planner = ArcPlanner()
    arc = planner.plan(_v())
    rapport = next(s for s in arc.stages if s.stage_id == "rapport")
    assert rapport.rewind_on_refusal is False
    for stage in arc.stages:
        if stage.stage_id != "rapport":
            assert stage.rewind_on_refusal is True


# --- planner determinism (rule #7) --------------------------------


def test_planner_is_deterministic() -> None:
    planner = ArcPlanner()
    a = planner.plan(_v())
    b = planner.plan(_v())
    assert a == b


def test_planner_respects_topic_override() -> None:
    planner = ArcPlanner()
    arc = planner.plan(_v(), topic="custom-topic-xyz")
    assert arc.topic == "custom-topic-xyz"


def test_planner_respects_persona_override() -> None:
    planner = ArcPlanner()
    arc = planner.plan(_v(), persona="security-researcher")
    assert arc.persona == "security-researcher"


def test_planner_uses_recon_personae_when_provided() -> None:
    planner = ArcPlanner()
    arc = planner.plan(_v(), recon_personae=("compliance_auditor",))
    assert arc.persona == "compliance_auditor"


def test_planner_rejects_unknown_stage_id() -> None:
    import pytest

    with pytest.raises(ValueError):
        ArcPlanner(stages=("rapport", "not_a_real_stage"))


# --- runner happy path --------------------------------------------


def test_runner_completes_when_no_refusals() -> None:
    arc = ArcPlanner().plan(_v())
    replies = [_probe(f"stage-{i}-reply") for i in range(len(arc.stages))]
    result, _ = _run_runner(arc, replies)
    assert result.completed is True
    assert result.aborted is False
    assert result.rewinds == 0
    assert len(result.outcomes) == len(arc.stages)
    assert all(isinstance(o, StageOutcome) for o in result.outcomes)


# --- refusal rewind -----------------------------------------------


def test_refusal_at_stage_2_rewinds_once() -> None:
    """Refused on boundary_probe → rewinds to persona_seed → succeeds.

    Scripted replies (one per probe call):
        1) rapport OK
        2) persona_seed OK
        3) boundary_probe REFUSED → rewind to persona_seed
        4) persona_seed OK (re-attempt after rewind)
        5) boundary_probe OK
        6) boundary_erode OK
        7) extract OK
    """
    arc = ArcPlanner().plan(_v())
    replies = [
        _probe("rapport-ok"),
        _probe("persona-ok"),
        _probe("I cannot help with that", refused=True),
        _probe("persona-ok-2"),
        _probe("probe-ok"),
        _probe("erode-ok"),
        _probe("extract-ok"),
    ]
    result, _ = _run_runner(arc, replies)
    assert result.completed is True
    assert result.rewinds == 1
    rewound_outcomes = [o for o in result.outcomes if o.rewound_to is not None]
    assert len(rewound_outcomes) == 1
    assert rewound_outcomes[0].stage_id == "boundary_probe"
    assert rewound_outcomes[0].rewound_to == "persona_seed"


def test_refusal_at_rapport_aborts_cleanly() -> None:
    """Stage 0 has rewind_on_refusal=False — refusal aborts, never silently."""
    arc = ArcPlanner().plan(_v())
    replies = [_probe("I cannot help", refused=True)]
    result, _ = _run_runner(arc, replies)
    assert result.completed is False
    assert result.aborted is True
    assert result.abort_reason == "refused_at_first_stage"
    assert result.rewinds == 0


def test_rewind_budget_exhaustion_aborts() -> None:
    """Persistent refusal must eventually abort with a named reason.

    Rule #9 — never silent. The two valid abort reasons here are
    ``rewind_budget_exhausted`` (rewinds capped before reaching
    rapport) and ``refused_at_first_stage`` (rewound back to the
    non-rewindable rapport stage and refused there too). Either is
    acceptable; the contract is that ``abort_reason`` is non-empty
    and explains the early stop.
    """
    arc = ArcPlanner().plan(_v())
    replies = [_probe("rapport-ok")] + [_probe("I refuse", refused=True) for _ in range(20)]
    result, _ = _run_runner(arc, replies)
    assert result.aborted is True
    assert result.abort_reason in (
        "rewind_budget_exhausted",
        "refused_at_first_stage",
    )
    assert result.rewinds >= 1


# --- runner determinism -------------------------------------------


def test_runner_outcome_deterministic_across_runs() -> None:
    arc = ArcPlanner().plan(_v())
    replies1 = [_probe(f"r-{i}") for i in range(len(arc.stages))]
    replies2 = [_probe(f"r-{i}") for i in range(len(arc.stages))]
    r1, _ = _run_runner(arc, replies1)
    r2, _ = _run_runner(arc, replies2)
    assert r1 == r2


# --- summarise_arc_outcomes ---------------------------------------


def test_summarise_arc_outcomes_aggregates_counts() -> None:
    arc = ArcPlanner().plan(_v("v-a"))
    arc2 = ArcPlanner().plan(_v("v-b"))
    replies_ok = [_probe(f"r-{i}") for i in range(len(arc.stages))]
    r_ok, _ = _run_runner(arc, replies_ok)
    r_abort, _ = _run_runner(arc2, [_probe("nope", refused=True)])

    summary = summarise_arc_outcomes([r_ok, r_abort])
    assert summary["arcs"] == 2
    assert summary["completed"] == 1
    assert summary["aborted"] == 1
    assert summary["total_rewinds"] == r_ok.rewinds + r_abort.rewinds
    assert isinstance(summary["stage_reach_counts"], dict)


def test_summarise_arc_outcomes_empty_returns_zero_dict() -> None:
    summary = summarise_arc_outcomes([])
    assert summary["arcs"] == 0
    assert summary["completed"] == 0
    assert summary["aborted"] == 0
    assert summary["total_rewinds"] == 0


def test_summarise_stage_reach_counts_reflect_furthest_stage() -> None:
    """A completed arc should bump every stage_id's counter."""
    arc = ArcPlanner().plan(_v())
    replies = [_probe(f"r-{i}") for i in range(len(arc.stages))]
    result, _ = _run_runner(arc, replies)
    summary = summarise_arc_outcomes([result])
    reach = summary["stage_reach_counts"]
    for stage_id in CANONICAL_STAGES:
        assert reach.get(stage_id, 0) >= 1
