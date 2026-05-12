"""Phase J — EmergenceReport unit tests.

Pins three invariants of ``build_emergence_report``:

1. Producer → consumer links are inferred from harvested-slot
   consumption: when step A lands and harvests slot ``S``, and a
   later step B is registered as a consumer of ``S``, exactly one
   ``EmergenceLink(A → B)`` is emitted.
2. First-consumer-wins: a single slot harvested once is linked to
   the *first* downstream consumer, not duplicated across later
   consumers (prevents double-counting in the chain transcript).
3. ``fallback_events`` from the underlying ``ChainResult`` round-trip
   through the report unchanged (rule #9 — no silent failures).
"""

from __future__ import annotations

from dataclasses import dataclass

from argus.engine.core.chain_graph import ChainEdge, ChainPlan
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.runtime.chain_runner import ChainResult, ChainStepRecord
from argus.engine.runtime.emergence_report import (
    EmergenceLink,
    EmergenceLog,
    build_emergence_report,
)


@dataclass(frozen=True, slots=True)
class _StubClass:
    """Minimal stand-in for an attack class with ``consumes`` slot."""

    consumes: tuple[str, ...]


def _stub_plan(nodes: tuple[str, ...]) -> ChainPlan:
    edges = tuple(ChainEdge(src=nodes[i], dst=nodes[i + 1], artefact="any") for i in range(len(nodes) - 1))
    return ChainPlan(chain_id=f"chain-{'-'.join(nodes)}", nodes=nodes, edges=edges)


def _stub_result(
    *,
    chain_id: str,
    plan: ChainPlan,
    steps: tuple[ChainStepRecord, ...],
    completed: bool = True,
    fallback_events: tuple[dict[str, object], ...] = (),
) -> ChainResult:
    return ChainResult(
        chain_id=chain_id,
        plan=plan,
        steps=steps,
        completed=completed,
        final_recon=ReconProfile(),
        fallback_events=fallback_events,
    )


def test_report_emits_link_when_producer_landed_and_consumer_registered(
    monkeypatch,
) -> None:
    """Step 0 harvests ``leaked_credentials`` → step 1 consumes it →
    one EmergenceLink(0 → 1) is emitted."""

    def fake_consumers(class_id: str) -> frozenset[str]:
        if class_id == "tp-credential-exercise":
            return frozenset({"leaked_credentials"})
        return frozenset()

    monkeypatch.setattr(
        "argus.engine.runtime.emergence_report._slot_consumers",
        fake_consumers,
    )
    plan = _stub_plan(("ext-credential-leak", "tp-credential-exercise"))
    steps = (
        ChainStepRecord(
            class_id="ext-credential-leak",
            fired=1,
            landed=True,
            variant_id="v0",
            harvested=(("leaked_credentials", ("sk-test-DEADBEEF",)),),
        ),
        ChainStepRecord(
            class_id="tp-credential-exercise",
            fired=1,
            landed=True,
            variant_id="v1",
            harvested=(),
        ),
    )
    result = _stub_result(chain_id="c0", plan=plan, steps=steps)
    report = build_emergence_report(result)
    assert report.chain_id == "c0"
    assert report.completed is True
    assert report.landed_class_ids == ("ext-credential-leak", "tp-credential-exercise")
    assert len(report.links) == 1
    link = report.links[0]
    assert link.producer_class_id == "ext-credential-leak"
    assert link.consumer_class_id == "tp-credential-exercise"
    assert link.harvested_field == "leaked_credentials"
    assert link.artefact_count == 1


def test_report_skips_link_when_producer_did_not_land(monkeypatch) -> None:
    """Even if a downstream consumer fires, no link is emitted unless
    the producer's step actually landed (rule #6 — every link has
    evidence)."""

    def fake_consumers(class_id: str) -> frozenset[str]:
        if class_id == "tp-credential-exercise":
            return frozenset({"leaked_credentials"})
        return frozenset()

    monkeypatch.setattr(
        "argus.engine.runtime.emergence_report._slot_consumers",
        fake_consumers,
    )
    plan = _stub_plan(("ext-credential-leak", "tp-credential-exercise"))
    steps = (
        ChainStepRecord(
            class_id="ext-credential-leak",
            fired=5,
            landed=False,  # No landing → no harvest → no producer
            variant_id=None,
            harvested=(),
        ),
        ChainStepRecord(
            class_id="tp-credential-exercise",
            fired=1,
            landed=True,
            variant_id="v1",
            harvested=(),
        ),
    )
    result = _stub_result(chain_id="c1", plan=plan, steps=steps)
    report = build_emergence_report(result)
    assert report.landed_class_ids == ("tp-credential-exercise",)
    assert report.links == ()


def test_report_first_consumer_wins_per_slot(monkeypatch) -> None:
    """If two downstream steps both consume the same slot, only the
    first link is emitted to keep the transcript tractable."""

    def fake_consumers(class_id: str) -> frozenset[str]:
        if class_id in {"consumer-a", "consumer-b"}:
            return frozenset({"x"})
        return frozenset()

    monkeypatch.setattr(
        "argus.engine.runtime.emergence_report._slot_consumers",
        fake_consumers,
    )
    plan = _stub_plan(("producer", "consumer-a", "consumer-b"))
    steps = (
        ChainStepRecord(
            class_id="producer",
            fired=1,
            landed=True,
            variant_id="v0",
            harvested=(("x", ("art",)),),
        ),
        ChainStepRecord(
            class_id="consumer-a",
            fired=1,
            landed=True,
            variant_id="v1",
            harvested=(),
        ),
        ChainStepRecord(
            class_id="consumer-b",
            fired=1,
            landed=True,
            variant_id="v2",
            harvested=(),
        ),
    )
    result = _stub_result(chain_id="c2", plan=plan, steps=steps)
    report = build_emergence_report(result)
    assert len(report.links) == 1
    assert report.links[0].consumer_class_id == "consumer-a"


def test_report_round_trips_fallback_events() -> None:
    """Rule #9 — fallback events on the source ``ChainResult`` are
    surfaced verbatim through the report."""
    plan = _stub_plan(("solo",))
    steps = (
        ChainStepRecord(
            class_id="solo",
            fired=1,
            landed=True,
            variant_id="v0",
            harvested=(),
        ),
    )
    events: tuple[dict[str, object], ...] = (
        {
            "event": "recon_plausibility_fallback",
            "class_id": "solo",
            "recon_variant_id": "v0r",
            "baseline_variant_id": "v0b",
        },
    )
    result = _stub_result(
        chain_id="c3",
        plan=plan,
        steps=steps,
        fallback_events=events,
    )
    report = build_emergence_report(result)
    assert report.fallback_events == events


def test_report_is_deterministic_for_same_input(monkeypatch) -> None:
    """Rule #7 — same ``ChainResult`` produces a bit-identical report."""

    def fake_consumers(class_id: str) -> frozenset[str]:
        if class_id == "b":
            return frozenset({"slot"})
        return frozenset()

    monkeypatch.setattr(
        "argus.engine.runtime.emergence_report._slot_consumers",
        fake_consumers,
    )
    plan = _stub_plan(("a", "b"))
    steps = (
        ChainStepRecord(
            class_id="a",
            fired=1,
            landed=True,
            variant_id="va",
            harvested=(("slot", ("x", "y")),),
        ),
        ChainStepRecord(
            class_id="b",
            fired=1,
            landed=True,
            variant_id="vb",
            harvested=(),
        ),
    )
    result = _stub_result(chain_id="c4", plan=plan, steps=steps)
    a = build_emergence_report(result)
    b = build_emergence_report(result)
    assert a == b
    assert a.as_dict() == b.as_dict()


def test_emergence_log_aggregates_multiple_reports() -> None:
    """``EmergenceLog.append`` accumulates reports in firing order."""
    log = EmergenceLog()
    plan = _stub_plan(("a",))
    steps = (ChainStepRecord(class_id="a", fired=1, landed=True, variant_id="va", harvested=()),)
    r1 = build_emergence_report(_stub_result(chain_id="c-1", plan=plan, steps=steps))
    r2 = build_emergence_report(_stub_result(chain_id="c-2", plan=plan, steps=steps))
    log.append(r1)
    log.append(r2)
    assert len(log.reports) == 2
    assert tuple(r.chain_id for r in log.reports) == ("c-1", "c-2")


def test_report_summary_is_non_empty_for_landed_chain() -> None:
    """``summary`` always produces a human-readable string when at
    least one step landed (rule #9 — explainable output)."""
    plan = _stub_plan(("a",))
    steps = (ChainStepRecord(class_id="a", fired=1, landed=True, variant_id="va", harvested=()),)
    report = build_emergence_report(_stub_result(chain_id="c-summary", plan=plan, steps=steps))
    assert isinstance(report.summary, str)
    assert report.summary.strip(), "summary should not be blank for a landed chain"


def test_link_as_dict_round_trips_every_field() -> None:
    """Persistence-shape helper exposes every field."""
    link = EmergenceLink(
        producer_class_id="p",
        producer_step_index=0,
        consumer_class_id="c",
        consumer_step_index=1,
        harvested_field="slot",
        artefact_count=3,
    )
    data = link.as_dict()
    assert data == {
        "producer_class_id": "p",
        "producer_step_index": 0,
        "consumer_class_id": "c",
        "consumer_step_index": 1,
        "harvested_field": "slot",
        "artefact_count": 3,
    }


def test_report_as_dict_is_json_serialisable() -> None:
    """``EmergenceReport.as_dict`` produces a json.dumps-able payload."""
    import json

    plan = _stub_plan(("a",))
    steps = (ChainStepRecord(class_id="a", fired=1, landed=True, variant_id="va", harvested=()),)
    report = build_emergence_report(_stub_result(chain_id="c-json", plan=plan, steps=steps))
    payload = report.as_dict()
    json.dumps(payload)  # Must not raise
    assert payload["chain_id"] == "c-json"
    assert payload["landed_class_ids"] == ["a"]


def test_empty_steps_produces_empty_report() -> None:
    """A chain that produced no steps is reported as completed=False
    landed_class_ids=() — never crashes (rule #9)."""
    plan = _stub_plan(("a",))
    result = _stub_result(chain_id="c-empty", plan=plan, steps=(), completed=False)
    report = build_emergence_report(result)
    assert report.chain_id == "c-empty"
    assert report.completed is False
    assert report.landed_class_ids == ()
    assert report.links == ()
