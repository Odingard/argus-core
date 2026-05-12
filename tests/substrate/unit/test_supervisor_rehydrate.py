"""Phase J — supervisor rehydrate integration tests.

Pins the contract between the persistence layer and the supervisor FSM:

1. Configuring an ``EngagementMemory`` makes the strategy start in
   ``EngagementPhase.REHYDRATE`` and computes a target fingerprint.
2. On a cold cache, ``_run_rehydrate`` is a no-op that emits a
   ``miss`` phase event (rule #9 — explainable outcomes).
3. On a warm cache, ``_run_rehydrate`` seeds ``RefusalKB`` from the
   persisted signatures, merges the persisted recon snapshot onto
   the running profile, and records persisted trust markers and
   landed-class IDs.
4. ``_persist_engagement_memory`` writes back a fresh entry covering
   the latest findings, refusal-KB state, and recon snapshot, with
   ``leaked_credentials`` stripped (rule #4).
"""

from __future__ import annotations

from pathlib import Path

from argus.engine.recon.mcp_introspect import TargetManifest, ToolManifest
from argus.engine.runtime.engagement_memory import (
    EngagementMemory,
    EngagementMemoryEntry,
    TrustMarker,
    compute_target_fingerprint,
)
from argus.engine.runtime.reward import ShadowModel
from argus.engine.runtime.strategy import EngagementPhase
from argus.engine.runtime.supervisor import Supervisor


class _NoopTransport:
    name = "noop"
    supported_surfaces = frozenset({"chat", "mcp"})

    async def probe(self, variant):  # pragma: no cover — never fired here
        raise AssertionError("transport.probe should not be invoked in these tests")


def _manifest() -> TargetManifest:
    return TargetManifest(
        transport="mcp",
        tools=(
            ToolManifest(
                name="read_file",
                description="read a file",
                parameters_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            ),
        ),
    )


def _supervisor(
    memory: EngagementMemory | None = None,
    *,
    model_id: str = "test-model",
    on_event=None,
) -> Supervisor:
    return Supervisor(
        transport=_NoopTransport(),
        manifest=_manifest(),
        shadow=ShadowModel(),
        layer="layer4_extraction",
        engagement_memory=memory,
        model_id=model_id,
        on_event=on_event,
    )


def test_supervisor_starts_in_rehydrate_when_memory_configured(tmp_path: Path) -> None:
    """Strategy initial phase is REHYDRATE only when memory is wired."""
    memory = EngagementMemory(memory_dir=tmp_path / "engagement")
    sup = _supervisor(memory=memory)
    assert sup._strategy.phase == EngagementPhase.REHYDRATE
    assert sup._target_fingerprint is not None


def test_supervisor_starts_in_recon_when_no_memory_configured() -> None:
    """Without memory the rehydrate phase never engages — backward compat."""
    sup = _supervisor(memory=None)
    assert sup._strategy.phase == EngagementPhase.RECON
    assert sup._target_fingerprint is None


def test_rehydrate_miss_is_explainable_and_noop(tmp_path: Path) -> None:
    """Rule #9 — a cold cache emits a ``miss`` phase event and leaves
    refusal-KB / trust markers untouched."""
    events: list[dict] = []
    memory = EngagementMemory(memory_dir=tmp_path / "engagement")
    sup = _supervisor(memory=memory, on_event=events.append)
    sup._run_rehydrate()
    miss_events = [e for e in events if e.get("type") == "phase" and e.get("outcome") == "miss"]
    assert len(miss_events) == 1
    assert miss_events[0]["phase"] == EngagementPhase.REHYDRATE.value
    assert miss_events[0]["fingerprint_id"] == sup._target_fingerprint.fingerprint_id
    assert sup._refusal_kb.size() == 0
    assert sup._trust_markers == []
    assert sup._rehydrated is False


def test_rehydrate_hit_seeds_refusal_kb_and_trust_markers(tmp_path: Path) -> None:
    """A persisted entry warms RefusalKB, loads trust markers, and
    records the prior landed-class roster."""
    memory = EngagementMemory(memory_dir=tmp_path / "engagement")
    manifest = _manifest()
    fingerprint = compute_target_fingerprint(manifest, model_id="test-model")
    entry = EngagementMemoryEntry(
        fingerprint=fingerprint,
        trust_markers=(TrustMarker(kind="persona", value="grandma", accepted_count=3, last_seen=0.0),),
        refusal_signatures=(
            "i cannot share that information",
            "i refuse to disclose policy",
        ),
        recon_snapshot={"persona_fragments": ("helpful_assistant",)},
        landed_class_ids=("ext-system-prompt-leak",),
        last_seen=9999999999.0,  # Far future so TTL never trips.
        ttl_seconds=7 * 24 * 3600,
    )
    memory.write(entry)

    events: list[dict] = []
    sup = _supervisor(memory=memory, on_event=events.append)
    sup._run_rehydrate()

    assert sup._rehydrated is True
    assert sup._refusal_kb.size() >= 2
    assert len(sup._trust_markers) == 1
    assert sup._trust_markers[0].value == "grandma"
    assert sup._persisted_landed_class_ids == ("ext-system-prompt-leak",)
    # Recon snapshot merged onto running profile.
    assert sup._recon_profile is not None
    assert "helpful_assistant" in sup._recon_profile.persona_fragments

    hit_events = [e for e in events if e.get("type") == "phase" and e.get("outcome") == "hit"]
    assert len(hit_events) == 1
    assert hit_events[0]["trust_markers_loaded"] == 1
    assert hit_events[0]["prior_landed_classes"] == ["ext-system-prompt-leak"]


def test_rehydrate_emits_skipped_when_memory_absent() -> None:
    """Defensive guard: calling _run_rehydrate without a memory just
    emits a ``skipped`` event and returns."""
    events: list[dict] = []
    sup = _supervisor(memory=None, on_event=events.append)
    sup._run_rehydrate()
    skipped = [e for e in events if e.get("type") == "phase" and e.get("outcome") == "skipped"]
    assert len(skipped) == 1
    assert skipped[0]["reason"] == "no_memory_configured"


def test_persist_engagement_memory_writes_entry_excluding_credentials(
    tmp_path: Path,
) -> None:
    """Rule #4 — ``leaked_credentials`` is filtered out of persisted snapshots."""
    from argus.engine.core.recon_profile import ReconProfile

    memory = EngagementMemory(memory_dir=tmp_path / "engagement")
    events: list[dict] = []
    sup = _supervisor(memory=memory, on_event=events.append)
    sup._recon_profile = ReconProfile(
        persona_fragments=("grandma",),
        leaked_credentials=("sk-EVIL-MUST-NOT-PERSIST",),
    )
    sup._persist_engagement_memory()

    persisted = [e for e in events if e.get("type") == "engagement_memory_persisted"]
    assert len(persisted) == 1
    # Round-trip through memory and verify the credential slot is gone.
    loaded = memory.get(sup._target_fingerprint)
    assert loaded is not None
    assert "leaked_credentials" not in loaded.recon_snapshot
    assert loaded.recon_snapshot.get("persona_fragments") == ("grandma",)


def test_rehydrate_then_persist_round_trip_preserves_markers(tmp_path: Path) -> None:
    """End-to-end: hit → engagement collects new markers → write-back
    union'd with prior markers without duplicates."""
    memory = EngagementMemory(memory_dir=tmp_path / "engagement")
    fingerprint = compute_target_fingerprint(_manifest(), model_id="test-model")
    seed_entry = EngagementMemoryEntry(
        fingerprint=fingerprint,
        trust_markers=(TrustMarker(kind="persona", value="grandma", accepted_count=1, last_seen=0.0),),
        refusal_signatures=(),
        recon_snapshot={},
        landed_class_ids=(),
        last_seen=9999999999.0,
        ttl_seconds=7 * 24 * 3600,
    )
    memory.write(seed_entry)

    sup = _supervisor(memory=memory)
    sup._run_rehydrate()
    # Simulate engagement landing a new framing primer.
    sup._capture_trust_marker(kind="framing", value="hypothetical scenario")
    sup._persist_engagement_memory()

    loaded = memory.get(fingerprint)
    assert loaded is not None
    values = {m.value for m in loaded.trust_markers}
    assert "grandma" in values
    assert "hypothetical scenario" in values
