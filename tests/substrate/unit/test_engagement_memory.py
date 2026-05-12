"""Phase J — EngagementMemory unit tests.

Pins six invariants:

1. ``compute_target_fingerprint`` is deterministic — same manifest +
   model produce bit-identical fingerprints across calls.
2. Schema drift on a single tool flips ``tool_schema_hash`` so a
   rehydrate against the new manifest gets a clean cache miss.
3. JSONL round-trip — write an entry, read it back, every field
   round-trips byte-for-byte (rule #7 determinism).
4. TTL expiry — an entry whose ``last_seen`` is past ``ttl_seconds``
   is invisible to ``get`` even though the JSONL line is still on
   disk (audit-preserved).
5. ``filter_persistable_recon`` strips ``leaked_credentials`` so
   AGENTS.md rule #4 (credentials never cross the engagement boundary)
   holds even when callers forget.
6. ``merge_trust_markers`` deduplicates on ``(kind, value)``,
   summing counts and advancing ``last_seen`` to ``max``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from argus.engine.recon.mcp_introspect import TargetManifest, ToolManifest
from argus.engine.runtime.engagement_memory import (
    EngagementMemory,
    EngagementMemoryEntry,
    TrustMarker,
    compute_target_fingerprint,
    filter_persistable_recon,
    merge_trust_markers,
    normalise_trust_value,
)


def _manifest_with_one_tool(*, schema: dict[str, object] | None = None) -> TargetManifest:
    return TargetManifest(
        transport="mcp",
        tools=(
            ToolManifest(
                name="read_file",
                description="read a file",
                parameters_schema=schema or {"type": "object", "properties": {"path": {"type": "string"}}},
            ),
        ),
    )


def test_fingerprint_is_deterministic_for_same_manifest_and_model() -> None:
    """Rule #7 — same input → same fingerprint, every call."""
    a = compute_target_fingerprint(_manifest_with_one_tool(), model_id="gpt-4o")
    b = compute_target_fingerprint(_manifest_with_one_tool(), model_id="gpt-4o")
    assert a == b
    assert a.fingerprint_id == b.fingerprint_id


def test_fingerprint_changes_when_tool_schema_drifts() -> None:
    """Schema drift on the *same* tool name → fresh fingerprint."""
    a = compute_target_fingerprint(_manifest_with_one_tool(), model_id="gpt-4o")
    b = compute_target_fingerprint(
        _manifest_with_one_tool(
            schema={
                "type": "object",
                "properties": {"path": {"type": "string"}, "mode": {"type": "string"}},
            }
        ),
        model_id="gpt-4o",
    )
    # Tool name set unchanged, so ``manifest_hash`` is identical.
    assert a.manifest_hash == b.manifest_hash
    # Schema differs, so ``tool_schema_hash`` diverges → distinct fingerprint.
    assert a.tool_schema_hash != b.tool_schema_hash
    assert a.fingerprint_id != b.fingerprint_id


def test_fingerprint_changes_when_model_id_changes() -> None:
    """Two engagements against the same MCP target but different LLM
    backings get distinct memory keys so a primer that worked against
    one model isn't blindly applied to another."""
    a = compute_target_fingerprint(_manifest_with_one_tool(), model_id="gpt-4o")
    b = compute_target_fingerprint(_manifest_with_one_tool(), model_id="claude-3-5-sonnet")
    assert a.manifest_hash == b.manifest_hash
    assert a.fingerprint_id != b.fingerprint_id


def test_memory_roundtrip_preserves_every_field(tmp_path: Path) -> None:
    """JSONL write → read → equality. Rule #7: deterministic, bit-identical."""
    memory = EngagementMemory(memory_dir=tmp_path)
    fingerprint = compute_target_fingerprint(_manifest_with_one_tool(), model_id="gpt-4o")
    entry = EngagementMemoryEntry(
        fingerprint=fingerprint,
        trust_markers=(
            TrustMarker(kind="persona", value="research assistant", accepted_count=3, last_seen=1234567890.0),
            TrustMarker(kind="framing", value="security review", accepted_count=1, last_seen=1234567891.0),
        ),
        refusal_signatures=("cannot|comply", "i'm|sorry|cannot"),
        recon_snapshot={"tool_names": ("read_file",), "personas": ("assistant",)},
        landed_class_ids=("tp-tool-instr", "ext-system-prompt-leak"),
        last_seen=time.time(),
        ttl_seconds=86400,
    )
    memory.write(entry)
    rehydrated = memory.get(fingerprint)
    assert rehydrated is not None
    assert rehydrated.fingerprint == fingerprint
    assert rehydrated.trust_markers == entry.trust_markers
    assert rehydrated.refusal_signatures == entry.refusal_signatures
    assert rehydrated.recon_snapshot == entry.recon_snapshot
    assert rehydrated.landed_class_ids == entry.landed_class_ids
    assert rehydrated.ttl_seconds == entry.ttl_seconds


def test_memory_ttl_expiry_hides_stale_entry(tmp_path: Path) -> None:
    """Past-TTL entry is invisible to ``get`` (but still on disk for audit)."""
    memory = EngagementMemory(memory_dir=tmp_path)
    fingerprint = compute_target_fingerprint(_manifest_with_one_tool())
    stale = EngagementMemoryEntry(
        fingerprint=fingerprint,
        trust_markers=(TrustMarker(kind="prefix", value="hi", accepted_count=1, last_seen=0.0),),
        last_seen=time.time() - 10_000,
        ttl_seconds=60,
    )
    memory.write(stale)
    # Without ``now`` override the entry is past its TTL.
    assert memory.get(fingerprint) is None
    # On-disk JSONL is preserved (audit trail, rule #9 explainability).
    path = next(tmp_path.glob("*.jsonl"))
    assert path.exists()
    assert path.read_text(encoding="utf-8").strip(), "entry should still be on disk"


def test_memory_invalidate_removes_record(tmp_path: Path) -> None:
    """Manifest-hash drift → supervisor invalidates the entry explicitly."""
    memory = EngagementMemory(memory_dir=tmp_path)
    fingerprint = compute_target_fingerprint(_manifest_with_one_tool())
    memory.write(EngagementMemoryEntry(fingerprint=fingerprint, last_seen=time.time(), ttl_seconds=3600))
    assert memory.get(fingerprint) is not None
    assert memory.invalidate(fingerprint) is True
    assert memory.get(fingerprint) is None
    # Idempotent — invalidating an already-removed entry returns False.
    assert memory.invalidate(fingerprint) is False


def test_memory_get_returns_latest_non_expired_entry(tmp_path: Path) -> None:
    """Two writes for the same fingerprint → ``get`` returns the freshest."""
    memory = EngagementMemory(memory_dir=tmp_path)
    fingerprint = compute_target_fingerprint(_manifest_with_one_tool())
    older = EngagementMemoryEntry(
        fingerprint=fingerprint,
        trust_markers=(TrustMarker(kind="prefix", value="old", accepted_count=1, last_seen=1.0),),
        last_seen=time.time(),
        ttl_seconds=3600,
    )
    newer = EngagementMemoryEntry(
        fingerprint=fingerprint,
        trust_markers=(TrustMarker(kind="prefix", value="new", accepted_count=1, last_seen=2.0),),
        last_seen=time.time(),
        ttl_seconds=3600,
    )
    memory.write(older)
    memory.write(newer)
    rehydrated = memory.get(fingerprint)
    assert rehydrated is not None
    assert any(tm.value == "new" for tm in rehydrated.trust_markers)


def test_filter_persistable_recon_strips_credentials() -> None:
    """Rule #4 — ``leaked_credentials`` never reaches disk."""
    raw = {
        "tool_names": ("read_file", "write_file"),
        "leaked_credentials": ("sk-test-DEADBEEF",),
        "personas": ("assistant",),
    }
    filtered = filter_persistable_recon(raw)
    assert "leaked_credentials" not in filtered
    assert filtered["tool_names"] == ("read_file", "write_file")
    assert filtered["personas"] == ("assistant",)


def test_from_dict_drops_credential_field_even_if_present_on_disk(tmp_path: Path) -> None:
    """Defensive: a malicious/older writer that leaked credentials onto
    disk cannot rehydrate them — ``from_dict`` filters at read time too."""
    memory = EngagementMemory(memory_dir=tmp_path)
    fingerprint = compute_target_fingerprint(_manifest_with_one_tool())
    # Hand-craft a JSONL payload that smuggles ``leaked_credentials``
    # past ``write`` (which itself filters via ``filter_persistable_recon``).
    path = tmp_path / f"{fingerprint.fingerprint_id}.jsonl"
    payload = {
        "fingerprint": fingerprint.as_dict(),
        "trust_markers": [],
        "refusal_signatures": [],
        "recon_snapshot": {
            "tool_names": ["read_file"],
            "leaked_credentials": ["sk-leaked"],
        },
        "landed_class_ids": [],
        "last_seen": time.time(),
        "ttl_seconds": 3600,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    rehydrated = memory.get(fingerprint)
    assert rehydrated is not None
    assert "leaked_credentials" not in rehydrated.recon_snapshot
    assert rehydrated.recon_snapshot.get("tool_names") == ("read_file",)


def test_merge_trust_markers_dedups_and_sums_counts() -> None:
    """Same (kind, value) across streams → counts summed, last_seen max."""
    existing = [
        TrustMarker(kind="persona", value="researcher", accepted_count=2, last_seen=100.0),
        TrustMarker(kind="framing", value="audit", accepted_count=1, last_seen=50.0),
    ]
    incoming = [
        TrustMarker(kind="persona", value="researcher", accepted_count=3, last_seen=200.0),
        TrustMarker(kind="prefix", value="hi", accepted_count=1, last_seen=10.0),
    ]
    merged = merge_trust_markers(existing, incoming, now=300.0)
    by_key = {(tm.kind, tm.value): tm for tm in merged}
    assert by_key[("persona", "researcher")].accepted_count == 5
    assert by_key[("persona", "researcher")].last_seen == 300.0
    assert by_key[("framing", "audit")].accepted_count == 1
    assert by_key[("prefix", "hi")].accepted_count == 1


def test_merge_trust_markers_rejects_invalid_kinds() -> None:
    """Defensive — unknown ``kind`` values are dropped, not crash."""
    existing = [TrustMarker(kind="persona", value="ok", accepted_count=1, last_seen=10.0)]
    incoming = [TrustMarker(kind="bogus", value="evil", accepted_count=99, last_seen=20.0)]
    merged = merge_trust_markers(existing, incoming)
    by_key = {(tm.kind, tm.value): tm for tm in merged}
    assert ("persona", "ok") in by_key
    assert ("bogus", "evil") not in by_key


def test_normalise_trust_value_strips_control_chars_and_caps_length() -> None:
    """Trust-marker values are length-capped and control-char-stripped."""
    raw = "  hello\x00 world  \x07"
    assert normalise_trust_value(raw) == "hello world"
    too_long = "a" * 1000
    assert len(normalise_trust_value(too_long)) <= 240


def test_target_fingerprint_id_is_stable_string() -> None:
    """``fingerprint_id`` is a hex digest — JSONL-safe filename."""
    fp = compute_target_fingerprint(_manifest_with_one_tool(), model_id="gpt-4o")
    fid = fp.fingerprint_id
    assert isinstance(fid, str)
    assert len(fid) >= 32
    int(fid, 16)  # Must parse as hex


def test_list_fingerprints_enumerates_recorded_entries(tmp_path: Path) -> None:
    """Diagnostic helper enumerates everything on disk for audit CLIs."""
    memory = EngagementMemory(memory_dir=tmp_path)
    fp_a = compute_target_fingerprint(_manifest_with_one_tool(), model_id="a")
    fp_b = compute_target_fingerprint(_manifest_with_one_tool(), model_id="b")
    memory.write(EngagementMemoryEntry(fingerprint=fp_a, last_seen=time.time(), ttl_seconds=3600))
    memory.write(EngagementMemoryEntry(fingerprint=fp_b, last_seen=time.time(), ttl_seconds=3600))
    fingerprints = memory.list_fingerprints()
    ids = {fp.fingerprint_id for fp in fingerprints}
    assert fp_a.fingerprint_id in ids
    assert fp_b.fingerprint_id in ids


def test_corrupt_jsonl_tail_is_tolerated(tmp_path: Path) -> None:
    """A partial flush on crash leaves a corrupt tail; readers skip it."""
    memory = EngagementMemory(memory_dir=tmp_path)
    fp = compute_target_fingerprint(_manifest_with_one_tool())
    good = EngagementMemoryEntry(
        fingerprint=fp,
        trust_markers=(TrustMarker(kind="prefix", value="ok", accepted_count=1, last_seen=1.0),),
        last_seen=time.time(),
        ttl_seconds=3600,
    )
    memory.write(good)
    # Tack on a corrupt line — should be skipped, not crash ``get``.
    path = next(tmp_path.glob("*.jsonl"))
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n{this-is-not-json")
    rehydrated = memory.get(fp)
    assert rehydrated is not None
    assert any(tm.value == "ok" for tm in rehydrated.trust_markers)


def test_refusal_kb_seed_from_signatures_skips_warmup() -> None:
    """Phase J wiring — rehydrate seeds RefusalKB so X8 gate is warm.

    With 5+ seeded signatures, the gate's cold-start window
    (size < 5 → bypass) is bypassed on the very next probe.
    """
    from argus.engine.runtime.refusal_kb import RefusalKB

    kb = RefusalKB()
    seeded = kb.seed_from_signatures(
        [
            "cannot|comply",
            "i'm|sorry|cannot",
            "won't|help",
            "unable|disclose",
            "refuse|share",
            "against|policy",
        ]
    )
    assert seeded == 6
    assert kb.size() == 6
    # Idempotent — re-seeding the same signatures is a no-op.
    assert kb.seed_from_signatures(["cannot|comply"]) == 0


def test_refusal_kb_seed_token_frequencies_accumulates() -> None:
    """Phase J rehydrate seeds token-frequency counters from prior runs."""
    from argus.engine.runtime.refusal_kb import RefusalKB

    kb = RefusalKB()
    kb.seed_token_frequencies({"cannot": 7, "policy": 3, "": 99, "negative": -1})
    freq = kb.token_frequencies()
    assert freq["cannot"] == 7
    assert freq["policy"] == 3
    # Empty / non-positive entries are rejected (rule #9: bounded input).
    assert "" not in freq
    assert freq.get("negative", 0) == 0


def test_refusal_kb_signature_keys_returns_sorted_view() -> None:
    """``signature_keys`` produces a stable, sorted view for persistence."""
    from argus.engine.runtime.refusal_kb import RefusalKB

    kb = RefusalKB()
    kb.seed_from_signatures(["z|sig", "a|sig", "m|sig"])
    keys = kb.signature_keys()
    assert keys == ("a|sig", "m|sig", "z|sig")


def test_engagement_memory_entry_is_expired_respects_now_override() -> None:
    """Tests pass an explicit ``now`` to make TTL arithmetic deterministic."""
    fp = compute_target_fingerprint(_manifest_with_one_tool())
    entry = EngagementMemoryEntry(fingerprint=fp, last_seen=1_000.0, ttl_seconds=60)
    assert entry.is_expired(now=1_059.0) is False
    assert entry.is_expired(now=1_061.0) is True


@pytest.mark.parametrize("kind", ["prefix", "persona", "framing"])
def test_valid_trust_marker_kinds(kind: str) -> None:
    """The three allowed kinds round-trip through merge unchanged."""
    marker = TrustMarker(kind=kind, value="value", accepted_count=1, last_seen=1.0)
    merged = merge_trust_markers([], [marker])
    assert len(merged) == 1
    assert merged[0].kind == kind
