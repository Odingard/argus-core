"""Tests for c11 — ci-tool-result-rag-feedback (Phase K)."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.registry import get
from argus.engine.layers.layer2_contextual_injection import (
    c11_tool_result_rag_feedback,
)


def test_tool_result_rag_feedback_registered() -> None:
    cls = get("ci-tool-result-rag-feedback")
    assert cls.layer == "layer2_contextual_injection"
    assert cls.target_variants == 150
    assert cls.recon_aware is True
    assert cls.target_surface == frozenset({"tool", "mcp"})


def test_tool_result_rag_feedback_variant_count() -> None:
    gen = c11_tool_result_rag_feedback.factory(seed_value=42)
    variants = list(gen.generate())
    assert len(variants) == 150


def test_tool_result_rag_feedback_deterministic_same_seed() -> None:
    a = list(c11_tool_result_rag_feedback.factory(seed_value=42).generate())
    b = list(c11_tool_result_rag_feedback.factory(seed_value=42).generate())
    assert [v.variant_id for v in a] == [v.variant_id for v in b]


def test_tool_result_rag_feedback_seed_sensitivity() -> None:
    a = list(c11_tool_result_rag_feedback.factory(seed_value=42).generate())
    c = list(c11_tool_result_rag_feedback.factory(seed_value=43).generate())
    assert [v.variant_id for v in a] != [v.variant_id for v in c]


def test_tool_result_rag_feedback_unique_variant_ids() -> None:
    variants = list(c11_tool_result_rag_feedback.factory(seed_value=42).generate())
    ids = [v.variant_id for v in variants]
    assert len(set(ids)) == len(ids), "variant ids must be unique"


def test_tool_result_rag_feedback_canary_present() -> None:
    """Every variant must carry a canary for the canary-echo matcher."""
    for variant in c11_tool_result_rag_feedback.factory(seed_value=42).generate():
        assert "canary-echo" in variant.matcher_ids
        assert variant.canaries is not None
        assert variant.canaries.primary, "canary primary is empty"


def test_tool_result_rag_feedback_canary_in_forged_tool_result() -> None:
    """The canary must appear in the forged tool-result message body —
    that is the staged precondition for IRREFUTABLE landing when the
    agent persists / cites / reflects the value downstream.
    """
    for variant in c11_tool_result_rag_feedback.factory(seed_value=42).generate():
        body = " ".join(m.content for m in variant.messages if m.content)
        assert variant.canaries is not None
        assert variant.canaries.primary in body, f"variant {variant.variant_id} missing canary in forged history"


def test_tool_result_rag_feedback_forges_tool_role_message() -> None:
    """The feedback-loop class works by forging a prior tool result.
    Every variant must contain a ``role=tool`` message — that is the
    structural precondition for the attack class to fire.
    """
    for variant in c11_tool_result_rag_feedback.factory(seed_value=42).generate():
        roles = [m.role for m in variant.messages]
        assert "tool" in roles, f"variant {variant.variant_id} missing forged tool result"


def test_tool_result_rag_feedback_credential_shape_matcher_enabled() -> None:
    """Citation-spoof and memory-write patterns can launder credentials,
    so the credential-shape matcher must be enabled.
    """
    cls = get("ci-tool-result-rag-feedback")
    sample = next(cls.factory(seed_value=42).generate())
    assert "credential-shape" in sample.matcher_ids
    assert "behavioral-drift" in sample.matcher_ids


def test_tool_result_rag_feedback_recon_memory_writer_substitution() -> None:
    """When recon supplies memory_writers, those values must appear in
    at least one forged history — proves the tool_to_memory_inject /
    cross_session_carry patterns consume the recon slot.
    """
    profile = ReconProfile(
        memory_writers=("save_user_pref", "store_long_term_memory"),
    )
    gen = c11_tool_result_rag_feedback.factory(seed_value=42, recon=profile)
    bodies = []
    for variant in gen.generate():
        bodies.append(" ".join(m.content for m in variant.messages if m.content))
    combined = " ".join(bodies)
    assert "save_user_pref" in combined or "store_long_term_memory" in combined, (
        "recon memory_writers did not propagate into any variant body"
    )


def test_tool_result_rag_feedback_recon_rag_endpoint_substitution() -> None:
    """When recon supplies rag_endpoints, those values must appear in
    at least one forged history — proves the tool_to_rag_poison /
    citation_spoof patterns consume the recon slot.
    """
    profile = ReconProfile(
        rag_endpoints=("retrieve_audit_docs", "search_internal_kb"),
    )
    gen = c11_tool_result_rag_feedback.factory(seed_value=42, recon=profile)
    bodies = []
    for variant in gen.generate():
        bodies.append(" ".join(m.content for m in variant.messages if m.content))
    combined = " ".join(bodies)
    assert "retrieve_audit_docs" in combined or "search_internal_kb" in combined, (
        "recon rag_endpoints did not propagate into any variant body"
    )


def test_tool_result_rag_feedback_recon_empty_fallback_baseline() -> None:
    """With an empty recon profile, the class still yields the full
    target_variants — baseline arm always available (rule #9).
    """
    gen = c11_tool_result_rag_feedback.factory(seed_value=42, recon=ReconProfile.empty())
    variants = list(gen.generate())
    assert len(variants) == 150


def test_tool_result_rag_feedback_variant_messages_nonempty() -> None:
    """No variant may render an empty user message — rule #9
    (no silent failures): every emitted variant must be fireable.
    """
    for variant in c11_tool_result_rag_feedback.factory(seed_value=42).generate():
        body = " ".join(m.content for m in variant.messages if m.content)
        assert body.strip(), f"variant {variant.variant_id} has empty body"


def test_tool_result_rag_feedback_planted_tool_reaches_variant() -> None:
    """Regression for Devin-Review BUG_0001: the mutator previously stored
    the attack tool under the ``_planted_tool`` key, which the Layer 2
    render hook (`make_layer2_render`) does not consume — so every variant
    shipped with an empty ``tools`` tuple and the agent had nothing to
    invoke. Every variant must now expose the planted tool via
    ``variant.tools`` and the tool name must come from the ``_PATTERNS``
    table (memory / RAG / citation / working-memory writers).
    """
    expected_tool_names = {
        "remember_fact",
        "index_document",
        "save_preference",
        "add_citation",
        "store_to_working_memory",
    }
    tool_names_seen: set[str] = set()
    for variant in c11_tool_result_rag_feedback.factory(seed_value=42).generate():
        assert variant.tools, (
            f"variant {variant.variant_id} has no tools — planted tool was silently dropped by the render hook"
        )
        assert len(variant.tools) == 1
        planted = variant.tools[0]
        assert planted.name in expected_tool_names, (
            f"variant {variant.variant_id} planted unexpected tool {planted.name!r}"
        )
        assert planted.annotations.get("kind") == "memory_write"
        tool_names_seen.add(planted.name)
    assert tool_names_seen == expected_tool_names, (
        f"not all planted-tool families surfaced; missing {expected_tool_names - tool_names_seen}"
    )


def test_tool_result_rag_feedback_both_framings_present() -> None:
    """Regression for Devin-Review BUG_0002: the previous ``inner_combos``
    list ordering (``for framing in _FRAMINGS for payload …``) sliced off
    every ``plaintext_directive`` combo because each pattern's budget was
    smaller than ``len(FEEDBACK_PAYLOADS)``. Both framings must now
    surface across the generated variants — proven by the
    ``framing`` metadata each variant carries.
    """
    framings_seen: set[str] = set()
    for variant in c11_tool_result_rag_feedback.factory(seed_value=42).generate():
        params = variant.metadata.get("params") or {}
        framing = params.get("framing") if isinstance(params, dict) else None
        if isinstance(framing, str):
            framings_seen.add(framing)
    assert framings_seen == {"json_directive", "plaintext_directive"}, (
        f"missing framings: {{'json_directive','plaintext_directive'}} - {framings_seen}"
    )
