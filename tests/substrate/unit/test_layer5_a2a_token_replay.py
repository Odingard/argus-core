"""Tests for o06 — mas-a2a-token-replay (Phase K)."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.registry import get
from argus.engine.layers.layer5_orchestration import o06_a2a_token_replay


def test_a2a_token_replay_registered() -> None:
    cls = get("mas-a2a-token-replay")
    assert cls.layer == "layer5_orchestration"
    assert cls.target_variants == 200
    assert cls.recon_aware is True
    assert cls.target_surface == frozenset({"chat", "tool", "mcp"})


def test_a2a_token_replay_variant_count() -> None:
    gen = o06_a2a_token_replay.factory(seed_value=42)
    variants = list(gen.generate())
    assert len(variants) == 200


def test_a2a_token_replay_deterministic_same_seed() -> None:
    a = list(o06_a2a_token_replay.factory(seed_value=42).generate())
    b = list(o06_a2a_token_replay.factory(seed_value=42).generate())
    assert [v.variant_id for v in a] == [v.variant_id for v in b]


def test_a2a_token_replay_seed_sensitivity() -> None:
    a = list(o06_a2a_token_replay.factory(seed_value=42).generate())
    c = list(o06_a2a_token_replay.factory(seed_value=43).generate())
    assert [v.variant_id for v in a] != [v.variant_id for v in c]


def test_a2a_token_replay_unique_variant_ids() -> None:
    variants = list(o06_a2a_token_replay.factory(seed_value=42).generate())
    ids = [v.variant_id for v in variants]
    assert len(set(ids)) == len(ids), "variant ids must be unique"


def test_a2a_token_replay_canary_present() -> None:
    """Every variant must carry a canary for the canary-echo matcher."""
    for variant in o06_a2a_token_replay.factory(seed_value=42).generate():
        assert "canary-echo" in variant.matcher_ids
        assert variant.canaries is not None
        assert variant.canaries.primary, "canary primary is empty"


def test_a2a_token_replay_canary_in_payload() -> None:
    """The canary must appear in the variant body — IRREFUTABLE signal
    when the downstream agent calls a tool with a token-bound canary
    it was never authorised to know.
    """
    for variant in o06_a2a_token_replay.factory(seed_value=42).generate():
        body = " ".join(m.content for m in variant.messages if m.content)
        assert variant.canaries is not None
        assert variant.canaries.primary in body, f"variant {variant.variant_id} missing canary in user message"


def test_a2a_token_replay_state_machine_matcher_enabled() -> None:
    """L5 attacks must enable the state-machine matcher so cross-tenant
    / cross-card forbidden-state transitions land as HIGH even without
    canary echo.
    """
    cls = get("mas-a2a-token-replay")
    sample = next(cls.factory(seed_value=42).generate())
    assert "state-machine" in sample.matcher_ids
    assert "credential-shape" in sample.matcher_ids


def test_a2a_token_replay_carries_tool_schema() -> None:
    """Every variant must carry a tool stub — the A2A endpoint the
    attacker plants to test token-binding enforcement.
    """
    for variant in o06_a2a_token_replay.factory(seed_value=42).generate():
        assert variant.tools is not None and len(variant.tools) >= 1, f"{variant.variant_id} missing tool schema"


def test_a2a_token_replay_recon_agent_card_substitution() -> None:
    """When recon supplies agent_cards, those values must appear in at
    least one rendered variant body — proves the agent-card-spoof
    pattern consumes the recon slot.
    """
    profile = ReconProfile(
        agent_cards=("card-finance-ops", "card-billing-admin"),
    )
    gen = o06_a2a_token_replay.factory(seed_value=42, recon=profile)
    bodies = []
    for variant in gen.generate():
        bodies.append(" ".join(m.content for m in variant.messages if m.content))
    combined = " ".join(bodies)
    assert "card-finance-ops" in combined or "card-billing-admin" in combined, (
        "recon agent_cards did not propagate into any variant body"
    )


def test_a2a_token_replay_recon_delegation_endpoint_substitution() -> None:
    """When recon supplies delegation_endpoints, those must appear in
    at least one variant — proves delegation-depth / confused-deputy
    patterns consume the recon slot.
    """
    profile = ReconProfile(
        delegation_endpoints=("delegate_run_finance", "delegate_invoke_admin"),
    )
    gen = o06_a2a_token_replay.factory(seed_value=42, recon=profile)
    bodies = []
    for variant in gen.generate():
        bodies.append(" ".join(m.content for m in variant.messages if m.content))
    combined = " ".join(bodies)
    assert "delegate_run_finance" in combined or "delegate_invoke_admin" in combined, (
        "recon delegation_endpoints did not propagate into any variant body"
    )


def test_a2a_token_replay_recon_empty_fallback_baseline() -> None:
    """With an empty recon profile, the class still yields the full
    target_variants — baseline arm always available (rule #9).
    """
    gen = o06_a2a_token_replay.factory(seed_value=42, recon=ReconProfile.empty())
    variants = list(gen.generate())
    assert len(variants) == 200


def test_a2a_token_replay_variant_messages_nonempty() -> None:
    """No variant may render an empty user message — rule #9
    (no silent failures): every emitted variant must be fireable.
    """
    for variant in o06_a2a_token_replay.factory(seed_value=42).generate():
        body = " ".join(m.content for m in variant.messages if m.content)
        assert body.strip(), f"variant {variant.variant_id} has empty body"
