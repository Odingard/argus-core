"""Tests for c14 — tp-mcp-supply-chain (Phase K)."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.registry import get
from argus.engine.layers.layer1_tool_poisoning import c14_mcp_supply_chain


def test_mcp_supply_chain_registered() -> None:
    cls = get("tp-mcp-supply-chain")
    assert cls.layer == "layer1_tool_poisoning"
    assert cls.target_variants == 250
    assert cls.recon_aware is True
    assert cls.target_surface == frozenset({"tool", "mcp"})


def test_mcp_supply_chain_variant_count() -> None:
    gen = c14_mcp_supply_chain.factory(seed_value=42)
    variants = list(gen.generate())
    assert len(variants) == 250


def test_mcp_supply_chain_deterministic_same_seed() -> None:
    a = list(c14_mcp_supply_chain.factory(seed_value=42).generate())
    b = list(c14_mcp_supply_chain.factory(seed_value=42).generate())
    assert [v.variant_id for v in a] == [v.variant_id for v in b]


def test_mcp_supply_chain_seed_sensitivity() -> None:
    a = list(c14_mcp_supply_chain.factory(seed_value=42).generate())
    c = list(c14_mcp_supply_chain.factory(seed_value=43).generate())
    assert [v.variant_id for v in a] != [v.variant_id for v in c]


def test_mcp_supply_chain_unique_variant_ids() -> None:
    variants = list(c14_mcp_supply_chain.factory(seed_value=42).generate())
    ids = [v.variant_id for v in variants]
    assert len(set(ids)) == len(ids), "variant ids must be unique"


def test_mcp_supply_chain_canary_present() -> None:
    """Every variant must carry a canary for the canary-echo matcher."""
    for variant in c14_mcp_supply_chain.factory(seed_value=42).generate():
        assert "canary-echo" in variant.matcher_ids
        assert variant.canaries is not None
        assert variant.canaries.primary, "canary primary is empty"


def test_mcp_supply_chain_canary_in_payload() -> None:
    """The canary token must appear in the variant body — the IRREFUTABLE
    signal: a tool argument that bypassed manifest-hash integrity.
    """
    for variant in c14_mcp_supply_chain.factory(seed_value=42).generate():
        body = " ".join(m.content for m in variant.messages if m.content)
        assert variant.canaries is not None
        assert variant.canaries.primary in body, f"variant {variant.variant_id} missing canary in user message"


def test_mcp_supply_chain_carries_tool_schema() -> None:
    """Every variant carries the tool stub the attacker plants — the
    schema that doesn't match the advertised manifest hash.
    """
    for variant in c14_mcp_supply_chain.factory(seed_value=42).generate():
        assert variant.tools is not None and len(variant.tools) >= 1, f"{variant.variant_id} missing tool schema"


def test_mcp_supply_chain_credential_shape_matcher_enabled() -> None:
    """Stale-cache / transitive-hijack patterns can exfil credentials,
    so the credential-shape matcher must be enabled for HIGH-tier
    landings even without canary echo.
    """
    cls = get("tp-mcp-supply-chain")
    sample = next(cls.factory(seed_value=42).generate())
    assert "credential-shape" in sample.matcher_ids


def test_mcp_supply_chain_recon_tool_name_substitution() -> None:
    """When recon supplies tool_names, the rendered tool stub uses one
    of those names instead of the static defaults — proves the
    recon-aware substitution path actually fires.
    """
    profile = ReconProfile(
        tool_names=("billing_charge", "database_query", "send_email"),
    )
    gen = c14_mcp_supply_chain.factory(seed_value=42, recon=profile)
    rendered_names = set()
    for variant in gen.generate():
        if variant.tools:
            rendered_names.add(variant.tools[0].name)
    assert rendered_names & {
        "billing_charge",
        "database_query",
        "send_email",
    }, f"recon tool names did not propagate (saw {rendered_names})"


def test_mcp_supply_chain_recon_manifest_hash_substitution() -> None:
    """When recon supplies manifest_hashes, those values must appear in
    at least one rendered variant body — proves the manifest-drift
    pattern actually consumes the recon slot.
    """
    profile = ReconProfile(
        manifest_hashes=("sha256:deadbeefcafe", "sha256:facefeed0042"),
    )
    gen = c14_mcp_supply_chain.factory(seed_value=42, recon=profile)
    bodies = []
    for variant in gen.generate():
        bodies.append(" ".join(m.content for m in variant.messages if m.content))
    combined = " ".join(bodies)
    assert "sha256:deadbeefcafe" in combined or "sha256:facefeed0042" in combined, (
        "recon manifest hashes did not propagate into any variant body"
    )


def test_mcp_supply_chain_recon_empty_fallback_baseline() -> None:
    """With an empty recon profile, the class still yields the full
    target_variants — proves the baseline arm is always available
    (no silent failure per rule #9).
    """
    gen = c14_mcp_supply_chain.factory(seed_value=42, recon=ReconProfile.empty())
    variants = list(gen.generate())
    assert len(variants) == 250


def test_mcp_supply_chain_variant_messages_nonempty() -> None:
    """No variant may render an empty user message — rule #9
    (no silent failures): every emitted variant must be fireable.
    """
    for variant in c14_mcp_supply_chain.factory(seed_value=42).generate():
        body = " ".join(m.content for m in variant.messages if m.content)
        assert body.strip(), f"variant {variant.variant_id} has empty body"
