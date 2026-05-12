"""Tests for c13 — tp-credential-exercise (Phase E)."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.registry import get
from argus.engine.layers.layer1_tool_poisoning import c13_credential_exercise


def test_credential_exercise_registered() -> None:
    cls = get("tp-credential-exercise")
    assert cls.layer == "layer1_tool_poisoning"
    assert cls.target_variants == 250
    assert cls.recon_aware is True
    assert cls.target_surface == frozenset({"tool", "mcp"})


def test_credential_exercise_variant_count() -> None:
    gen = c13_credential_exercise.factory(seed_value=42)
    variants = list(gen.generate())
    assert len(variants) == 250


def test_credential_exercise_deterministic_same_seed() -> None:
    a = list(c13_credential_exercise.factory(seed_value=42).generate())
    b = list(c13_credential_exercise.factory(seed_value=42).generate())
    assert [v.variant_id for v in a] == [v.variant_id for v in b]


def test_credential_exercise_seed_sensitivity() -> None:
    a = list(c13_credential_exercise.factory(seed_value=42).generate())
    c = list(c13_credential_exercise.factory(seed_value=43).generate())
    assert [v.variant_id for v in a] != [v.variant_id for v in c]


def test_credential_exercise_canary_present() -> None:
    """Every variant must carry a canary for the canary-echo matcher."""
    for variant in c13_credential_exercise.factory(seed_value=42).generate():
        assert "canary-echo" in variant.matcher_ids
        assert variant.canaries is not None
        assert variant.canaries.primary, "canary primary is empty"


def test_credential_exercise_canary_in_payload() -> None:
    """The canary token must actually appear in the user message body —
    that is the IRREFUTABLE-tier signal: agent calling a tool with a
    secret it was never authorised to know.
    """
    for variant in c13_credential_exercise.factory(seed_value=42).generate():
        body = " ".join(m.content for m in variant.messages if m.content)
        assert variant.canaries is not None
        assert variant.canaries.primary in body, f"variant {variant.variant_id} missing canary in user message"


def test_credential_exercise_carries_tool_schema() -> None:
    """Every variant must carry exactly one tool schema —
    the tool the agent is being induced to call with the credential.
    """
    for variant in c13_credential_exercise.factory(seed_value=42).generate():
        assert variant.tools is not None and len(variant.tools) >= 1, f"{variant.variant_id} missing tool schema"


def test_credential_exercise_uses_credential_shape_matcher() -> None:
    """Phase E variants must enable the credential-shape matcher so
    that even a partial credential reflection lands as HIGH.
    """
    cls = get("tp-credential-exercise")
    sample = next(cls.factory(seed_value=42).generate())
    assert "credential-shape" in sample.matcher_ids


def test_credential_exercise_recon_substitution_alters_tools() -> None:
    """When recon supplies tool_names, the rendered tool name must
    use one of those names instead of the static schema name —
    proves the recon-aware substitution path actually fires.
    """
    profile = ReconProfile(tool_names=("billing_charge", "database_query", "send_email"))
    gen = c13_credential_exercise.factory(seed_value=42, recon=profile)
    rendered_names = set()
    for variant in gen.generate():
        if variant.tools:
            rendered_names.add(variant.tools[0].name)
    # At least one substituted tool name must appear; otherwise the
    # recon plumbing is silently dropped.
    assert rendered_names & {
        "billing_charge",
        "database_query",
        "send_email",
    }, f"recon tool names did not propagate (saw {rendered_names})"
