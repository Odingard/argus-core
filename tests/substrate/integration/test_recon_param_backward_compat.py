"""Backward-compatibility tests for recon-param.

Hard contract: when ``recon=None`` (or omitted), every class must produce
a bit-identical variant set to the pre-upgrade head. This is the gate
that lets us ship recon-param without breaking the existing 215 tests.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.registry import all_classes


def _ids(generator) -> list[str]:
    return [v.variant_id for v in generator.generate()]


def test_no_recon_kwarg_matches_explicit_none_for_recon_aware_classes():
    """Calling factory without ``recon`` must equal calling with ``recon=None``."""
    for cls in all_classes():
        if not cls.recon_aware:
            continue
        baseline = _ids(cls.factory(seed_value=42))
        explicit = _ids(cls.factory(seed_value=42, recon=None))
        assert baseline == explicit, f"{cls.class_id}: recon=None diverges from omitted recon kwarg"


def test_empty_recon_profile_is_noop_across_all_recon_aware_classes():
    """An ``is_empty()`` profile must be a strict no-op (no variant_id changes)."""
    empty = ReconProfile.empty()
    assert empty.is_empty()
    for cls in all_classes():
        if not cls.recon_aware:
            continue
        baseline = _ids(cls.factory(seed_value=42))
        with_empty = _ids(cls.factory(seed_value=42, recon=empty))
        assert baseline == with_empty, f"{cls.class_id}: empty ReconProfile altered variant set"


def test_non_recon_aware_classes_still_callable_without_kwarg():
    """Non-adopting classes (~30 of 40) must remain callable as before."""
    for cls in all_classes():
        if cls.recon_aware:
            continue
        ids = _ids(cls.factory(seed_value=42))
        assert ids, f"{cls.class_id} produced no variants"


def test_recon_aware_count_matches_adoption_matrix():
    """Adoption gate: exactly 15 classes are recon_aware.

    Phase E's ``tp-credential-exercise`` joined the recon-aware roster
    because its tool-call rendering substitutes harvested
    ``leaked_credentials`` and ``tool_names`` into the exercise step.

    Phase K adds three MCP-specific depth classes that consume new
    recon slots: ``tp-mcp-supply-chain`` (manifest hashes / tool names),
    ``mas-a2a-token-replay`` (agent cards / delegation endpoints / A2A
    token format), and ``ci-tool-result-rag-feedback`` (memory writers /
    RAG endpoints / citation format).
    """
    aware = [c.class_id for c in all_classes() if c.recon_aware]
    expected = {
        "tp-protocol-exploit",
        "tp-schema-shadowing",
        "tp-resource-stego",
        "tp-credential-exercise",
        "tp-mcp-supply-chain",
        "ci-rag-direct-poisoning",
        "ci-tool-result-rag-feedback",
        "cog-counterfactual-priming",
        "cog-self-consistency-exploit",
        "ext-system-prompt-leak",
        "ext-tool-schema-leak",
        "ext-credential-leak",
        "mas-handoff-hijack",
        "mas-trust-pivot",
        "mas-a2a-token-replay",
    }
    assert set(aware) == expected, f"adoption mismatch: {set(aware) ^ expected}"
