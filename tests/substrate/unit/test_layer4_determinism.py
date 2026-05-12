"""Layer-4 determinism + variant-count regression tests."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import classes_in_layer

LAYER4_TARGETS = {
    "ext-system-prompt-leak": 400,
    "ext-tool-schema-leak": 350,
    "ext-rag-corpus-leak": 350,
    "ext-training-data-regurgitation": 300,
    "ext-side-channel-introspection": 300,
    "ext-auth-boundary-leak": 300,
    "ext-credential-leak": 200,
    # Phase S — 2 new structurally-different extraction shapes.
    "ext-role-assumption-chain": 200,
    "ext-schema-boundary-confusion": 200,
}


def test_all_layer4_classes_registered() -> None:
    classes = list(classes_in_layer("layer4_extraction"))
    ids = {c.class_id for c in classes}
    assert ids == set(LAYER4_TARGETS), f"missing or extra classes: {ids ^ LAYER4_TARGETS.keys()}"


def test_layer4_variant_counts_meet_targets() -> None:
    for cls in classes_in_layer("layer4_extraction"):
        target = LAYER4_TARGETS[cls.class_id]
        produced = sum(1 for _ in cls.factory(seed_value=42).generate())
        floor = int(target * 0.93)
        assert produced >= floor, f"{cls.class_id} produced={produced} target={target}"


def test_layer4_total_variants_at_2000() -> None:
    total = sum(sum(1 for _ in cls.factory(seed_value=42).generate()) for cls in classes_in_layer("layer4_extraction"))
    assert total >= 2_200, f"layer4 total={total} below 2,200 target"


def test_layer4_determinism_same_seed() -> None:
    for cls in classes_in_layer("layer4_extraction"):
        a = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        b = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert a == b, f"{cls.class_id} non-deterministic across two runs with seed=42"


def test_layer4_variant_ids_unique_within_class() -> None:
    for cls in classes_in_layer("layer4_extraction"):
        ids = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert len(ids) == len(set(ids)), f"{cls.class_id} has duplicate variant_ids"


def test_layer4_canaries_present_when_required() -> None:
    for cls in classes_in_layer("layer4_extraction"):
        for variant in cls.factory(seed_value=42).generate():
            if "canary-echo" in variant.matcher_ids:
                assert variant.canaries is not None, (
                    f"{cls.class_id}/{variant.variant_id} declares canary-echo matcher without canary set"
                )
                assert variant.canaries.primary, "canary primary is empty"


def test_layer4_canary_substituted_in_output() -> None:
    """No raw `{canary}` placeholders should leak through render."""
    for cls in classes_in_layer("layer4_extraction"):
        for variant in cls.factory(seed_value=42).generate():
            for msg in variant.messages:
                assert "{canary}" not in msg.content, (
                    f"{cls.class_id}/{variant.variant_id} leaked literal {{canary}} placeholder into message content"
                )


def test_layer4_canary_present_in_message_content() -> None:
    """Canary value should appear inside at least one rendered message."""
    for cls in classes_in_layer("layer4_extraction"):
        for variant in cls.factory(seed_value=42).generate():
            if variant.canaries is None:
                continue
            primary = variant.canaries.primary
            joined = "\n".join(m.content for m in variant.messages)
            assert primary in joined, (
                f"{cls.class_id}/{variant.variant_id} canary {primary} not present in rendered messages"
            )


def test_layer4_classes_declare_chat_or_tool_surface() -> None:
    for cls in classes_in_layer("layer4_extraction"):
        surface = cls.target_surface
        assert surface & {"chat", "tool", "rag", "mcp"}, (
            f"{cls.class_id} must declare at least one extraction-relevant surface"
        )


def test_layer4_classes_carry_structural_matcher() -> None:
    """Layer-4 findings rely on structural regex backup beyond canary echo."""
    for cls in classes_in_layer("layer4_extraction"):
        sample = next(iter(cls.factory(seed_value=42).generate()))
        assert "structural" in sample.matcher_ids, (
            f"{cls.class_id} should attach structural matcher (HIGH-tier fallback) alongside canary-echo"
        )


def test_layer4_seed_value_alters_canary_only() -> None:
    """Different seed values produce different canaries but identical message
    structure (mutator stack is canary-independent)."""
    import argus.engine.core.registry as r

    for cls in r.classes_in_layer("layer4_extraction"):
        a = list(cls.factory(seed_value=1).generate())
        b = list(cls.factory(seed_value=2).generate())
        assert len(a) == len(b), f"{cls.class_id} variant count drifted with seed"
        # Canary text must differ at every position (canary derived from seed).
        for va, vb in zip(a, b):
            assert va.canaries.primary != vb.canaries.primary, f"{cls.class_id}: canary should depend on seed_value"
