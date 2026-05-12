"""Layer-3 determinism + variant-count regression tests."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import classes_in_layer

LAYER3_TARGETS = {
    "cog-chain-of-thought-hijack": 400,
    "cog-reasoning-step-injection": 400,
    "cog-self-consistency-exploit": 360,
    "cog-logical-fallacy-amplifier": 400,
    "cog-counterfactual-priming": 360,
    "cog-meta-reasoning-bypass": 360,
    "cog-analogical-substitution": 360,
    "cog-recursive-decomposition": 360,
    # Phase S — 4 new structurally-different cognitive shapes.
    "cog-epistemic-confidence-drain": 200,
    "cog-authority-laundering": 200,
    "cog-socratic-extraction": 240,
    "cog-benign-pretext-switch": 240,
}


def test_all_layer3_classes_registered() -> None:
    classes = list(classes_in_layer("layer3_cognitive"))
    ids = {c.class_id for c in classes}
    assert ids == set(LAYER3_TARGETS), f"missing or extra classes: {ids ^ LAYER3_TARGETS.keys()}"


def test_layer3_variant_counts_meet_targets() -> None:
    for cls in classes_in_layer("layer3_cognitive"):
        target = LAYER3_TARGETS[cls.class_id]
        produced = sum(1 for _ in cls.factory(seed_value=42).generate())
        floor = int(target * 0.93)
        assert produced >= floor, f"{cls.class_id} produced={produced} target={target}"


def test_layer3_total_variants_at_3000() -> None:
    total = sum(sum(1 for _ in cls.factory(seed_value=42).generate()) for cls in classes_in_layer("layer3_cognitive"))
    # Phase S raised the L3 floor to 3,880 (8 pre-Phase-S × ~360 +
    # 4 Phase S × 200/240). Keep the existing 3,000 floor honoured.
    assert total >= 3_000, f"layer3 total={total} below 3,000 target"


def test_layer3_determinism_same_seed() -> None:
    for cls in classes_in_layer("layer3_cognitive"):
        a = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        b = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert a == b, f"{cls.class_id} non-deterministic across two runs with seed=42"


def test_layer3_variant_ids_unique_within_class() -> None:
    for cls in classes_in_layer("layer3_cognitive"):
        ids = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert len(ids) == len(set(ids)), f"{cls.class_id} has duplicate variant_ids"


def test_layer3_canaries_present_when_required() -> None:
    for cls in classes_in_layer("layer3_cognitive"):
        for variant in cls.factory(seed_value=42).generate():
            if "canary-echo" in variant.matcher_ids:
                assert variant.canaries is not None, (
                    f"{cls.class_id}/{variant.variant_id} declares canary-echo matcher without canary set"
                )
                assert variant.canaries.primary, "canary primary is empty"


def test_layer3_canary_substituted_in_output() -> None:
    """No raw `{canary}` placeholders should leak through render."""
    for cls in classes_in_layer("layer3_cognitive"):
        for variant in cls.factory(seed_value=42).generate():
            for msg in variant.messages:
                assert "{canary}" not in msg.content, (
                    f"{cls.class_id}/{variant.variant_id} leaked literal {{canary}} placeholder into message content"
                )


def test_layer3_canary_present_in_message_content() -> None:
    """Canary value should appear inside at least one rendered message."""
    for cls in classes_in_layer("layer3_cognitive"):
        for variant in cls.factory(seed_value=42).generate():
            if variant.canaries is None:
                continue
            primary = variant.canaries.primary
            joined = "\n".join(m.content for m in variant.messages)
            assert primary in joined, (
                f"{cls.class_id}/{variant.variant_id} canary {primary} not present in rendered messages"
            )


def test_layer3_classes_target_chat_surface() -> None:
    for cls in classes_in_layer("layer3_cognitive"):
        assert "chat" in cls.target_surface, f"{cls.class_id} must declare chat surface (cognitive layer is chat-only)"
