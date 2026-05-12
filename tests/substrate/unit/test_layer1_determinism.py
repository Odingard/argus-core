"""Layer-1 determinism + variant-count regression tests."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import classes_in_layer

LAYER1_TARGETS = {
    "tp-protocol-exploit": 400,
    "tp-schema-shadowing": 1500,
    "tp-dependency-injection": 500,
    "tp-resource-stego": 400,
    "tp-description-stego": 300,
    "tp-name-collision": 400,
    "tp-return-value": 400,
    "tp-parameter-binding": 300,
    "tp-confused-deputy": 300,
    "tp-auth-bypass": 200,
    "tp-prompt-resource": 150,
    "tp-echo-poisoning": 150,
    "tp-credential-exercise": 250,
    "tp-mcp-supply-chain": 250,
}


def test_all_layer1_classes_registered() -> None:
    classes = list(classes_in_layer("layer1_tool_poisoning"))
    ids = {c.class_id for c in classes}
    assert ids == set(LAYER1_TARGETS), f"missing or extra classes: {ids ^ LAYER1_TARGETS.keys()}"


def test_layer1_variant_counts_meet_targets() -> None:
    for cls in classes_in_layer("layer1_tool_poisoning"):
        target = LAYER1_TARGETS[cls.class_id]
        produced = sum(1 for _ in cls.factory(seed_value=42).generate())
        # Allow ±5 % slack for cartesian-product ceilings; total must hit 5,000.
        assert produced >= int(target * 0.93), f"{cls.class_id} produced={produced} target={target}"


def test_layer1_total_variants_at_5000() -> None:
    total = sum(
        sum(1 for _ in cls.factory(seed_value=42).generate()) for cls in classes_in_layer("layer1_tool_poisoning")
    )
    assert total >= 5_000, f"layer1 total={total} below 5,000 target"


def test_layer1_determinism_same_seed() -> None:
    for cls in classes_in_layer("layer1_tool_poisoning"):
        a = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        b = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert a == b, f"{cls.class_id} non-deterministic across two runs with seed=42"


def test_layer1_seed_sensitivity() -> None:
    """At least half the classes should diverge across different seeds."""
    diverged = 0
    total = 0
    for cls in classes_in_layer("layer1_tool_poisoning"):
        a = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        c = [v.variant_id for v in cls.factory(seed_value=43).generate()]
        if a != c:
            diverged += 1
        total += 1
    assert diverged >= total // 2, f"only {diverged}/{total} seed-sensitive"


def test_layer1_variant_ids_unique_within_class() -> None:
    for cls in classes_in_layer("layer1_tool_poisoning"):
        ids = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert len(ids) == len(set(ids)), f"{cls.class_id} has duplicate variant_ids"


def test_layer1_canaries_present_when_required() -> None:
    """Every Layer-1 variant carrying a canary echo matcher must have a canary."""
    for cls in classes_in_layer("layer1_tool_poisoning"):
        for variant in cls.factory(seed_value=42).generate():
            if "canary_echo" in variant.matcher_ids:
                assert variant.canaries is not None, (
                    f"{cls.class_id}/{variant.variant_id} declares canary_echo matcher without canary set"
                )
                assert variant.canaries.primary, "canary primary is empty"
