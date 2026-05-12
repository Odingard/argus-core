"""Layer-2 determinism + variant-count regression tests."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import classes_in_layer

LAYER2_TARGETS = {
    "ci-multi-token-delimiter": 1000,
    "ci-cross-prompt-scripting": 500,
    "ci-rag-semantic-desensitization": 1200,
    "ci-indirect-payload-splitting": 300,
    "ci-schema-level-pi": 250,
    "ci-rag-direct-poisoning": 250,
    "ci-rag-embedding-drift": 150,
    "ci-context-window-stuffing": 150,
    "ci-conversation-history-forgery": 100,
    "ci-inline-tool-result-injection": 100,
    "ci-tool-result-rag-feedback": 150,
}


def test_all_layer2_classes_registered() -> None:
    classes = list(classes_in_layer("layer2_contextual_injection"))
    ids = {c.class_id for c in classes}
    assert ids == set(LAYER2_TARGETS), f"missing or extra classes: {ids ^ LAYER2_TARGETS.keys()}"


def test_layer2_variant_counts_meet_targets() -> None:
    for cls in classes_in_layer("layer2_contextual_injection"):
        target = LAYER2_TARGETS[cls.class_id]
        produced = sum(1 for _ in cls.factory(seed_value=42).generate())
        # Allow ±7% slack on small classes; classes must clear their floor.
        floor = int(target * 0.93)
        assert produced >= floor, f"{cls.class_id} produced={produced} target={target}"


def test_layer2_total_variants_at_4000() -> None:
    total = sum(
        sum(1 for _ in cls.factory(seed_value=42).generate()) for cls in classes_in_layer("layer2_contextual_injection")
    )
    assert total >= 4_000, f"layer2 total={total} below 4,000 target"


def test_layer2_determinism_same_seed() -> None:
    for cls in classes_in_layer("layer2_contextual_injection"):
        a = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        b = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert a == b, f"{cls.class_id} non-deterministic across two runs with seed=42"


def test_layer2_seed_sensitivity() -> None:
    """At least half the classes should diverge across different seeds."""
    diverged = 0
    total = 0
    for cls in classes_in_layer("layer2_contextual_injection"):
        a = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        c = [v.variant_id for v in cls.factory(seed_value=43).generate()]
        if a != c:
            diverged += 1
        total += 1
    assert diverged >= total // 2, f"only {diverged}/{total} seed-sensitive"


def test_layer2_variant_ids_unique_within_class() -> None:
    for cls in classes_in_layer("layer2_contextual_injection"):
        ids = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert len(ids) == len(set(ids)), f"{cls.class_id} has duplicate variant_ids"


def test_layer2_canaries_present_when_required() -> None:
    for cls in classes_in_layer("layer2_contextual_injection"):
        for variant in cls.factory(seed_value=42).generate():
            if "canary-echo" in variant.matcher_ids:
                assert variant.canaries is not None, (
                    f"{cls.class_id}/{variant.variant_id} declares canary-echo matcher without canary set"
                )
                assert variant.canaries.primary, "canary primary is empty"


def test_layer2_canary_substituted_in_output() -> None:
    """No raw `{canary}` placeholders should leak through render."""
    for cls in classes_in_layer("layer2_contextual_injection"):
        for variant in cls.factory(seed_value=42).generate():
            for msg in variant.messages:
                assert "{canary}" not in msg.content, (
                    f"{cls.class_id}/{variant.variant_id} leaked literal {{canary}} placeholder into message content"
                )
            for doc in variant.rag_corpus:
                assert "{canary}" not in doc, (
                    f"{cls.class_id}/{variant.variant_id} leaked literal {{canary}} placeholder into rag_corpus"
                )


def test_layer2_rag_classes_have_corpus() -> None:
    """Classes that target the rag surface must produce non-empty corpora."""
    rag_classes = {
        "ci-rag-semantic-desensitization",
        "ci-rag-direct-poisoning",
        "ci-rag-embedding-drift",
    }
    for cls in classes_in_layer("layer2_contextual_injection"):
        if cls.class_id not in rag_classes:
            continue
        for variant in cls.factory(seed_value=42).generate():
            assert variant.rag_corpus, (
                f"{cls.class_id}/{variant.variant_id} declares RAG target surface but produced empty rag_corpus"
            )
