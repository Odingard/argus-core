"""Layer-5 determinism + variant-count regression tests."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.mutator import MultiAgentEnvelopeMutator
from argus.engine.core.registry import classes_in_layer

LAYER5_TARGETS = {
    "mas-handoff-hijack": 350,
    "mas-supervisor-override": 300,
    "mas-second-order-injection": 300,
    "mas-trust-pivot": 250,
    "mas-sandbox-escape": 300,
    "mas-a2a-token-replay": 200,
}


def test_all_layer5_classes_registered() -> None:
    classes = list(classes_in_layer("layer5_orchestration"))
    ids = {c.class_id for c in classes}
    assert ids == set(LAYER5_TARGETS), f"missing or extra classes: {ids ^ LAYER5_TARGETS.keys()}"


def test_layer5_variant_counts_meet_targets() -> None:
    for cls in classes_in_layer("layer5_orchestration"):
        target = LAYER5_TARGETS[cls.class_id]
        produced = sum(1 for _ in cls.factory(seed_value=42).generate())
        floor = int(target * 0.93)
        assert produced >= floor, f"{cls.class_id} produced={produced} target={target}"


def test_layer5_total_variants_at_1200() -> None:
    total = sum(
        sum(1 for _ in cls.factory(seed_value=42).generate()) for cls in classes_in_layer("layer5_orchestration")
    )
    assert total >= 1_500, f"layer5 total={total} below 1,500 target"


def test_layer5_determinism_same_seed() -> None:
    for cls in classes_in_layer("layer5_orchestration"):
        a = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        b = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert a == b, f"{cls.class_id} non-deterministic across two runs with seed=42"


def test_layer5_variant_ids_unique_within_class() -> None:
    for cls in classes_in_layer("layer5_orchestration"):
        ids = [v.variant_id for v in cls.factory(seed_value=42).generate()]
        assert len(ids) == len(set(ids)), f"{cls.class_id} has duplicate variant_ids"


def test_layer5_canaries_present_when_required() -> None:
    for cls in classes_in_layer("layer5_orchestration"):
        for variant in cls.factory(seed_value=42).generate():
            if "canary-echo" in variant.matcher_ids:
                assert variant.canaries is not None, (
                    f"{cls.class_id}/{variant.variant_id} declares canary-echo matcher without canary set"
                )
                assert variant.canaries.primary, "canary primary is empty"


def test_layer5_canary_substituted_in_output() -> None:
    """No raw `{canary}` placeholders should leak through render."""
    for cls in classes_in_layer("layer5_orchestration"):
        for variant in cls.factory(seed_value=42).generate():
            for msg in variant.messages:
                assert "{canary}" not in msg.content, (
                    f"{cls.class_id}/{variant.variant_id} leaked literal {{canary}} placeholder into message content"
                )
            for tool in variant.tools:
                assert "{canary}" not in tool.description, (
                    f"{cls.class_id}/{variant.variant_id} leaked literal {{canary}} placeholder into tool description"
                )
            for resource in variant.resources:
                assert "{canary}" not in resource.description, (
                    f"{cls.class_id}/{variant.variant_id} leaked literal "
                    "{canary} placeholder into resource description"
                )
            for doc in variant.rag_corpus:
                assert "{canary}" not in str(doc), (
                    f"{cls.class_id}/{variant.variant_id} leaked literal {{canary}} placeholder into rag corpus"
                )


def test_layer5_canary_present_in_carrier_surface() -> None:
    """Canary value should appear inside at least one carrier surface
    (message body, tool description, resource description, or rag
    corpus). Layer 5's o03 second-order-injection class plants on
    non-message surfaces, so we cannot insist the canary lives in
    message content alone."""
    for cls in classes_in_layer("layer5_orchestration"):
        for variant in cls.factory(seed_value=42).generate():
            if variant.canaries is None:
                continue
            primary = variant.canaries.primary
            joined = "\n".join(m.content for m in variant.messages)
            joined += "\n" + "\n".join(t.description for t in variant.tools)
            joined += "\n" + "\n".join(r.description for r in variant.resources)
            joined += "\n" + "\n".join(str(d) for d in variant.rag_corpus)
            assert primary in joined, (
                f"{cls.class_id}/{variant.variant_id} canary {primary} not present in any rendered surface"
            )


def test_layer5_classes_declare_orchestration_surface() -> None:
    for cls in classes_in_layer("layer5_orchestration"):
        surface = cls.target_surface
        assert surface & {"chat", "tool", "rag", "mcp"}, (
            f"{cls.class_id} must declare at least one orchestration-relevant surface"
        )


def test_layer5_classes_carry_structural_matcher() -> None:
    """Layer-5 findings rely on structural regex backup beyond canary echo."""
    for cls in classes_in_layer("layer5_orchestration"):
        sample = next(iter(cls.factory(seed_value=42).generate()))
        assert "structural" in sample.matcher_ids, (
            f"{cls.class_id} should attach structural matcher (HIGH-tier fallback) alongside canary-echo"
        )


def test_layer5_seed_value_alters_canary_only() -> None:
    """Different seed values produce different canaries but identical message
    structure (mutator stack is canary-independent)."""
    for cls in classes_in_layer("layer5_orchestration"):
        a = list(cls.factory(seed_value=1).generate())
        b = list(cls.factory(seed_value=2).generate())
        assert len(a) == len(b), f"{cls.class_id} variant count drifted with seed"
        for va, vb in zip(a, b):
            assert va.canaries.primary != vb.canaries.primary, f"{cls.class_id}: canary should depend on seed_value"


def test_multi_agent_envelope_mutator_protocol_compliance() -> None:
    """Layer 5 introduces a new universal mutator. Confirm it implements
    the Mutator protocol shape (name + mutate signature) and produces
    the canonical 5 envelope styles by default."""
    mut = MultiAgentEnvelopeMutator()
    assert mut.name == "multi_agent_envelope"

    from random import Random

    from argus.engine.core.seed import Seed

    seed = Seed(
        seed_id="probe",
        attack_class="mas-trust-pivot",
        layer="layer5_orchestration",
        version=1,
        template="{canary}",
        target_surface=frozenset({"chat"}),
        meta={"authority": "supervisor", "payload": "probe payload"},
    )
    outputs = list(mut.mutate(seed, Random(0)))
    assert len(outputs) == 5, f"expected 5 envelope styles, got {len(outputs)}"
    style_names = {params["envelope_style"] for _, _, params in outputs}
    assert style_names == {
        "json_envelope",
        "prefix_marker",
        "structural_tag",
        "citation",
        "nested_quote",
    }, f"unexpected envelope styles: {style_names}"
