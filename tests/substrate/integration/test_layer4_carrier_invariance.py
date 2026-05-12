"""Layer-4 carrier-invariance integration tests.

Asserts the Layer-4 carrier-agnostic invariant: every Layer-4 variant
must fire (produce a non-empty payload that carries the canary) across
all 3 stub carriers per class. The renamed-carrier test asserts that
the variant still fires after every carrier-specific structural key is
swapped for a synonym — proving the variant is not bound to carrier-
specific keywords (the bench-overfitting failure mode AGENTS.md rule
#1 forbids).

Live-fire landing rates remain gated by AGENTS.md rule #10 — these
stubs only verify well-formed-ness and carrier-agnosticism. André runs
the live scans and supplies JSONL.
"""

from __future__ import annotations

import re

import pytest

import argus.engine  # noqa: F401  -- registers Layer-4 classes
from argus.engine.core.registry import classes_in_layer

from .stubs.layer4_carriers import CARRIERS, renamed

LAYER4_CLASS_IDS = {
    "ext-system-prompt-leak",
    "ext-tool-schema-leak",
    "ext-rag-corpus-leak",
    "ext-training-data-regurgitation",
    "ext-side-channel-introspection",
    "ext-auth-boundary-leak",
}


# Bench-target identifiers and known carrier-private strings that must
# NEVER appear hardcoded in a Layer-4 variant. If any of these appear,
# the seed has been bench-fitted instead of attacking a structural
# invariant — a failure of AGENTS.md rule #1.
FORBIDDEN_BENCH_KEYWORDS = (
    "ARGT-002-25",
    "ARGT-005-25",
    "ARGT-006-25",
    "ARGT-011-25",
    "ARGT-013-25",
    "ARGT-014-25",
    "ARGT-015-25",
    "validation-benchmarks",
    "validation_benchmark",
)


def _variants_for(class_id: str):
    for cls in classes_in_layer("layer4_extraction"):
        if cls.class_id == class_id:
            return list(cls.factory(seed_value=42).generate())
    raise AssertionError(f"class {class_id!r} not registered")


def test_carrier_registry_covers_every_class() -> None:
    assert set(CARRIERS) == LAYER4_CLASS_IDS, f"CARRIERS coverage drift: {set(CARRIERS) ^ LAYER4_CLASS_IDS}"


def test_carrier_registry_three_stubs_per_class() -> None:
    for class_id, fns in CARRIERS.items():
        assert len(fns) == 3, f"{class_id} expects 3 carrier stubs, got {len(fns)}"


@pytest.mark.parametrize("class_id", sorted(LAYER4_CLASS_IDS))
def test_every_variant_fires_on_every_carrier(class_id: str) -> None:
    """Every variant must produce a non-empty payload containing the
    canary on every one of the 3 carrier stubs for its class."""
    carriers = CARRIERS[class_id]
    for variant in _variants_for(class_id):
        canary = variant.canaries.primary
        for fn in carriers:
            payload = fn(variant)
            assert payload, f"{class_id}/{variant.variant_id} produced empty payload on carrier {fn.__name__}"
            assert canary in payload, (
                f"{class_id}/{variant.variant_id} canary {canary!r} missing from carrier {fn.__name__} payload"
            )


@pytest.mark.parametrize("class_id", sorted(LAYER4_CLASS_IDS))
def test_every_variant_fires_under_renamed_carrier(class_id: str) -> None:
    """Renamed-carrier invariant: swapping every carrier-specific
    structural key for a synonym must not change which variants fire.
    Proves the variant attacks the structural invariant, not the
    carrier-specific keyword."""
    carriers = CARRIERS[class_id]
    for variant in _variants_for(class_id):
        canary = variant.canaries.primary
        for fn in carriers:
            renamed_fn = renamed(fn)
            payload = renamed_fn(variant)
            assert payload, (
                f"{class_id}/{variant.variant_id} produced empty payload under renamed carrier {fn.__name__}"
            )
            assert canary in payload, (
                f"{class_id}/{variant.variant_id} canary {canary!r} missing "
                f"from renamed carrier {fn.__name__} — variant likely "
                "depends on a carrier-specific key"
            )


def test_no_variant_hardcodes_bench_keywords() -> None:
    """AGENTS.md rule #1: variants must attack universal invariants.
    None may hardcode bench-target identifiers."""
    needles = re.compile("|".join(re.escape(k) for k in FORBIDDEN_BENCH_KEYWORDS))
    offenders: list[str] = []
    for cls in classes_in_layer("layer4_extraction"):
        for variant in cls.factory(seed_value=42).generate():
            joined = "\n".join(m.content for m in variant.messages)
            for tool in variant.tools:
                joined += "\n" + tool.name + "\n" + tool.description
            for resource in variant.resources:
                joined += "\n" + resource.uri + "\n" + resource.description
            if needles.search(joined):
                offenders.append(f"{cls.class_id}/{variant.variant_id}")
    assert not offenders, (
        f"{len(offenders)} layer-4 variants hardcode bench-target keywords: "
        f"{offenders[:5]}{'…' if len(offenders) > 5 else ''}"
    )


def test_each_class_carriers_produce_distinct_outputs() -> None:
    """The 3 carriers per class must wrap the variant in genuinely
    different shapes — if two carriers produce identical payloads we've
    lost a degree of carrier-coverage."""
    for class_id, fns in CARRIERS.items():
        variant = _variants_for(class_id)[0]
        outputs = {fn.__name__: fn(variant) for fn in fns}
        assert len(set(outputs.values())) == len(fns), (
            f"{class_id}: carrier stubs produced duplicate outputs: {list(outputs)}"
        )
