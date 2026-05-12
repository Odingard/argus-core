"""Layer-4 strategy-roster regression tests.

Regression invariant: every Layer-4 attack class must appear in
``probing ∪ pivot``. Exploitation alone is not sufficient because the
exploitation phase only runs once ``best_global_score`` crosses
``EXPLOITATION_THRESHOLD`` (0.5), which never happens on hardened
targets where every class lands 0%. Same-shape regression as the
Layer-3 PR #9 fix that added c04 + c08 to pivot.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import classes_in_layer
from argus.engine.runtime.strategy import StrategyNavigator

LAYER4_CLASSES = {
    "ext-system-prompt-leak",
    "ext-tool-schema-leak",
    "ext-rag-corpus-leak",
    "ext-training-data-regurgitation",
    "ext-side-channel-introspection",
    "ext-auth-boundary-leak",
    "ext-credential-leak",
}


def _roster() -> dict[str, tuple[str, ...]]:
    return StrategyNavigator._LAYER_ROSTERS["layer4_extraction"]


def test_layer4_roster_present() -> None:
    assert "layer4_extraction" in StrategyNavigator._LAYER_ROSTERS, (
        "layer4_extraction missing from StrategyNavigator._LAYER_ROSTERS"
    )


def test_layer4_probing_pivot_union_covers_all_classes() -> None:
    roster = _roster()
    union = set(roster.get("probing", ())) | set(roster.get("pivot", ()))
    missing = LAYER4_CLASSES - union
    assert not missing, (
        f"layer4 classes missing from (probing ∪ pivot): {sorted(missing)}. "
        "Exploitation-only placement is insufficient on hardened targets."
    )


def test_layer4_exploitation_covers_all_classes() -> None:
    roster = _roster()
    exploitation = set(roster.get("exploitation", ()))
    missing = LAYER4_CLASSES - exploitation
    assert not missing, f"layer4 classes missing from exploitation: {sorted(missing)}"


def test_layer4_roster_only_references_registered_classes() -> None:
    registered = {c.class_id for c in classes_in_layer("layer4_extraction")}
    roster = _roster()
    for slot, names in roster.items():
        for name in names:
            assert name in registered, f"layer4 roster slot={slot} references unregistered class {name!r}"


def test_layer4_probing_and_pivot_nonempty() -> None:
    roster = _roster()
    assert roster.get("probing"), "layer4 probing roster is empty"
    assert roster.get("pivot"), "layer4 pivot roster is empty"
