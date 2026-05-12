"""Layer-5 strategy-roster regression tests.

Regression invariant: every Layer-5 attack class must appear in
``probing ∪ pivot``. Exploitation alone is not sufficient because the
exploitation phase only runs once ``best_global_score`` crosses
``EXPLOITATION_THRESHOLD`` (0.5), which never happens on hardened
multi-agent targets where every class lands 0%. Same-shape regression
as the Layer-3 PR #9 fix (c04 + c08 added to pivot) and the Layer-4
PR #11 roster.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import classes_in_layer
from argus.engine.runtime.strategy import StrategyNavigator

LAYER5_CLASSES = {
    "mas-handoff-hijack",
    "mas-supervisor-override",
    "mas-second-order-injection",
    "mas-trust-pivot",
    "mas-sandbox-escape",
}


def _roster() -> dict[str, tuple[str, ...]]:
    return StrategyNavigator._LAYER_ROSTERS["layer5_orchestration"]


def test_layer5_roster_present() -> None:
    assert "layer5_orchestration" in StrategyNavigator._LAYER_ROSTERS, (
        "layer5_orchestration missing from StrategyNavigator._LAYER_ROSTERS"
    )


def test_layer5_probing_pivot_union_covers_all_classes() -> None:
    roster = _roster()
    union = set(roster.get("probing", ())) | set(roster.get("pivot", ()))
    missing = LAYER5_CLASSES - union
    assert not missing, (
        f"layer5 classes missing from (probing ∪ pivot): {sorted(missing)}. "
        "Exploitation-only placement is insufficient on hardened targets."
    )


def test_layer5_exploitation_covers_all_classes() -> None:
    roster = _roster()
    exploitation = set(roster.get("exploitation", ()))
    missing = LAYER5_CLASSES - exploitation
    assert not missing, f"layer5 classes missing from exploitation: {sorted(missing)}"


def test_layer5_roster_only_references_registered_classes() -> None:
    registered = {c.class_id for c in classes_in_layer("layer5_orchestration")}
    roster = _roster()
    for slot, names in roster.items():
        for name in names:
            assert name in registered, f"layer5 roster slot={slot} references unregistered class {name!r}"


def test_layer5_probing_and_pivot_nonempty() -> None:
    roster = _roster()
    assert roster.get("probing"), "layer5 probing roster is empty"
    assert roster.get("pivot"), "layer5 pivot roster is empty"
