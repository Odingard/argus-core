"""Layer-2 strategy-roster regression tests.

The first ARGT-002 re-validation against the delimiter-embedded refactor
revealed a structural bug: ``ci-indirect-payload-splitting`` (c04) and
``ci-context-window-stuffing`` (c08) were registered only in the
``pivot`` roster, but the engagement FSM walks
``recon -> probing -> exploitation`` and only enters ``pivot`` when
probing's best score stays below the exploitation threshold. Because
``ci-cross-prompt-scripting`` lands in probing on most targets, the
pivot phase is skipped and c04 / c08 never fire.

After the delimiter-embedding refactor those two classes are
single-transport force multipliers, not last-resort indirect carriers,
so they belong in ``probing`` and ``exploitation`` rosters as well.
This test pins that placement so the regression cannot reappear silently.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.runtime.strategy import StrategyNavigator


def test_layer2_force_multipliers_scheduled_in_probing_and_exploitation() -> None:
    nav = StrategyNavigator(layer="layer2_contextual_injection")
    rosters = nav._LAYER_ROSTERS["layer2_contextual_injection"]
    must_appear = (
        "ci-indirect-payload-splitting",
        "ci-context-window-stuffing",
    )
    for cid in must_appear:
        assert cid in rosters["exploitation"], (
            f"{cid} must be in the exploitation roster — it is a "
            "single-transport delimiter-embedding force multiplier; "
            "limiting it to pivot causes 0 fires when probing succeeds."
        )
    # c08 also belongs in probing because delimiter-wrapped padding is
    # a low-noise probe (cheap to fire, easy to early-stop on no drift).
    assert "ci-context-window-stuffing" in rosters["probing"]


def test_layer2_probing_classes_all_registered() -> None:
    """Every roster entry must be a real attack class id."""
    from argus.engine.core.registry import get as registry_get

    nav = StrategyNavigator(layer="layer2_contextual_injection")
    rosters = nav._LAYER_ROSTERS["layer2_contextual_injection"]
    for slot, cids in rosters.items():
        for cid in cids:
            cls = registry_get(cid)
            assert cls.class_id == cid, (
                f"roster slot {slot!r} references {cid!r} but registry returned {cls.class_id!r}"
            )
