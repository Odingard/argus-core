"""Layer-3 strategy-roster regression tests.

Pins the cognitive-attack roster so the same class-skip bug we hit on
Layer 2 (c04 / c08 sitting only in ``pivot`` and never firing) cannot
silently reappear here.

Layer 3 invariants:
  * Every roster entry must be a real registered attack class.
  * ``cog-meta-reasoning-bypass`` and ``cog-recursive-decomposition`` are
    heavy-hitter chained attacks — both must appear in ``exploitation``.
  * The four cheap reasoning hijacks (CoT-hijack, step-injection,
    self-consistency, counterfactual-priming) must appear in ``probing``
    so the engine fires them before walking into pivot.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import get as registry_get
from argus.engine.runtime.strategy import StrategyNavigator


def test_layer3_probing_classes_present() -> None:
    nav = StrategyNavigator(layer="layer3_cognitive")
    rosters = nav._LAYER_ROSTERS["layer3_cognitive"]
    must_probe = {
        "cog-chain-of-thought-hijack",
        "cog-reasoning-step-injection",
        "cog-self-consistency-exploit",
        "cog-counterfactual-priming",
        "cog-analogical-substitution",
    }
    assert must_probe.issubset(set(rosters["probing"])), (
        f"layer3 probing roster missing: {must_probe - set(rosters['probing'])}"
    )


def test_layer3_exploitation_classes_present() -> None:
    nav = StrategyNavigator(layer="layer3_cognitive")
    rosters = nav._LAYER_ROSTERS["layer3_cognitive"]
    must_exploit = {
        "cog-recursive-decomposition",
        "cog-logical-fallacy-amplifier",
        "cog-meta-reasoning-bypass",
        "cog-analogical-substitution",
    }
    assert must_exploit.issubset(set(rosters["exploitation"])), (
        f"layer3 exploitation roster missing: {must_exploit - set(rosters['exploitation'])}"
    )


def test_layer3_analogical_substitution_dual_scheduled() -> None:
    """c07 cog-analogical-substitution must appear in probing AND exploitation.

    The first ARGT-002 layer3 run revealed the same FSM-skip bug we hit on
    Layer 2 (c04 / c08): when probing's best score crosses the
    exploitation threshold (chain-of-thought-hijack landed at 21.7%), the
    pivot phase is skipped. c07 was originally pivot-only, so it never
    fired against ARGT-002. Pinning it in probing AND exploitation
    guarantees it cannot silently disappear again.
    """
    nav = StrategyNavigator(layer="layer3_cognitive")
    rosters = nav._LAYER_ROSTERS["layer3_cognitive"]
    assert "cog-analogical-substitution" in rosters["probing"], (
        "cog-analogical-substitution must be in the probing roster — pivot-only placement caused 0 fires on ARGT-002."
    )
    assert "cog-analogical-substitution" in rosters["exploitation"], (
        "cog-analogical-substitution must be in the exploitation roster — "
        "pivot-only placement caused 0 fires on ARGT-002."
    )


def test_layer3_roster_entries_are_registered_classes() -> None:
    nav = StrategyNavigator(layer="layer3_cognitive")
    rosters = nav._LAYER_ROSTERS["layer3_cognitive"]
    for slot, cids in rosters.items():
        for cid in cids:
            cls = registry_get(cid)
            assert cls.class_id == cid, (
                f"layer3 {slot!r} roster references {cid!r} but registry returned {cls.class_id!r}"
            )


def test_layer3_recommendation_returns_classes() -> None:
    """Sanity: navigator advances past recon and recommends layer3 classes."""
    nav = StrategyNavigator(layer="layer3_cognitive")
    nav.advance()  # recon -> probing
    recommended = nav.recommend_attack_classes()
    assert recommended, "layer3 navigator returned empty probing recommendation"
    for cid in recommended:
        assert cid.startswith("cog-"), f"non-cognitive class {cid!r} in layer3 probing"


def test_layer3_all_classes_in_probing_or_pivot_union() -> None:
    """Every layer-3 class must fire on hardened targets where exploitation never runs.

    On hardened targets like ARGT-005, no probing/pivot variant ever
    crosses ``EXPLOITATION_THRESHOLD`` (0.5) because every class lands at
    0%.  The FSM therefore never enters EXPLOITATION — it walks
    probing → pivot → probing → ... → reporting.

    Exploitation-only placement = silently skipped on hardened targets.
    The first ARGT-005 layer3 run revealed this: c04
    (logical-fallacy-amplifier) and c08 (recursive-decomposition) both
    fired 0 times across 500 variants because they were exploitation-only.

    Invariant: every cog-* class must be in (probing ∪ pivot).  This
    pins the bug so it cannot silently reappear.
    """
    nav = StrategyNavigator(layer="layer3_cognitive")
    rosters = nav._LAYER_ROSTERS["layer3_cognitive"]
    all_classes = {
        "cog-chain-of-thought-hijack",
        "cog-reasoning-step-injection",
        "cog-self-consistency-exploit",
        "cog-counterfactual-priming",
        "cog-analogical-substitution",
        "cog-meta-reasoning-bypass",
        "cog-logical-fallacy-amplifier",
        "cog-recursive-decomposition",
    }
    pre_exploit_union = set(rosters["probing"]) | set(rosters["pivot"])
    missing = all_classes - pre_exploit_union
    assert not missing, (
        f"layer3 classes silently skipped on hardened targets — never appear in "
        f"probing ∪ pivot: {sorted(missing)}.  Exploitation-only placement is a "
        f"silent skip when nothing lands."
    )


def test_layer3_logical_fallacy_amplifier_in_pivot() -> None:
    """c04 cog-logical-fallacy-amplifier must be in the pivot roster.

    Originally exploitation-only.  ARGT-005 layer3 run-1: 0 fires across
    500 variants — exploitation was never entered because nothing landed.
    Pivot placement guarantees it fires when probing exhausts itself.
    """
    nav = StrategyNavigator(layer="layer3_cognitive")
    rosters = nav._LAYER_ROSTERS["layer3_cognitive"]
    assert "cog-logical-fallacy-amplifier" in rosters["pivot"], (
        "cog-logical-fallacy-amplifier must be in the pivot roster — "
        "exploitation-only placement caused 0 fires on ARGT-005."
    )


def test_layer3_recursive_decomposition_in_pivot() -> None:
    """c08 cog-recursive-decomposition must be in the pivot roster.

    Originally exploitation-only.  ARGT-005 layer3 run-1: 0 fires across
    500 variants — exploitation was never entered because nothing landed.
    Pivot placement guarantees it fires when probing exhausts itself.
    """
    nav = StrategyNavigator(layer="layer3_cognitive")
    rosters = nav._LAYER_ROSTERS["layer3_cognitive"]
    assert "cog-recursive-decomposition" in rosters["pivot"], (
        "cog-recursive-decomposition must be in the pivot roster — "
        "exploitation-only placement caused 0 fires on ARGT-005."
    )
