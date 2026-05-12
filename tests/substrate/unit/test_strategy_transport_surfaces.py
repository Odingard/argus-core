"""StrategyNavigator must merge transport-reported surfaces.

PR #5 (multi-call transport) introduces ``session_state`` as a wire-
level capability. The three Layer 2 classes c04 / c08 / c09 declare
``target_surface={"session_state"}``; without the merge, those
classes are never feasibility-feasible no matter what transport runs
underneath. With the merge, an empty manifest plus a multi-call
transport correctly opens the session-state gate and a single-call
transport correctly leaves it shut.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all attack classes
from argus.engine.recon.mcp_introspect import TargetManifest, ToolManifest
from argus.engine.runtime.strategy import EngagementPhase, StrategyNavigator

# c04 / c08 / c09 — the three Layer 2 classes whose ``target_surface``
# is gated on real server-tracked session state.
_SESSION_STATE_CLASSES = (
    "ci-conversation-history-forgery",
    "ci-indirect-payload-splitting",
    "ci-context-window-stuffing",
)


def _all_rostered(nav: StrategyNavigator) -> set[str]:
    """Union of every roster slot for the navigator's layer."""
    rosters = nav._LAYER_ROSTERS.get(nav.layer, {})
    out: set[str] = set()
    for cids in rosters.values():
        out.update(cids)
    return out


def _filtered_union(nav: StrategyNavigator) -> set[str]:
    """Run ``_filter_feasible`` over every rostered class for the layer."""
    return set(nav._filter_feasible(list(_all_rostered(nav))))


def test_empty_manifest_and_chat_only_transport_disables_gating() -> None:
    nav = StrategyNavigator(
        layer="layer2_contextual_injection",
        transport_surfaces=frozenset({"chat"}),
    )
    nav.advance()  # → PROBING
    # Chat-only transport contributes nothing beyond {"chat"}, manifest
    # is empty, so available_surfaces is empty → gating disabled.
    assert nav.available_surfaces() == frozenset()
    feasible = _filtered_union(nav)
    # All three session-state classes still pass the filter — gating is
    # disabled, so they fire and the per-class early-stop handles the
    # no-land case (ARGT-002 single-call behaviour preserved).
    for cid in _SESSION_STATE_CLASSES:
        assert cid in feasible


def test_multi_call_transport_opens_session_state_gate() -> None:
    nav = StrategyNavigator(
        layer="layer2_contextual_injection",
        transport_surfaces=frozenset({"chat", "session_state"}),
    )
    nav.advance()  # → PROBING
    surfaces = nav.available_surfaces()
    assert "chat" in surfaces
    assert "session_state" in surfaces
    feasible = _filtered_union(nav)
    # Session-state-gated classes are now feasible across all rosters.
    for cid in _SESSION_STATE_CLASSES:
        assert cid in feasible


def test_single_call_transport_keeps_session_state_gated_when_manifest_present() -> None:
    """Manifest present + single-call transport ⇒ session-state classes
    are correctly excluded.

    With a populated manifest, ``available_surfaces`` is no longer the
    empty sentinel and the per-class ``target_surface`` filter is
    enforced. A chat-only transport contributes no ``session_state``
    capability, so c04 / c08 / c09 are dropped before they fire.
    """
    manifest = TargetManifest(
        transport="mcp",
        tools=(
            ToolManifest(
                name="search",
                description="search docs",
                parameters_schema={"type": "object"},
            ),
        ),
    )
    nav = StrategyNavigator(
        layer="layer2_contextual_injection",
        transport_surfaces=frozenset({"chat"}),
        manifest=manifest,
    )
    nav.advance()  # → PROBING
    surfaces = nav.available_surfaces()
    assert "tool" in surfaces
    assert "session_state" not in surfaces
    feasible = _filtered_union(nav)
    for cid in _SESSION_STATE_CLASSES:
        assert cid not in feasible, (
            f"{cid} requires session_state; chat-only transport must exclude it from the feasible set."
        )


def test_multi_call_transport_with_manifest_unions_both_signals() -> None:
    manifest = TargetManifest(
        transport="mcp",
        tools=(
            ToolManifest(
                name="search",
                description="search docs",
                parameters_schema={"type": "object"},
            ),
        ),
    )
    nav = StrategyNavigator(
        layer="layer2_contextual_injection",
        transport_surfaces=frozenset({"chat", "session_state"}),
        manifest=manifest,
    )
    nav.advance()  # → PROBING
    surfaces = nav.available_surfaces()
    assert {"chat", "tool", "schema", "mcp", "session_state"} <= surfaces
    feasible = _filtered_union(nav)
    for cid in _SESSION_STATE_CLASSES:
        assert cid in feasible


def test_transport_surfaces_default_preserves_pre_pr5_behaviour() -> None:
    """A navigator constructed without ``transport_surfaces`` (e.g. from
    a test that was written before PR #5) must behave exactly as it did
    before — empty transport_surfaces, no session_state in the
    available set, all gating relying on the manifest alone.
    """
    nav = StrategyNavigator(layer="layer2_contextual_injection")
    nav.advance()
    assert nav.transport_surfaces == frozenset()
    # Empty manifest + empty transport ⇒ empty available ⇒ gating off.
    assert nav.available_surfaces() == frozenset()
    # Phase still walks correctly.
    assert nav.phase == EngagementPhase.PROBING
