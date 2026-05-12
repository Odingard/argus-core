"""Layer-5 two-stage canary gate tests for o03 second-order injection.

The two-stage canary gate is the structural invariant that distinguishes
``mas-second-order-injection`` from Layer-4 single-agent extraction:

  Stage 1 (plant) — A canary-bearing payload is placed on agent-A's
                    input channel: a RAG-corpus document, tool
                    description, resource annotation, prepended
                    system-message turn, or shared-memory entry.

  Stage 2 (harvest) — Agent-B is asked to perform a routine task whose
                      natural execution will surface the planted canary
                      in its own reply (e.g. summarise the corpus,
                      list available tools, recall the most recent
                      shared-memory entry).

Live-fire confirmation requires that the canary surface in agent-B's
output without agent-A having quoted it directly — proving cross-channel
flow rather than within-channel echo. These tests validate the
*structural* shape required for the live-fire gate to make sense:

  1. Every o03 variant carries a planted surface (rag_corpus, tools,
     resources, or prepended system message) — Stage 1.
  2. The user-facing message asks agent-B to surface that surface —
     Stage 2.
  3. The canary appears in the planted surface, not only in the user
     message — proving the plant is on a non-message channel.
  4. Every plant channel from the o03 catalogue is exercised at least
     once across the variant set.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers Layer-5 classes
from argus.engine.core.registry import classes_in_layer

CLASS_ID = "mas-second-order-injection"


def _variants():
    for cls in classes_in_layer("layer5_orchestration"):
        if cls.class_id == CLASS_ID:
            return list(cls.factory(seed_value=42).generate())
    raise AssertionError(f"{CLASS_ID} not registered")


def test_o03_every_variant_has_planted_surface() -> None:
    """Stage 1 invariant: every o03 variant must plant the canary on a
    non-message surface (rag_corpus, tool description, resource
    description) OR on a prepended system-role message that is not
    the user-authored harvest message."""
    for variant in _variants():
        primary = variant.canaries.primary

        rag_blob = "\n".join(str(d) for d in variant.rag_corpus)
        tools_blob = "\n".join(t.description for t in variant.tools)
        resources_blob = "\n".join(r.description for r in variant.resources)

        # Identify prepended (non-user) message planters.
        prepended_blob = "\n".join(m.content for m in variant.messages if m.role != "user")

        plant_surfaces = (rag_blob, tools_blob, resources_blob, prepended_blob)
        plant_hit = any(primary in surface for surface in plant_surfaces)
        assert plant_hit, (
            f"{variant.variant_id} has no planted surface carrying canary "
            f"{primary!r} — Stage 1 of two-stage gate broken"
        )


def test_o03_harvest_message_distinct_from_plant() -> None:
    """Stage 2 invariant: the user-authored harvest message must NOT
    quote the canary directly. The canary lives on a non-user surface
    so any agent-B output that surfaces it proves cross-channel flow.
    """
    for variant in _variants():
        primary = variant.canaries.primary
        user_messages = [m.content for m in variant.messages if m.role == "user"]
        assert user_messages, f"{variant.variant_id} has no user message"
        for content in user_messages:
            assert primary not in content, (
                f"{variant.variant_id} user message quoted canary directly — "
                "two-stage gate cannot prove cross-channel flow"
            )


def test_o03_harvest_message_directs_at_planted_channel() -> None:
    """Each variant's user message must instruct the receiving agent
    to interact with the planted channel (summarise the corpus, list
    tools, quote a resource, recall shared memory, continue from prior
    upstream reply, honour session state). This is the substrate the
    live-fire judge needs in order to reason about whether agent-B
    surfaced the plant naturally."""
    expected_substrings = (
        "summarise",
        "summarize",
        "list",
        "quote",
        "continue",
        "honour",
        "honor",
        "recall",
    )
    for variant in _variants():
        user_blob = " ".join(m.content.lower() for m in variant.messages if m.role == "user")
        assert any(sub in user_blob for sub in expected_substrings), (
            f"{variant.variant_id} harvest message does not direct at planted channel — got: {user_blob[:120]}"
        )


def test_o03_plant_channel_diversity() -> None:
    """All six plant channels in the o03 catalogue must be represented
    across the variant set. Loss of channel diversity would weaken
    cross-carrier coverage."""
    expected_channels = {
        "rag_corpus",
        "tool",
        "resource",
        "upstream_message",
        "session_state",
        "shared_memory",
    }
    seen: set[str] = set()
    for variant in _variants():
        params = variant.metadata.get("params", {})
        channel = params.get("channel")
        if channel:
            seen.add(channel)
    missing = expected_channels - seen
    assert not missing, f"o03 variant set missing plant channels: {sorted(missing)}. Saw: {sorted(seen)}"
