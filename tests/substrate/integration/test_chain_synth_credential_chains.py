"""Tests for the credential-bearing chain templates registered in
``chain_synth.default_chain_graph``.

Two starter chains pin the Phase C → Phase E kill chain into the default
graph:

  * Chain 6: ``ext-credential-leak -> tp-credential-exercise``
    (Phase C surfaces a credential, Phase E exercises it via a tool
    call.)
  * Chain 7: ``ext-tool-schema-leak -> ext-credential-leak ->
    tp-credential-exercise`` (recon-style chain: schema leak feeds the
    credential-leak step which feeds the exercise step.)

Both chains must be reachable through ``beam_search`` once a
``leaked_credentials`` slot enters the recon profile, and the static
``produces``/``consumes`` declarations must line up with the artefact
names emitted by ``ext-credential-leak.harvest``.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.chain_synth import beam_search, default_chain_graph
from argus.engine.core.recon_profile import ReconProfile


def test_credential_chain_nodes_present() -> None:
    graph = default_chain_graph()
    node_ids = {n.class_id for n in graph.nodes()}
    assert "ext-credential-leak" in node_ids
    assert "tp-credential-exercise" in node_ids


def test_ext_credential_leak_produces_leaked_credentials() -> None:
    graph = default_chain_graph()
    node = graph.get_node("ext-credential-leak")
    assert "leaked_credentials" in node.produces


def test_tp_credential_exercise_consumes_leaked_credentials() -> None:
    graph = default_chain_graph()
    node = graph.get_node("tp-credential-exercise")
    assert "leaked_credentials" in node.consumes


def test_chain6_edge_exists() -> None:
    """Direct credential kill-chain edge must be wired."""
    graph = default_chain_graph()
    edges = list(graph.edges())
    pair = ("ext-credential-leak", "tp-credential-exercise")
    matches = [e for e in edges if (e.src, e.dst) == pair and e.artefact == "leaked_credentials"]
    assert matches, "missing chain-6 edge ext-credential-leak -> tp-credential-exercise"


def test_chain7_intermediate_edge_exists() -> None:
    """Schema-leak -> credential-leak intermediate edge must be wired."""
    graph = default_chain_graph()
    edges = list(graph.edges())
    pair = ("ext-tool-schema-leak", "ext-credential-leak")
    matches = [e for e in edges if (e.src, e.dst) == pair and e.artefact == "tool_names"]
    assert matches, "missing chain-7 intermediate edge"


def test_credential_chain_discoverable_by_beam_search() -> None:
    """``beam_search`` must surface a chain that lands on
    ``tp-credential-exercise`` once recon supplies a tool name (the
    initial slot the schema-leak step harvests).
    """
    graph = default_chain_graph()
    initial = ReconProfile(tool_names=("billing_charge",))
    plans = beam_search(graph, initial_recon=initial, K=3, beam_width=8)
    assert any(plan.nodes[-1] == "tp-credential-exercise" for plan in plans), (
        f"no plan terminating at tp-credential-exercise (saw {[p.nodes for p in plans]})"
    )


def test_credential_chain_harvest_contract() -> None:
    """``ext-credential-leak``'s registered harvest must be capable of
    emitting the ``leaked_credentials`` key the chain edge promises.
    Otherwise the chain runner will silently drop the artefact and
    Phase E gets nothing to exercise.
    """
    from argus.engine.core.registry import get

    cls = get("ext-credential-leak")
    assert cls.harvest is not None, "ext-credential-leak must register a harvest() to feed Phase E"
