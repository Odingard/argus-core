"""Unit tests for ``argus.engine.core.chain_synth.beam_search``.

Covers: K=1/2/3, determinism across runs, beam_width truncation,
recon-driven head admission, tie-break ordering, no self-loop / no
re-entry guarantees.
"""

from __future__ import annotations

import pytest

from argus.engine.core.chain_graph import (
    ChainEdge,
    ChainGraph,
    ChainNode,
)
from argus.engine.core.chain_synth import beam_search, default_chain_graph
from argus.engine.core.recon_profile import ReconProfile


def _build_graph() -> ChainGraph:
    g = ChainGraph()
    g.add_node(
        ChainNode(
            class_id="leak-prompt",
            layer="layer4_extraction",
            produces=("persona_fragments",),
        )
    )
    g.add_node(
        ChainNode(
            class_id="leak-tools",
            layer="layer4_extraction",
            produces=("tool_names",),
        )
    )
    g.add_node(
        ChainNode(
            class_id="prime",
            layer="layer3_cognitive",
            consumes=("persona_fragments",),
        )
    )
    g.add_node(
        ChainNode(
            class_id="shadow",
            layer="layer1_tool_poisoning",
            consumes=("tool_names",),
        )
    )
    g.add_edge(ChainEdge(src="leak-prompt", dst="prime", artefact="persona_fragments"))
    g.add_edge(ChainEdge(src="leak-tools", dst="shadow", artefact="tool_names"))
    return g


def test_beam_search_K1_returns_only_heads():
    g = _build_graph()
    plans = beam_search(g, initial_recon=ReconProfile.empty(), K=1)
    assert plans
    for plan in plans:
        assert len(plan.nodes) == 1
        assert plan.edges == ()


def test_beam_search_K2_returns_two_step_plans():
    g = _build_graph()
    plans = beam_search(g, initial_recon=ReconProfile.empty(), K=2)
    assert plans
    for plan in plans:
        assert len(plan.nodes) == 2
        assert len(plan.edges) == 1
        assert plan.edges[0].src == plan.nodes[0]
        assert plan.edges[0].dst == plan.nodes[1]


def test_beam_search_K3_handles_no_3_step_chains_gracefully():
    g = _build_graph()
    plans = beam_search(g, initial_recon=ReconProfile.empty(), K=3)
    assert plans == ()


def test_beam_search_is_deterministic_across_calls():
    g = _build_graph()
    a = beam_search(g, initial_recon=ReconProfile.empty(), K=2, seed_value=99)
    b = beam_search(g, initial_recon=ReconProfile.empty(), K=2, seed_value=99)
    assert tuple(p.chain_id for p in a) == tuple(p.chain_id for p in b)
    assert tuple(p.nodes for p in a) == tuple(p.nodes for p in b)


def test_beam_width_truncates_frontier():
    g = _build_graph()
    wide = beam_search(g, initial_recon=ReconProfile.empty(), K=1, beam_width=8)
    narrow = beam_search(g, initial_recon=ReconProfile.empty(), K=1, beam_width=1)
    assert len(narrow) == 1
    assert len(wide) >= len(narrow)


def test_beam_search_with_empty_recon_admits_only_no_consume_heads():
    g = _build_graph()
    plans = beam_search(g, initial_recon=ReconProfile.empty(), K=1)
    head_ids = {p.nodes[0] for p in plans}
    assert head_ids == {"leak-prompt", "leak-tools"}


def test_beam_search_with_satisfied_recon_admits_consume_heads_too():
    g = _build_graph()
    recon = ReconProfile(persona_fragments=("DataBot",), tool_names=("search",))
    plans = beam_search(g, initial_recon=recon, K=1, beam_width=8)
    head_ids = {p.nodes[0] for p in plans}
    assert {"prime", "shadow"} <= head_ids


def test_beam_search_no_self_loop_and_no_revisit():
    g = ChainGraph()
    g.add_node(
        ChainNode(
            class_id="a",
            layer="layer4_extraction",
            produces=("tool_names",),
            consumes=("tool_names",),
        )
    )
    g.add_node(
        ChainNode(
            class_id="b",
            layer="layer1_tool_poisoning",
            produces=("tool_names",),
            consumes=("tool_names",),
        )
    )
    g.add_edge(ChainEdge(src="a", dst="b", artefact="tool_names"))
    g.add_edge(ChainEdge(src="b", dst="a", artefact="tool_names"))
    plans = beam_search(g, initial_recon=ReconProfile(tool_names=("x",)), K=3)
    for plan in plans:
        assert len(set(plan.nodes)) == len(plan.nodes)


def test_beam_search_invalid_args_raise():
    g = _build_graph()
    with pytest.raises(ValueError):
        beam_search(g, initial_recon=ReconProfile.empty(), K=0)
    with pytest.raises(ValueError):
        beam_search(g, initial_recon=ReconProfile.empty(), K=1, beam_width=0)


def test_default_chain_graph_supports_K3_for_three_step_chains():
    g = default_chain_graph()
    plans = beam_search(g, initial_recon=ReconProfile.empty(), K=3, beam_width=16)
    assert plans
    chain_node_sets = {tuple(p.nodes) for p in plans}
    assert (
        "mas-handoff-hijack",
        "ext-system-prompt-leak",
        "cog-counterfactual-priming",
    ) in chain_node_sets
    assert (
        "ext-tool-schema-leak",
        "tp-protocol-exploit",
        "mas-trust-pivot",
    ) in chain_node_sets
