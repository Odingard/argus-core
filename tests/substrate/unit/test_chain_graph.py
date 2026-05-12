"""Unit tests for ``argus.engine.core.chain_graph``.

Covers: node / edge validation, hashability, ``valid_heads`` /
``successors`` filtering by recon, ``ChainPlan.chain_id`` determinism.
"""

from __future__ import annotations

import pytest

from argus.engine.core.chain_graph import (
    ChainEdge,
    ChainGraph,
    ChainNode,
    ChainPlan,
    make_chain_id,
)
from argus.engine.core.recon_profile import ReconProfile


def _make_basic_graph() -> ChainGraph:
    g = ChainGraph()
    g.add_node(
        ChainNode(
            class_id="producer",
            layer="layer4_extraction",
            produces=("tool_names",),
        )
    )
    g.add_node(
        ChainNode(
            class_id="consumer",
            layer="layer1_tool_poisoning",
            consumes=("tool_names",),
        )
    )
    g.add_edge(ChainEdge(src="producer", dst="consumer", artefact="tool_names"))
    return g


def test_chain_node_normalises_and_dedupes_keys():
    node = ChainNode(
        class_id="x",
        layer="layer1_tool_poisoning",
        produces=("b", "a", "a"),
        consumes=("c", "b", ""),
    )
    assert node.produces == ("a", "b")
    assert node.consumes == ("b", "c")


def test_chain_node_rejects_empty_class_id_and_layer():
    with pytest.raises(ValueError):
        ChainNode(class_id="", layer="layer1_tool_poisoning")
    with pytest.raises(ValueError):
        ChainNode(class_id="x", layer="")


def test_chain_edge_rejects_self_loop_and_negative_weight():
    with pytest.raises(ValueError):
        ChainEdge(src="x", dst="x", artefact="tool_names")
    with pytest.raises(ValueError):
        ChainEdge(src="x", dst="y", artefact="tool_names", weight=-1.0)


def test_chain_graph_rejects_duplicate_node_and_unregistered_edge():
    g = _make_basic_graph()
    with pytest.raises(ValueError):
        g.add_node(ChainNode(class_id="producer", layer="layer4_extraction", produces=("x",)))
    with pytest.raises(KeyError):
        g.add_edge(ChainEdge(src="missing", dst="consumer", artefact="tool_names"))
    with pytest.raises(KeyError):
        g.add_edge(ChainEdge(src="producer", dst="missing", artefact="tool_names"))


def test_chain_graph_rejects_edge_artefact_not_in_produces_or_consumes():
    g = ChainGraph()
    g.add_node(ChainNode(class_id="p", layer="layer4_extraction", produces=("tool_names",)))
    g.add_node(ChainNode(class_id="c", layer="layer1_tool_poisoning", consumes=("rag_citations",)))
    with pytest.raises(ValueError):
        g.add_edge(ChainEdge(src="p", dst="c", artefact="tool_names"))


def test_chain_graph_nodes_and_edges_deterministic_order():
    g1 = _make_basic_graph()
    g2 = _make_basic_graph()
    assert [n.class_id for n in g1.nodes()] == [n.class_id for n in g2.nodes()]
    assert [(e.src, e.dst, e.artefact) for e in g1.edges()] == [(e.src, e.dst, e.artefact) for e in g2.edges()]
    assert g1.signature == g2.signature


def test_valid_heads_and_successors_respect_recon():
    g = _make_basic_graph()
    empty = ReconProfile.empty()
    heads = g.valid_heads(empty)
    head_ids = {n.class_id for n in heads}
    assert "producer" in head_ids
    assert "consumer" not in head_ids

    populated = ReconProfile(tool_names=("calculator",))
    heads_pop = g.valid_heads(populated)
    assert {n.class_id for n in heads_pop} >= {"producer", "consumer"}

    succ = g.successors("producer", populated)
    assert len(succ) == 1
    edge, dst = succ[0]
    assert edge.artefact == "tool_names"
    assert dst.class_id == "consumer"


def test_chain_plan_validates_node_edge_alignment_and_no_loops():
    e = ChainEdge(src="a", dst="b", artefact="tool_names")
    p = ChainPlan(
        chain_id=make_chain_id(("a", "b"), (e,)),
        nodes=("a", "b"),
        edges=(e,),
    )
    assert p.nodes == ("a", "b")

    with pytest.raises(ValueError):
        ChainPlan(chain_id="x", nodes=("a", "b"), edges=())  # mismatched lengths
    with pytest.raises(ValueError):
        ChainPlan(
            chain_id="x",
            nodes=("a", "b"),
            edges=(ChainEdge(src="z", dst="b", artefact="tool_names"),),
        )
    with pytest.raises(ValueError):
        ChainPlan(
            chain_id="x",
            nodes=("a", "a"),
            edges=(ChainEdge(src="a", dst="a", artefact="tool_names"),),
        )


def test_make_chain_id_is_deterministic_and_changes_with_inputs():
    e1 = ChainEdge(src="a", dst="b", artefact="tool_names")
    e2 = ChainEdge(src="a", dst="b", artefact="rag_citations")
    id_a = make_chain_id(("a", "b"), (e1,))
    id_b = make_chain_id(("a", "b"), (e1,))
    id_c = make_chain_id(("a", "b"), (e2,))
    assert id_a == id_b
    assert id_a != id_c
    assert len(id_a) == 24  # blake2b 12-byte hex
