"""Integration tests for the starter chains in ``default_chain_graph``.

These pin the starter-pack contract: 14 nodes / 16 edges (5 original
chains, the Phase C → Phase E credential kill chain, plus the Phase K
MCP-depth fan-in to ``tp-credential-exercise``). Every chain's
consumes are satisfied by either ``initial_recon`` or some upstream
node's produces, and the two 3-step chains
(`mas-handoff-hijack` → `ext-system-prompt-leak` →
`cog-counterfactual-priming` and
`ext-tool-schema-leak` → `tp-protocol-exploit` → `mas-trust-pivot`)
both surface in ``beam_search`` results given a representative recon
profile.
"""

from __future__ import annotations

from argus.engine.core.chain_graph import ChainGraph
from argus.engine.core.chain_synth import beam_search, default_chain_graph
from argus.engine.core.recon_profile import ReconProfile


def test_starter_pack_node_and_edge_counts():
    g = default_chain_graph()
    assert len(list(g.nodes())) == 14
    assert len(list(g.edges())) == 16


def test_starter_pack_class_ids_match_design_spec():
    g = default_chain_graph()
    expected = {
        "ext-system-prompt-leak",
        "ext-tool-schema-leak",
        "ext-rag-corpus-leak",
        "mas-handoff-hijack",
        "tp-protocol-exploit",
        "cog-counterfactual-priming",
        "tp-schema-shadowing",
        "ci-rag-direct-poisoning",
        "mas-trust-pivot",
        "ext-credential-leak",
        "tp-credential-exercise",
        # Phase K — MCP-specific depth.
        "tp-mcp-supply-chain",
        "mas-a2a-token-replay",
        "ci-tool-result-rag-feedback",
    }
    assert {n.class_id for n in g.nodes()} == expected


def test_starter_pack_2_step_chains_beam_search_to_themselves():
    g = default_chain_graph()
    # ext-system-prompt-leak consumes agent_role_names (chain 4 prefix), so
    # the empty-recon beam admits the other two 2-step chains as heads,
    # and the persona-priming 2-step surfaces once recon has the role
    # name (or as the tail of the 3-step chain — see test below).
    plans_empty = beam_search(g, initial_recon=ReconProfile.empty(), K=2, beam_width=16)
    pairs_empty = {tuple(p.nodes) for p in plans_empty}
    assert (
        "ext-tool-schema-leak",
        "tp-schema-shadowing",
    ) in pairs_empty
    assert (
        "ext-rag-corpus-leak",
        "ci-rag-direct-poisoning",
    ) in pairs_empty

    plans_with_role = beam_search(
        g,
        initial_recon=ReconProfile(agent_role_names=("planner",)),
        K=2,
        beam_width=16,
    )
    pairs_with_role = {tuple(p.nodes) for p in plans_with_role}
    assert (
        "ext-system-prompt-leak",
        "cog-counterfactual-priming",
    ) in pairs_with_role


def test_starter_pack_3_step_chains_surface_at_K3():
    g = default_chain_graph()
    plans = beam_search(g, initial_recon=ReconProfile.empty(), K=3, beam_width=32)
    triples = {tuple(p.nodes) for p in plans}
    assert (
        "mas-handoff-hijack",
        "ext-system-prompt-leak",
        "cog-counterfactual-priming",
    ) in triples
    assert (
        "ext-tool-schema-leak",
        "tp-protocol-exploit",
        "mas-trust-pivot",
    ) in triples


def test_starter_pack_no_step_has_unsatisfied_consumes():
    g = default_chain_graph()
    plans = beam_search(g, initial_recon=ReconProfile.empty(), K=3, beam_width=32)
    for plan in plans:
        produced: set[str] = set()
        for class_id in plan.nodes:
            node = g.get_node(class_id)
            for c in node.consumes:
                assert c in produced, (
                    f"chain {plan.chain_id} step {class_id} consumes {c!r} but no upstream node produces it"
                )
            produced.update(node.produces)


def test_default_chain_graph_returns_same_signature_each_call():
    g1: ChainGraph = default_chain_graph()
    g2: ChainGraph = default_chain_graph()
    assert g1.signature == g2.signature
