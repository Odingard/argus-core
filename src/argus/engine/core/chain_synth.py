"""Deterministic beam-search chain synthesiser.

Walks the typed ``ChainGraph`` and emits the top-``beam_width`` chain
plans of length ``K`` ordered by static-prior score. Determinism is
hard-pinned: the same ``(graph_signature, initial_recon, K, beam_width,
seed_value)`` tuple produces the same byte-identical plan list across
runs and across processes.

The static prior on each edge is::

    score(edge) = edge.weight × indicator(simulated_recon ⊨ edge.dst.consumes)

where ``simulated_recon`` is ``initial_recon`` extended with the
artefacts every prior step in the partial plan declared in its
``produces`` tuple. Beam search assumes a step's harvest is *capable* of
producing the artefact for synthesis purposes; whether it actually does
so live is a runtime decision (see ``runtime.chain_runner``).

The ``seed_value`` argument is reserved for future deterministic
randomised tie-break experiments and is part of the cache key today so
every chain plan emitted by a given supervisor run is reproducible from
its supervisor seed alone.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .chain_graph import (
    ChainEdge,
    ChainGraph,
    ChainNode,
    ChainPlan,
    make_chain_id,
)
from .recon_profile import _FIELDS as _RECON_FIELDS
from .recon_profile import ReconProfile, _normalise


@dataclass(frozen=True, slots=True)
class _BeamState:
    """One partial chain in the beam frontier."""

    nodes: tuple[str, ...]
    edges: tuple[ChainEdge, ...]
    simulated_recon: ReconProfile
    score: float

    @property
    def head(self) -> str:
        return self.nodes[-1]

    @property
    def tie_break(self) -> str:
        h = hashlib.blake2b(digest_size=8)
        for node_id in self.nodes:
            h.update(node_id.encode("utf-8"))
            h.update(b"\x00")
        return h.hexdigest()


def _extend_recon(
    recon: ReconProfile,
    node: ChainNode,
) -> ReconProfile:
    """Return a recon profile extended with synthetic artefacts for ``node.produces``.

    The synthetic artefact is the literal field name; this is only used
    for satisfaction checks during beam search, never executed against a
    target. The chain runner replaces these synthetic placeholders with
    real harvested values during execution.
    """
    if not node.produces:
        return recon
    kwargs: dict[str, tuple[str, ...]] = {}
    for key in node.produces:
        existing = recon.get(key)
        if existing:
            kwargs[key] = existing
        else:
            placeholder = f"__chain_synth__:{node.class_id}:{key}"
            kwargs[key] = _normalise((placeholder,))
    # Build kwargs for every recon field, preserving existing values.
    full: dict[str, object] = {}
    for f in _RECON_FIELDS:
        full[f] = kwargs.get(f, recon.get(f))
    full["source_path"] = recon.source_path
    full["captured_at"] = recon.captured_at
    return ReconProfile(**full)


def beam_search(
    graph: ChainGraph,
    *,
    initial_recon: ReconProfile,
    K: int = 3,
    beam_width: int = 8,
    seed_value: int = 0,
) -> tuple[ChainPlan, ...]:
    """Yield up to ``beam_width`` deterministic ``ChainPlan`` objects of length ``K``.

    Args:
        graph: the registered ``ChainGraph`` to walk.
        initial_recon: the recon profile for the engagement; only nodes
            whose ``consumes`` are satisfied (after artefact extension)
            are admitted.
        K: chain depth (number of nodes per plan).
        beam_width: maximum number of partial chains kept at each
            frontier expansion. Caller-bounded so beam search is
            O(K · beam_width · |edges|) regardless of graph density.
        seed_value: opaque key folded into ``ChainPlan.metadata`` so
            multiple supervisor runs with different seeds can be told
            apart in transcripts. Does not affect ordering.

    Returns:
        A tuple of plans, deterministically ordered by ``(-score,
        tie_break)`` then truncated at ``beam_width``.
    """
    if K < 1:
        raise ValueError("beam_search K must be >= 1")
    if beam_width < 1:
        raise ValueError("beam_search beam_width must be >= 1")

    heads = graph.valid_heads(initial_recon)
    if not heads:
        return ()

    frontier: list[_BeamState] = []
    for head in heads:
        frontier.append(
            _BeamState(
                nodes=(head.class_id,),
                edges=(),
                simulated_recon=_extend_recon(initial_recon, head),
                score=1.0,
            )
        )
    frontier = _trim(frontier, beam_width)

    for _depth in range(1, K):
        next_frontier: list[_BeamState] = []
        for state in frontier:
            successors = graph.successors(state.head, state.simulated_recon)
            if not successors:
                continue
            for edge, dst in successors:
                if dst.class_id in state.nodes:
                    continue
                next_frontier.append(
                    _BeamState(
                        nodes=state.nodes + (dst.class_id,),
                        edges=state.edges + (edge,),
                        simulated_recon=_extend_recon(state.simulated_recon, dst),
                        score=state.score + edge.weight,
                    )
                )
        if not next_frontier:
            return ()
        frontier = _trim(next_frontier, beam_width)

    plans: list[ChainPlan] = []
    for state in frontier:
        chain_id = make_chain_id(state.nodes, state.edges)
        plans.append(
            ChainPlan(
                chain_id=chain_id,
                nodes=state.nodes,
                edges=state.edges,
                score=state.score,
                metadata=(("seed_value", str(seed_value)),),
            )
        )
    return tuple(plans)


def _trim(states: list[_BeamState], width: int) -> list[_BeamState]:
    states.sort(key=lambda s: (-s.score, s.tie_break))
    return states[:width]


__all__ = ["beam_search"]


# --- Default starter graph -------------------------------------------------
#
# The 5 starter chains from the design spec (§4) live here so the supervisor
# can wire a default graph without every consumer having to register edges
# by hand. This is purely a convenience over ``ChainGraph()`` —
# every chain registered here is documented in the design spec.


def _default_starter_chain_nodes() -> tuple[ChainNode, ...]:
    return (
        ChainNode(
            class_id="ext-system-prompt-leak",
            layer="layer4_extraction",
            produces=("persona_fragments", "framework_hints"),
            consumes=("agent_role_names",),
        ),
        ChainNode(
            class_id="ext-tool-schema-leak",
            layer="layer4_extraction",
            produces=("tool_names", "tool_parameter_keys"),
            consumes=(),
        ),
        ChainNode(
            class_id="ext-rag-corpus-leak",
            layer="layer4_extraction",
            produces=("rag_corpus_excerpts", "rag_citations"),
            consumes=(),
        ),
        ChainNode(
            class_id="mas-handoff-hijack",
            layer="layer5_orchestration",
            produces=("agent_role_names",),
            consumes=(),
        ),
        ChainNode(
            class_id="tp-protocol-exploit",
            layer="layer1_tool_poisoning",
            produces=("tool_names", "agent_envelope_styles"),
            consumes=("tool_names",),
        ),
        ChainNode(
            class_id="cog-counterfactual-priming",
            layer="layer3_cognitive",
            produces=(),
            consumes=("persona_fragments", "framework_hints"),
        ),
        ChainNode(
            class_id="tp-schema-shadowing",
            layer="layer1_tool_poisoning",
            produces=(),
            consumes=("tool_names", "tool_parameter_keys"),
        ),
        ChainNode(
            class_id="ci-rag-direct-poisoning",
            layer="layer2_contextual_injection",
            produces=(),
            consumes=("rag_corpus_excerpts", "rag_citations"),
        ),
        ChainNode(
            class_id="mas-trust-pivot",
            layer="layer5_orchestration",
            produces=(),
            consumes=("tool_names", "agent_envelope_styles"),
        ),
        # Phase C → Phase E credential kill chain.
        ChainNode(
            class_id="ext-credential-leak",
            layer="layer4_extraction",
            produces=("leaked_credentials",),
            consumes=("tool_names",),
        ),
        ChainNode(
            class_id="tp-credential-exercise",
            layer="layer1_tool_poisoning",
            produces=(),
            consumes=("leaked_credentials", "tool_names"),
        ),
        # Phase K — MCP-specific depth classes consume the new recon
        # slots populated by ReconProfile.from_manifest. The supply-chain
        # class can additionally produce leaked_credentials when its
        # transitive-hijack / stale-cache patterns surface secrets via
        # OOB exfil, so it feeds tp-credential-exercise (Phase E).
        ChainNode(
            class_id="tp-mcp-supply-chain",
            layer="layer1_tool_poisoning",
            produces=("leaked_credentials",),
            consumes=("tool_names", "manifest_hashes"),
        ),
        ChainNode(
            class_id="mas-a2a-token-replay",
            layer="layer5_orchestration",
            produces=("leaked_credentials",),
            consumes=(
                "agent_cards",
                "delegation_endpoints",
                "a2a_token_format",
            ),
        ),
        ChainNode(
            class_id="ci-tool-result-rag-feedback",
            layer="layer2_contextual_injection",
            produces=(),
            consumes=(
                "memory_writers",
                "rag_endpoints",
                "citation_format",
            ),
        ),
    )


def _default_starter_chain_edges() -> tuple[ChainEdge, ...]:
    return (
        # Chain 1: ext-system-prompt-leak -> cog-counterfactual-priming
        ChainEdge(
            "ext-system-prompt-leak",
            "cog-counterfactual-priming",
            "persona_fragments",
        ),
        ChainEdge(
            "ext-system-prompt-leak",
            "cog-counterfactual-priming",
            "framework_hints",
        ),
        # Chain 2: ext-tool-schema-leak -> tp-schema-shadowing
        ChainEdge(
            "ext-tool-schema-leak",
            "tp-schema-shadowing",
            "tool_names",
        ),
        ChainEdge(
            "ext-tool-schema-leak",
            "tp-schema-shadowing",
            "tool_parameter_keys",
        ),
        # Chain 5 prefix: ext-tool-schema-leak -> tp-protocol-exploit
        ChainEdge(
            "ext-tool-schema-leak",
            "tp-protocol-exploit",
            "tool_names",
        ),
        # Chain 3: ext-rag-corpus-leak -> ci-rag-direct-poisoning
        ChainEdge(
            "ext-rag-corpus-leak",
            "ci-rag-direct-poisoning",
            "rag_corpus_excerpts",
        ),
        ChainEdge(
            "ext-rag-corpus-leak",
            "ci-rag-direct-poisoning",
            "rag_citations",
        ),
        # Chain 4: mas-handoff-hijack -> ext-system-prompt-leak
        ChainEdge(
            "mas-handoff-hijack",
            "ext-system-prompt-leak",
            "agent_role_names",
        ),
        # Chain 5 tail: tp-protocol-exploit -> mas-trust-pivot
        ChainEdge(
            "tp-protocol-exploit",
            "mas-trust-pivot",
            "tool_names",
        ),
        ChainEdge(
            "tp-protocol-exploit",
            "mas-trust-pivot",
            "agent_envelope_styles",
        ),
        # Chain 6: ext-credential-leak -> tp-credential-exercise
        # (Phase C surfaces a credential, Phase E exercises it.)
        ChainEdge(
            "ext-credential-leak",
            "tp-credential-exercise",
            "leaked_credentials",
        ),
        ChainEdge(
            "ext-tool-schema-leak",
            "ext-credential-leak",
            "tool_names",
        ),
        # Chain 7: ext-tool-schema-leak -> ext-credential-leak ->
        # tp-credential-exercise reuses the tool_names produced by the
        # schema-leak step so the exercise step targets a real tool.
        ChainEdge(
            "ext-tool-schema-leak",
            "tp-credential-exercise",
            "tool_names",
        ),
        # Chain 8 (Phase K): ext-tool-schema-leak -> tp-mcp-supply-chain
        # — schema leak surfaces the actual tool_names that the supply-
        # chain class then audits for manifest-hash / pin / signature
        # drift. tp-mcp-supply-chain can in turn surface leaked
        # credentials (transitive-hijack / stale-cache patterns), so
        # it stacks into tp-credential-exercise (Phase E).
        ChainEdge(
            "ext-tool-schema-leak",
            "tp-mcp-supply-chain",
            "tool_names",
        ),
        ChainEdge(
            "tp-mcp-supply-chain",
            "tp-credential-exercise",
            "leaked_credentials",
        ),
        # Chain 9 (Phase K): mas-a2a-token-replay can surface leaked
        # credentials (cross-tenant replay / expired-credential
        # tolerance), so it also stacks into tp-credential-exercise.
        ChainEdge(
            "mas-a2a-token-replay",
            "tp-credential-exercise",
            "leaked_credentials",
        ),
    )


def default_chain_graph() -> ChainGraph:
    """Build the starter ``ChainGraph`` covering all 5 chains in the design spec.

    Mas-handoff-hijack and ext-system-prompt-leak both appear in chains
    because they are nodes that *also* serve as upstream producers for
    downstream chain steps. ``mas-handoff-hijack`` produces
    ``agent_role_names``; ``ext-system-prompt-leak`` produces persona +
    framework hints. The graph is dependency-injected into the supervisor
    via the optional ``chain_graph=`` kwarg; callers can substitute a
    smaller / larger graph at construction time.
    """
    graph = ChainGraph()
    for node in _default_starter_chain_nodes():
        graph.add_node(node)
    for edge in _default_starter_chain_edges():
        graph.add_edge(edge)
    # Promote `mas-handoff-hijack` so its consumed-from-recon slot is
    # explicit when an engagement starts with `agent_role_names`
    # populated. Handoff hijack itself does not require recon to fire,
    # so its consumes tuple is empty by design (it produces agent_role
    # names from the L5 finding, not from prior recon).
    return graph
