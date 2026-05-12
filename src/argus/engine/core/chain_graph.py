"""Chain-synthesis graph — typed registry of nodes + directed artefact edges.

The graph is the substrate the deterministic chain synthesiser
(``argus.engine.core.chain_synth.beam_search``) walks. Each node wraps an
already-registered attack class and declares the artefact tuple it
*produces* (after a successful finding) and the artefact tuple it
*consumes* (via the recon-param plumbing shipped in PR #13). Each edge
is a directed claim "node A produces an artefact that satisfies one of
node B's consumed slots".

Determinism contract:

* Nodes / edges are interned in registration order; ``edges()`` and
  ``nodes()`` return tuples sorted by content hash so two registries
  built from the same registrations produce byte-identical iteration.
* ``ChainPlan.chain_id`` is a content hash over node ids + edge tuples;
  the same plan reconstituted from a different process produces the
  same id.
* Validation is strict — registering a node twice, registering an edge
  whose ``artefact`` is not in ``src.produces`` / ``dst.consumes``, or
  registering an edge whose endpoints aren't on the graph all raise.

Artefact vocabulary is the same ``ReconProfile`` field set used by the
recon-param upgrade (PR #13). No new vocabulary is introduced.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .recon_profile import ReconProfile

ArtefactKey = str
"""One of the field names declared on ``ReconProfile``.

The chain graph deliberately reuses the recon-param vocabulary so chain
composition operates on the same artefact axis the per-class
parameterisation already understands.
"""


@dataclass(frozen=True, slots=True)
class ChainNode:
    """A single step in a chain plan.

    ``produces`` lists the artefact keys the node's ``harvest`` callable
    can extract from a confirmed finding. ``consumes`` lists artefact
    keys the node's ``factory`` reads through the recon-param plumbing.
    Both tuples are deduplicated and sorted at construction so two
    nodes built from the same arguments compare equal.
    """

    class_id: str
    layer: str
    produces: tuple[ArtefactKey, ...] = ()
    consumes: tuple[ArtefactKey, ...] = ()

    def __post_init__(self) -> None:
        if not self.class_id:
            raise ValueError("ChainNode.class_id must be non-empty")
        if not self.layer:
            raise ValueError("ChainNode.layer must be non-empty")
        # Normalise tuples — sort + dedup — so equality is structural.
        object.__setattr__(self, "produces", _norm_keys(self.produces))
        object.__setattr__(self, "consumes", _norm_keys(self.consumes))

    def consumes_satisfied_by(self, recon: ReconProfile) -> bool:
        """True iff every key in ``self.consumes`` has an artefact in ``recon``.

        Nodes with no consumed artefacts are always satisfied — they are
        "valid heads" for the beam search regardless of recon contents.
        """
        if not self.consumes:
            return True
        return all(recon.get(key) for key in self.consumes)


@dataclass(frozen=True, slots=True)
class ChainEdge:
    """A directed edge "src produces ``artefact`` consumed by dst"."""

    src: str
    dst: str
    artefact: ArtefactKey
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not self.src or not self.dst:
            raise ValueError("ChainEdge endpoints must be non-empty class_ids")
        if self.src == self.dst:
            raise ValueError(f"ChainEdge cannot be a self-loop: {self.src} -> {self.dst}")
        if not self.artefact:
            raise ValueError("ChainEdge.artefact must be non-empty")
        if self.weight < 0:
            raise ValueError("ChainEdge.weight must be non-negative")


@dataclass(frozen=True, slots=True)
class ChainPlan:
    """A topologically-ordered sequence of nodes plus the edges that connect them.

    ``chain_id`` is a deterministic content hash over the plan's nodes
    and edges so plan equality survives serialisation.
    """

    chain_id: str
    nodes: tuple[str, ...]
    edges: tuple[ChainEdge, ...]
    score: float = 0.0
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.nodes:
            raise ValueError("ChainPlan.nodes must be non-empty")
        if len(self.edges) != len(self.nodes) - 1:
            raise ValueError(
                "ChainPlan.edges must have exactly len(nodes)-1 entries; "
                f"got nodes={len(self.nodes)} edges={len(self.edges)}"
            )
        for idx, edge in enumerate(self.edges):
            if edge.src != self.nodes[idx]:
                raise ValueError(f"ChainPlan edge[{idx}].src={edge.src} does not match nodes[{idx}]={self.nodes[idx]}")
            if edge.dst != self.nodes[idx + 1]:
                raise ValueError(
                    f"ChainPlan edge[{idx}].dst={edge.dst} does not match nodes[{idx + 1}]={self.nodes[idx + 1]}"
                )
        seen: set[str] = set()
        for node_id in self.nodes:
            if node_id in seen:
                raise ValueError(f"ChainPlan revisits node {node_id} — chains may not loop or re-enter a node")
            seen.add(node_id)


def make_chain_id(nodes: Iterable[str], edges: Iterable[ChainEdge]) -> str:
    """Deterministic content hash over a plan's nodes + edges.

    The hash is the same length / shape as ``Variant.variant_id`` (12-char
    blake2b hex) so chain ids interleave cleanly in JSONL transcripts.
    """
    h = hashlib.blake2b(digest_size=12)
    for node_id in nodes:
        h.update(b"node:")
        h.update(node_id.encode("utf-8"))
        h.update(b"\x00")
    for edge in edges:
        h.update(b"edge:")
        h.update(edge.src.encode("utf-8"))
        h.update(b"->")
        h.update(edge.dst.encode("utf-8"))
        h.update(b":")
        h.update(edge.artefact.encode("utf-8"))
        h.update(f":{edge.weight:.6f}".encode())
        h.update(b"\x00")
    return h.hexdigest()


def _norm_keys(values: Iterable[Any]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        if not isinstance(v, str) or not v:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    out.sort()
    return tuple(out)


@dataclass(slots=True)
class ChainGraph:
    """Mutable typed registry of ``ChainNode`` + ``ChainEdge``.

    Mutability is restricted to ``add_node`` / ``add_edge``; the graph
    itself is never edited in place after construction in production
    code (the test-only ``reset()`` exists for unit-test isolation).
    The ``signature`` property provides a stable hash of the registry
    contents so a graph can be compared across runs without hashing
    a non-frozen dataclass.
    """

    _nodes: dict[str, ChainNode] = field(default_factory=dict)
    _edges: list[ChainEdge] = field(default_factory=list)

    def add_node(self, node: ChainNode) -> ChainNode:
        if node.class_id in self._nodes:
            raise ValueError(f"duplicate ChainGraph node registration: {node.class_id}")
        self._nodes[node.class_id] = node
        return node

    def add_edge(self, edge: ChainEdge) -> ChainEdge:
        if edge.src not in self._nodes:
            raise KeyError(f"ChainEdge.src node not registered: {edge.src}")
        if edge.dst not in self._nodes:
            raise KeyError(f"ChainEdge.dst node not registered: {edge.dst}")
        src = self._nodes[edge.src]
        dst = self._nodes[edge.dst]
        if edge.artefact not in src.produces:
            raise ValueError(f"ChainEdge artefact {edge.artefact!r} is not in {edge.src}.produces={src.produces}")
        if edge.artefact not in dst.consumes:
            raise ValueError(f"ChainEdge artefact {edge.artefact!r} is not in {edge.dst}.consumes={dst.consumes}")
        for existing in self._edges:
            if existing.src == edge.src and existing.dst == edge.dst and existing.artefact == edge.artefact:
                raise ValueError(f"duplicate ChainEdge: {edge.src}->{edge.dst} ({edge.artefact})")
        self._edges.append(edge)
        return edge

    def has_node(self, class_id: str) -> bool:
        return class_id in self._nodes

    def get_node(self, class_id: str) -> ChainNode:
        return self._nodes[class_id]

    def nodes(self) -> tuple[ChainNode, ...]:
        """Nodes in deterministic content-hash order."""
        return tuple(sorted(self._nodes.values(), key=lambda n: _node_sort_key(n)))

    def edges(self) -> tuple[ChainEdge, ...]:
        """Edges in deterministic content-hash order."""
        return tuple(sorted(self._edges, key=_edge_sort_key))

    def edges_from(self, class_id: str) -> tuple[ChainEdge, ...]:
        """Edges whose ``src == class_id``, deterministic order."""
        return tuple(
            sorted(
                (e for e in self._edges if e.src == class_id),
                key=_edge_sort_key,
            )
        )

    def valid_heads(self, recon: ReconProfile) -> tuple[ChainNode, ...]:
        """Nodes whose ``consumes`` set is satisfied by ``recon``.

        Order is deterministic (content-hash ascending). A node with no
        consumed artefacts is always a valid head.
        """
        return tuple(n for n in self.nodes() if n.consumes_satisfied_by(recon))

    def successors(self, class_id: str, recon: ReconProfile) -> tuple[tuple[ChainEdge, ChainNode], ...]:
        """Outgoing edges where the destination's consumes are satisfied
        by ``recon`` extended with the edge's carried artefact.

        Used by beam search to expand a partial chain. ``recon`` is the
        synthesised recon profile after every preceding step's simulated
        produces have been merged in.
        """
        out: list[tuple[ChainEdge, ChainNode]] = []
        for edge in self.edges_from(class_id):
            dst = self._nodes[edge.dst]
            # The edge guarantees the artefact is in dst.consumes; the
            # rest of dst.consumes must be satisfied by recon.
            if not dst.consumes_satisfied_by(recon):
                continue
            out.append((edge, dst))
        out.sort(key=lambda pair: _edge_sort_key(pair[0]))
        return tuple(out)

    def __iter__(self) -> Iterator[ChainNode]:
        return iter(self.nodes())

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def signature(self) -> str:
        """Stable content hash over (nodes, edges) for cross-run comparison."""
        h = hashlib.blake2b(digest_size=16)
        for node in self.nodes():
            h.update(b"N:")
            h.update(node.class_id.encode("utf-8"))
            h.update(b":")
            h.update(node.layer.encode("utf-8"))
            h.update(b":")
            h.update(",".join(node.produces).encode("utf-8"))
            h.update(b"|")
            h.update(",".join(node.consumes).encode("utf-8"))
            h.update(b"\x00")
        for edge in self.edges():
            h.update(b"E:")
            h.update(edge.src.encode("utf-8"))
            h.update(b"->")
            h.update(edge.dst.encode("utf-8"))
            h.update(b":")
            h.update(edge.artefact.encode("utf-8"))
            h.update(f":{edge.weight:.6f}".encode())
            h.update(b"\x00")
        return h.hexdigest()

    def reset(self) -> None:
        """Test-only helper: clear all registrations."""
        self._nodes.clear()
        self._edges.clear()


def _node_sort_key(node: ChainNode) -> str:
    h = hashlib.blake2b(digest_size=8)
    h.update(node.class_id.encode("utf-8"))
    return h.hexdigest()


def _edge_sort_key(edge: ChainEdge) -> str:
    h = hashlib.blake2b(digest_size=8)
    h.update(edge.src.encode("utf-8"))
    h.update(b"->")
    h.update(edge.dst.encode("utf-8"))
    h.update(b":")
    h.update(edge.artefact.encode("utf-8"))
    return h.hexdigest()


__all__ = [
    "ArtefactKey",
    "ChainEdge",
    "ChainGraph",
    "ChainNode",
    "ChainPlan",
    "make_chain_id",
]
