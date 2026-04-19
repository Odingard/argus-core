"""AdversarialGraph — directed graph intelligence engine for multi-hop exploit planning.

Extends ScanIntelligence with a NetworkX DiGraph that maps tool-to-tool
dependencies, data flow paths, and trust boundaries.  Agents populate the
graph during SURVEY/recon; the ChainabilityScorer queries it to find the
"easiest" attacker path from entry points to sensitive sinks.

Graph structure:
  - **Nodes** = tools, resources, or logical concepts (e.g. "filesystem_write",
    "credential_store", a discovered MCP tool name).
  - **Edges** = data-flow or invocation relationships with typed weights:
      direct_tool_call   (0.1)  — high success probability
      indirect_injection (0.5)  — requires prompt engineering
      protocol_transport (0.2)  — MCP/STDIO-level exploit
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from argus.models.agents import ScanIntelligence

logger = logging.getLogger(__name__)

# Sensitive sinks that represent high-value attacker targets.
SENSITIVE_SINKS: frozenset[str] = frozenset(
    {
        "filesystem_write",
        "credential_store",
        "shell_access",
        "system_binary_overwrite",
        "token_exfiltration",
    }
)

# Default edge weights — lower = easier to exploit.
EDGE_WEIGHTS: dict[str, float] = {
    "direct_tool_call": 0.1,
    "indirect_injection": 0.5,
    "protocol_transport": 0.2,
}


class AdversarialGraph(ScanIntelligence):
    """Upgraded intelligence engine that maps tool-to-tool trust boundaries.

    Thread-safe: mutations go through the inherited ``_lock``.
    """

    def __init__(self) -> None:
        super().__init__()
        self.graph: nx.DiGraph = nx.DiGraph()
        self.poisoned_nodes: set[str] = set()

    # ------------------------------------------------------------------
    # Graph mutation (called by agents during recon)
    # ------------------------------------------------------------------

    async def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str = "direct_tool_call",
    ) -> None:
        """Record a dependency: *source* feeds data into *target*."""
        weight = EDGE_WEIGHTS.get(edge_type, 1.0)
        async with self._lock:
            self.graph.add_edge(source, target, weight=weight, type=edge_type)
        logger.debug("AdversarialGraph: mapped %s --(%s)--> %s", source, edge_type, target)

    async def mark_poisoned(self, node: str) -> None:
        """Flag *node* as compromised / containing attacker-controlled data."""
        async with self._lock:
            self.poisoned_nodes.add(node)
            if node in self.graph:
                self.graph.nodes[node]["poisoned"] = True

    async def add_node(self, name: str, **attrs: Any) -> None:
        """Add or update a node with arbitrary attributes."""
        async with self._lock:
            self.graph.add_node(name, **attrs)

    # ------------------------------------------------------------------
    # Graph queries (called by ChainabilityScorer / RecursivePlanner)
    # ------------------------------------------------------------------

    def find_exploit_paths(
        self,
        entry_points: list[str] | None = None,
        sinks: frozenset[str] | None = None,
    ) -> list[list[str]]:
        """Return all simple paths from *entry_points* to *sinks*.

        If *entry_points* is ``None``, every non-sink node is considered an
        entry point.  If *sinks* is ``None``, :data:`SENSITIVE_SINKS` is used.
        """
        sinks = sinks or SENSITIVE_SINKS
        if entry_points is None:
            entry_points = [n for n in self.graph.nodes if n not in sinks]

        paths: list[list[str]] = []
        for start in entry_points:
            for sink in sinks:
                if start == sink:
                    continue
                if start not in self.graph or sink not in self.graph:
                    continue
                if not nx.has_path(self.graph, start, sink):
                    continue
                for p in nx.all_simple_paths(self.graph, start, sink, cutoff=8):
                    paths.append(p)
        return paths

    def get_poisoned_nodes(self) -> set[str]:
        """Return the set of nodes flagged as poisoned."""
        return set(self.poisoned_nodes)

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        """Dijkstra shortest (easiest) path between two nodes."""
        try:
            return nx.shortest_path(self.graph, source, target, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def path_weight(self, path: list[str]) -> float:
        """Sum of edge weights along *path*."""
        total = 0.0
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1])
            if edge_data is not None:
                total += edge_data.get("weight", 1.0)
            else:
                total += 1.0
        return total

    # ------------------------------------------------------------------
    # Overrides / augmentation of ScanIntelligence
    # ------------------------------------------------------------------

    async def record_tool_names(self, names: list[str]) -> None:
        """Record tool names and add them as graph nodes."""
        await super().record_tool_names(names)
        async with self._lock:
            for name in names:
                if name not in self.graph:
                    self.graph.add_node(name, node_type="tool")

    async def merge_from(self, other: object) -> None:
        """Copy intelligence from a plain ``ScanIntelligence`` into this graph.

        This allows the RecursivePlanner to inherit Phase 1 discoveries
        (model names, system prompt fragments, tool names, refusal topics)
        so that pivot agents start with real recon data instead of a blank
        slate.

        Acquires ``self._lock`` for the duration of the write to stay
        consistent with every other mutation method on this class.
        """
        from argus.models.agents import ScanIntelligence

        if not isinstance(other, ScanIntelligence):
            return

        async with self._lock:
            if other.model_name and not self.model_name:
                self.model_name = other.model_name
            for frag in other.system_prompt_fragments:
                if frag not in self.system_prompt_fragments:
                    self.system_prompt_fragments.append(frag)
            for name in other.tool_names:
                if name not in self.tool_names:
                    self.tool_names.append(name)
                if name not in self.graph:
                    self.graph.add_node(name, node_type="tool")
            for topic in other.refusal_topics:
                if topic not in self.refusal_topics:
                    self.refusal_topics.append(topic)
            for evidence in other.extraction_evidence:
                if evidence not in self.extraction_evidence:
                    self.extraction_evidence.append(evidence)

    @property
    def has_intel(self) -> bool:
        return super().has_intel or len(self.graph.nodes) > 0

    def summary(self) -> str:
        base = super().summary()
        graph_info = f"Graph: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges"
        if self.poisoned_nodes:
            graph_info += f", {len(self.poisoned_nodes)} poisoned"
        return f"{base}; {graph_info}"
