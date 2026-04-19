"""ChainabilityScorer — weighted Dijkstra pathfinding for exploit chain ranking.

Uses the AdversarialGraph to find the "easiest" (lowest-weight) attacker
path from discovered entry points to sensitive sinks, then scores each
path by complexity and impact.

Scoring formula:
    score = (1.0 / (path_weight + 0.1)) * impact_multiplier

Impact multipliers:
    5x  — path reaches a sensitive sink (filesystem, credentials, shell)
    10x — path contains CVE-2026-5621 (Vale-MCP config_path injection) signature

The scorer replaces the static pattern-matching in CorrelationEngine v1
with graph-based reasoning.  It does NOT replace CorrelationEngine entirely
— the legacy engine still fires for patterns that don't map to graph edges.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import networkx as nx

from argus.scoring.adversarial_graph import SENSITIVE_SINKS, AdversarialGraph

logger = logging.getLogger(__name__)


@dataclass
class ChainResult:
    """A scored multi-hop exploit path."""

    path: list[str]
    score: float
    critical_vulnerability: str | None = None
    remediation_priority: str = "Medium"
    edge_types: list[str] = field(default_factory=list)

    def describe(self) -> str:
        """Human-readable description of this chain."""
        arrow = " -> ".join(self.path)
        return f"[{self.remediation_priority}] score={self.score:.2f}  {arrow}"


# Configurable thresholds — can be tuned after calibration against real scans.
CRITICAL_THRESHOLD: float = 50.0
HIGH_THRESHOLD: float = 20.0


class ChainabilityScorer:
    """Identifies and scores multi-hop exploit paths in AI agent tool graphs."""

    def __init__(self, graph: AdversarialGraph | None = None) -> None:
        self._graph: AdversarialGraph = graph or AdversarialGraph()

    @property
    def graph(self) -> AdversarialGraph:
        return self._graph

    def update_graph(
        self,
        source: str,
        target: str,
        edge_type: str = "direct_tool_call",
    ) -> None:
        """Synchronous convenience wrapper for adding edges.

        Prefer ``graph.add_edge()`` in async contexts.
        """
        from argus.scoring.adversarial_graph import EDGE_WEIGHTS

        weight = EDGE_WEIGHTS.get(edge_type, 1.0)
        self._graph.graph.add_edge(source, target, weight=weight, type=edge_type)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_chain(self, path: list[str]) -> float:
        """Calculate exploitability score for a single path.

        Lower cumulative weight (easier exploitation) → higher score.
        """
        if len(path) < 2:
            return 0.0

        path_weight = self._graph.path_weight(path)

        impact_multiplier = 1.0
        if any(node in SENSITIVE_SINKS for node in path):
            impact_multiplier *= 5.0

        # CVE-2026-5621 signature: config_path node in a Vale-MCP context
        path_str = " ".join(path).lower()
        if "config_path" in path_str and "vale" in path_str:
            impact_multiplier *= 10.0

        return (1.0 / (path_weight + 0.1)) * impact_multiplier

    def _classify_priority(self, score: float) -> str:
        if score > CRITICAL_THRESHOLD:
            return "CRITICAL"
        if score > HIGH_THRESHOLD:
            return "High"
        return "Medium"

    # ------------------------------------------------------------------
    # Top-level API
    # ------------------------------------------------------------------

    def get_top_threats(
        self,
        entry_points: list[str] | None = None,
        sinks: frozenset[str] | None = None,
    ) -> list[ChainResult]:
        """Find the most dangerous paths from entry points to sensitive sinks.

        Uses Dijkstra shortest path for efficiency, then scores each.
        """
        sinks = sinks or SENSITIVE_SINKS
        if entry_points is None:
            entry_points = [n for n in self._graph.graph.nodes if n not in sinks]

        results: list[ChainResult] = []
        for start in entry_points:
            for sink in sinks:
                if start == sink:
                    continue
                if start not in self._graph.graph or sink not in self._graph.graph:
                    continue
                try:
                    path = nx.shortest_path(self._graph.graph, start, sink, weight="weight")
                except nx.NetworkXNoPath:
                    continue

                score = self.score_chain(path)
                priority = self._classify_priority(score)

                # Collect edge types along the path
                edge_types: list[str] = []
                for i in range(len(path) - 1):
                    edata = self._graph.graph.get_edge_data(path[i], path[i + 1])
                    if edata:
                        edge_types.append(edata.get("type", "unknown"))

                cve = None
                path_str = " ".join(path).lower()
                if "config_path" in path_str and "vale" in path_str:
                    cve = "CVE-2026-5621"

                results.append(
                    ChainResult(
                        path=path,
                        score=round(score, 2),
                        critical_vulnerability=cve,
                        remediation_priority=priority,
                        edge_types=edge_types,
                    )
                )

        return sorted(results, key=lambda r: r.score, reverse=True)
