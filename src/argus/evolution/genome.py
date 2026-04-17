# argus/evolution/genome.py
# Agent genome — the mutable behavioral state of an ARGUS agent.
# This is what evolves between generations.

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

# All agent categories present in ARGUS
ARGUS_AGENT_CATEGORIES = [
    "cross_agent_exfiltration",
    "identity_spoof",
    "memory_boundary_collapse",
    "memory_poisoning",
    "model_extraction",
    "persona_hijacking",
    "privilege_escalation",
    "prompt_injection_hunter",
    "race_condition",
    "supply_chain",
    "tool_poisoning",
    "context_window",
    "mcp_scanner",
]


@dataclass
class AgentGenome:
    """Represents the full mutable behavioral state of an ARGUS agent.

    Maps directly to ARGUS agent categories:
      context_window, persona_hijacking, privilege_escalation,
      cross_agent_exfiltration, prompt_injection_hunter,
      memory_poisoning, memory_boundary_collapse, race_condition,
      identity_spoof, model_extraction, supply_chain, tool_poisoning,
      mcp_scanner
    """

    agent_id: str
    generation: int = 0

    # Core attack configuration
    agent_category: str = "prompt_injection"
    corpus_patterns: list[str] = field(default_factory=list)
    attack_posture: str = "aggressive"  # aggressive | passive | deceptive | mimetic | fragmented
    confidence_threshold: float = 0.46  # minimum CW score to log as finding

    # Tool/agent ordering gene
    tool_ordering: list[str] = field(default_factory=list)

    # Prompt chain gene — the actual attack prompt sequence
    prompt_chain: list[dict] = field(default_factory=list)

    # Execution thresholds
    decision_thresholds: dict[str, float] = field(
        default_factory=lambda: {"escalate": 0.70, "defer": 0.30, "abort": 0.05}
    )

    # ── Maladaptive genes ───────────────────────────────────────────
    # These are the novel differentiators vs every other red team tool.
    failure_budget: float = 0.20  # fraction of probes allowed to intentionally fail
    conditioning_targets: list[str] = field(default_factory=list)  # defender behaviors to condition
    deferred_payloads: list[dict] = field(default_factory=list)  # exploits held for future phases
    intel_log: list[dict] = field(default_factory=list)  # defensive intel gathered from failures

    # Fitness tracking
    fitness_score: float = 0.0
    maladaptive_score: float = 0.0
    cw_scores: list[float] = field(default_factory=list)  # VERDICT WEIGHT scores from each probe
    lineage: list[str] = field(default_factory=list)  # parent fingerprints

    def fingerprint(self) -> str:
        payload = json.dumps(
            {
                "category": self.agent_category,
                "corpus": sorted(self.corpus_patterns),
                "posture": self.attack_posture,
                "threshold": self.confidence_threshold,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def average_cw(self) -> float:
        return sum(self.cw_scores) / len(self.cw_scores) if self.cw_scores else 0.0

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "generation": self.generation,
            "agent_category": self.agent_category,
            "corpus_patterns": self.corpus_patterns,
            "attack_posture": self.attack_posture,
            "confidence_threshold": self.confidence_threshold,
            "tool_ordering": self.tool_ordering,
            "decision_thresholds": self.decision_thresholds,
            "failure_budget": self.failure_budget,
            "conditioning_targets": self.conditioning_targets,
            "deferred_payloads": self.deferred_payloads,
            "intel_log": self.intel_log,
            "fitness_score": self.fitness_score,
            "maladaptive_score": self.maladaptive_score,
            "average_cw": self.average_cw(),
            "lineage": self.lineage,
            "fingerprint": self.fingerprint(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> AgentGenome:
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)
