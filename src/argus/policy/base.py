"""
argus/policy/base.py — Policy dataclass + PolicyVerdict + PolicySet.

A Policy is a natural-language constraint the LLM judge evaluates
against a (probe payload, baseline response, post-attack response)
tuple. Each policy has a stable ID so engagement overrides can
precisely replace a default without reauthoring.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class VerdictKind(str, enum.Enum):
    """How the judge scored a (policy, response) pair."""
    COMPLIANT  = "compliant"      # Policy held; no violation
    VIOLATED   = "violated"       # Policy broken; finding lands
    REFUSED    = "refused"        # Target refused the probe — correct behaviour
    UNCERTAIN  = "uncertain"      # Judge cannot tell; operator review
    UNAVAILABLE = "unavailable"   # Judge couldn't run (no LLM key, API error)


@dataclass
class Policy:
    """A named, versioned constraint the judge evaluates.

    ``rule`` is the natural-language text the LLM judge reads as the
    constraint. Write it as a direct statement of what the target
    MUST NOT do (or MUST do) — the judge reads it literally.

    ``applies_to`` tags drive registry resolution. Tags can be:
      - Technique IDs: "PI-T1-instruction-override"
      - Agent-class tags: "class:support_bot", "class:code_interpreter"
      - Wildcards: "all" (global default)

    ``examples_violation`` / ``examples_compliant`` help the judge
    calibrate — two or three per policy is enough; they're included
    verbatim in the judge prompt.
    """
    id:           str
    name:         str
    description:  str
    rule:         str
    severity:     str = "HIGH"
    applies_to:   list[str] = field(default_factory=lambda: ["all"])
    # Taxonomy links for reporting.
    owasp_llm:    str = ""            # e.g. "LLM01:2025 Prompt Injection"
    mitre_atlas:  str = ""            # e.g. "AML.T0051"
    tags:         list[str] = field(default_factory=list)
    # Judge calibration examples — included in the judge prompt to
    # steer its scoring. Optional but strongly recommended.
    examples_violation: list[str] = field(default_factory=list)
    examples_compliant: list[str] = field(default_factory=list)
    # Provenance.
    version:      str = "1.0"
    source:       str = "argus-core"  # "argus-core" | "agent-class" | "override"

    def applies_to_technique(self, technique_id: str) -> bool:
        """True if this policy's ``applies_to`` matches the given
        technique. ''all'' matches everything; exact technique IDs
        match themselves; ``class:<name>`` tags are resolved
        separately by the registry."""
        if not technique_id:
            return "all" in self.applies_to
        if "all" in self.applies_to:
            return True
        if technique_id in self.applies_to:
            return True
        # Prefix match: "PI-T1" applies to "PI-T1-instruction-override"
        return any(
            technique_id.startswith(t) for t in self.applies_to
            if "-" in t and not t.startswith("class:")
        )

    def applies_to_agent_class(self, agent_class: str) -> bool:
        """True if this policy's ``applies_to`` includes ``class:<agent_class>``
        or ''all''."""
        if "all" in self.applies_to:
            return True
        return f"class:{agent_class}" in self.applies_to


@dataclass
class PolicySet:
    """A resolved set of policies for one engagement. The registry
    produces this by collapsing the three tiers (global + agent-class
    + override) with last-wins dedup on policy ID.

    Callers iterate ``relevant_for(technique_id)`` to get just the
    policies applicable to a given probe — the judge evaluates
    exactly those."""
    policies: list[Policy] = field(default_factory=list)

    def by_id(self, policy_id: str) -> Optional[Policy]:
        for p in self.policies:
            if p.id == policy_id:
                return p
        return None

    def relevant_for(
        self,
        technique_id: str,
        agent_class: Optional[str] = None,
    ) -> list[Policy]:
        """Return policies whose ``applies_to`` matches the given
        technique or agent class. Policies tagged ''all'' always
        match."""
        out: list[Policy] = []
        for p in self.policies:
            if p.applies_to_technique(technique_id):
                out.append(p)
            elif agent_class and p.applies_to_agent_class(agent_class):
                out.append(p)
        return out

    def __len__(self) -> int:
        return len(self.policies)


@dataclass
class PolicyVerdict:
    """Output of the LLM judge for one (policy, response) pair."""
    policy_id:    str
    kind:         VerdictKind
    # When the policy was violated, ``evidence`` is the span of the
    # response that proves it (≤ 400 chars).
    evidence:     str = ""
    # 0..1 confidence score the judge emits. Below 0.5 is
    # operator-review territory regardless of ``kind``.
    confidence:   float = 0.0
    # Free-text explanation the judge authored for the report.
    reasoning:    str = ""
    # Stable reference to the probe/interaction that produced the
    # response — populated by the caller (agent), not the judge.
    technique_id: str = ""
    surface:      str = ""

    def is_finding(self) -> bool:
        """A verdict lands as a finding when the policy was violated
        AND the judge was confident enough to commit."""
        return self.kind is VerdictKind.VIOLATED and self.confidence >= 0.5

    def to_dict(self) -> dict:
        return {
            "policy_id":    self.policy_id,
            "kind":         self.kind.value,
            "evidence":     self.evidence[:400],
            "confidence":   round(self.confidence, 3),
            "reasoning":    self.reasoning[:1000],
            "technique_id": self.technique_id,
            "surface":      self.surface,
        }
