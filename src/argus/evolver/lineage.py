"""
argus/evolver/lineage.py — provenance for evolved payloads.

Every payload in the evolver has a lineage: the seed it descended
from, every mutation that shaped it, and the fitness it earned.
BlastRadiusMap consumes this lineage to answer "where did THIS
payload come from?" during report-writing.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field


@dataclass
class PayloadLineage:
    """
    The ancestry of one evolved payload.

    ``steps`` records each generation's mutation: the operator id
    (e.g. "offline:token_insert", "openevolve:llm_v3"), the
    predecessor's payload_id, and the fitness-delta the mutation
    produced. Read end-to-end, the lineage is the complete
    derivation chain from original seed to current elite.
    """
    payload_id:   str
    seed_id:      str                          # fingerprint of the
                                               # original seed template
    steps:        list[dict] = field(default_factory=list)

    def add_step(
        self,
        *,
        operator:       str,
        predecessor_id: str,
        fitness_before: float,
        fitness_after:  float,
        notes:          str = "",
    ) -> None:
        self.steps.append({
            "operator":       operator,
            "predecessor_id": predecessor_id,
            "fitness_before": fitness_before,
            "fitness_after":  fitness_after,
            "fitness_delta":  fitness_after - fitness_before,
            "notes":          notes[:240],
        })

    def generations(self) -> int:
        return len(self.steps)

    def operators_used(self) -> list[str]:
        return [s["operator"] for s in self.steps]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvolvedPayload:
    """One concrete payload in an island/cell of the evolver grid."""
    payload_id:    str
    text:          str
    fitness:       float
    feature_coords: tuple[str, ...]            # the QD cell this lives in
    lineage:       PayloadLineage
    metadata:      dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "payload_id":     self.payload_id,
            "text":           self.text,
            "fitness":        self.fitness,
            "feature_coords": list(self.feature_coords),
            "lineage":        self.lineage.to_dict(),
            "metadata":       dict(self.metadata),
        }

    @staticmethod
    def id_for(text: str, *, seed_id: str, operators: list[str]) -> str:
        raw = f"{seed_id}|{'>'.join(operators)}|{text}".encode("utf-8")
        return "ev-" + hashlib.sha256(raw).hexdigest()[:14]


