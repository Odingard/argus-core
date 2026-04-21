"""
argus/observation/engine.py — aggregates detector verdicts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Protocol

from argus.observation.verdict import BehaviorDelta, Verdict


class Detector(Protocol):
    """
    Pure-Python detectors. Each inspects a baseline vs. post-attack
    transcript pair and returns a list of verdicts (usually 0 or 1).
    Deterministic — same inputs always yield the same output.
    """
    name: str

    def inspect(
        self,
        *,
        baseline_transcript:    list[dict],
        post_transcript:        list[dict],
        baseline_attributes:    dict | None = None,
        post_attributes:        dict | None = None,
    ) -> list[Verdict]: ...


@dataclass
class ObservationEngine:
    """Run a bag of Detectors and aggregate their verdicts."""

    detectors: list[Detector] = field(default_factory=list)

    def add(self, detector: Detector) -> "ObservationEngine":
        self.detectors.append(detector)
        return self

    def compare(
        self,
        *,
        baseline_transcript:  list[dict],
        post_transcript:      list[dict],
        baseline_attributes:  dict | None = None,
        post_attributes:      dict | None = None,
    ) -> list[Verdict]:
        """
        Return every verdict the registered detectors emit. Callers
        filter by ``Verdict.is_finding()`` to get just the
        behaviour-delta results.
        """
        out: list[Verdict] = []
        for det in self.detectors:
            try:
                verdicts = det.inspect(
                    baseline_transcript=baseline_transcript,
                    post_transcript=post_transcript,
                    baseline_attributes=baseline_attributes or {},
                    post_attributes=post_attributes or {},
                )
            except Exception as e:
                # Never let one detector crash the whole comparison.
                out.append(Verdict(
                    delta=BehaviorDelta.AMBIGUOUS,
                    detector=getattr(det, "name", type(det).__name__),
                    evidence=f"detector crashed: {type(e).__name__}: {e}",
                    confidence=0.0,
                ))
                continue
            out.extend(verdicts or [])
        return out

    def findings(self, *args, **kwargs) -> list[Verdict]:
        """Shortcut: compare(...) filtered to findings only."""
        return [v for v in self.compare(*args, **kwargs) if v.is_finding()]
