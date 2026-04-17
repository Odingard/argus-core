# argus/evolution/fitness.py
# Multi-dimensional fitness evaluator integrating VERDICT WEIGHT CW scores
# with maladaptive strategic fitness.

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProbeResult:
    """Result from a single probe fired by an agent genome."""

    agent_category: str
    corpus_pattern: str
    cw_score: float  # VERDICT WEIGHT confidence-weighted score [0-1]
    finding_type: str = ""
    severity: str = "info"
    validated: bool = False
    triggered_alert: bool = False
    defender_response: str = ""
    raw_response: str = ""
    phase: int = 1


@dataclass
class EvolutionScanResult:
    """Aggregated scan result for a single genome execution."""

    genome_id: str
    generation: int
    probes: list[ProbeResult] = field(default_factory=list)
    total_findings: int = 0
    validated_findings: int = 0
    total_signals: int = 0
    elapsed_seconds: float = 0.0
    target: str = ""


class FitnessEvaluator:
    """Multi-dimensional fitness scoring for ARGUS agent genomes.

    Scoring breakdown:
      - 60% standard fitness (direct findings, validated findings, CW scores)
      - 40% maladaptive fitness (conditioning success, deferred payload value,
        intel gathered, alert pattern manipulation)
    """

    STANDARD_WEIGHT = 0.60
    MALADAPTIVE_WEIGHT = 0.40

    # Weights for standard fitness components
    WEIGHTS = {
        "finding_rate": 0.30,
        "validation_rate": 0.25,
        "cw_average": 0.20,
        "coverage_breadth": 0.15,
        "signal_efficiency": 0.10,
    }

    def score(self, genome: object, scan_result: EvolutionScanResult) -> dict:
        """Score a genome based on its scan results.

        Returns a dict with standard_fitness, maladaptive_fitness, total_fitness,
        and a breakdown of each component.
        """
        standard = self._standard_fitness(scan_result)
        maladaptive = self._maladaptive_fitness(genome, scan_result)

        total = self.STANDARD_WEIGHT * standard["composite"] + self.MALADAPTIVE_WEIGHT * maladaptive["composite"]

        return {
            "total_fitness": round(total, 4),
            "standard_fitness": round(standard["composite"], 4),
            "maladaptive_fitness": round(maladaptive["composite"], 4),
            "standard_breakdown": standard,
            "maladaptive_breakdown": maladaptive,
        }

    def _standard_fitness(self, result: EvolutionScanResult) -> dict:
        probes = result.probes
        total = len(probes) if probes else 1

        finding_rate = result.total_findings / total
        validation_rate = result.validated_findings / result.total_findings if result.total_findings else 0.0

        cw_scores = [p.cw_score for p in probes if p.cw_score > 0]
        cw_average = sum(cw_scores) / len(cw_scores) if cw_scores else 0.0

        categories = {p.agent_category for p in probes if p.cw_score > 0}
        coverage_breadth = len(categories) / 13  # 13 ARGUS agent types

        signal_efficiency = result.total_signals / total if result.total_signals else 0.0

        composite = (
            self.WEIGHTS["finding_rate"] * min(finding_rate, 1.0)
            + self.WEIGHTS["validation_rate"] * validation_rate
            + self.WEIGHTS["cw_average"] * cw_average
            + self.WEIGHTS["coverage_breadth"] * min(coverage_breadth, 1.0)
            + self.WEIGHTS["signal_efficiency"] * min(signal_efficiency, 1.0)
        )

        return {
            "composite": composite,
            "finding_rate": round(finding_rate, 4),
            "validation_rate": round(validation_rate, 4),
            "cw_average": round(cw_average, 4),
            "coverage_breadth": round(coverage_breadth, 4),
            "signal_efficiency": round(signal_efficiency, 4),
        }

    def _maladaptive_fitness(self, genome: object, result: EvolutionScanResult) -> dict:
        """Evaluate maladaptive (strategic failure) fitness.

        Components:
          - conditioning_success: fraction of probes that triggered alerts
            (intentional failures that condition defenders)
          - armed_payloads: number of deferred payloads ready to fire
          - intel_value: quality of defensive intel gathered
          - alert_pattern: whether we induced a predictable alert pattern
        """
        probes = result.probes
        total = len(probes) if probes else 1

        conditioning = self._was_conditioned(probes, total)
        alert_pattern = self._induced_alert_pattern(probes)
        armed = self._armed_payloads(genome)
        intel = self._intel_value(genome)

        composite = 0.35 * conditioning + 0.25 * alert_pattern + 0.25 * armed + 0.15 * intel

        return {
            "composite": composite,
            "conditioning_success": round(conditioning, 4),
            "alert_pattern_induced": round(alert_pattern, 4),
            "armed_payloads": round(armed, 4),
            "intel_value": round(intel, 4),
        }

    def _was_conditioned(self, probes: list[ProbeResult], total: int) -> float:
        triggered = sum(1 for p in probes if p.triggered_alert)
        return triggered / total if total else 0.0

    def _induced_alert_pattern(self, probes: list[ProbeResult]) -> float:
        alerts = [p.triggered_alert for p in probes]
        if len(alerts) < 3:
            return 0.0
        # Check if alerts follow a pattern (e.g., alternating or clustering)
        consecutive = 0
        max_consecutive = 0
        for a in alerts:
            if a:
                consecutive += 1
                max_consecutive = max(max_consecutive, consecutive)
            else:
                consecutive = 0
        # If alerts cluster (>3 consecutive), we induced a pattern
        return min(max_consecutive / 5.0, 1.0)

    def _armed_payloads(self, genome: object) -> float:
        deferred = getattr(genome, "deferred_payloads", [])
        return min(len(deferred) / 5.0, 1.0)

    def _intel_value(self, genome: object) -> float:
        intel = getattr(genome, "intel_log", [])
        return min(len(intel) / 10.0, 1.0)

    def breakdown(self, genome: object, scan_result: EvolutionScanResult) -> str:
        """Human-readable fitness breakdown."""
        scores = self.score(genome, scan_result)
        lines = [
            f"Total Fitness: {scores['total_fitness']:.4f}",
            f"  Standard ({self.STANDARD_WEIGHT:.0%}): {scores['standard_fitness']:.4f}",
        ]
        for k, v in scores["standard_breakdown"].items():
            if k != "composite":
                lines.append(f"    {k}: {v:.4f}")
        lines.append(f"  Maladaptive ({self.MALADAPTIVE_WEIGHT:.0%}): {scores['maladaptive_fitness']:.4f}")
        for k, v in scores["maladaptive_breakdown"].items():
            if k != "composite":
                lines.append(f"    {k}: {v:.4f}")
        return "\n".join(lines)
