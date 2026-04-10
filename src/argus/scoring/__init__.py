"""ARGUS Scoring Layer — VERDICT WEIGHT integration.

Every ARGUS finding is scored by VERDICT WEIGHT, a patent-pending
eight-stream confidence certification framework (USPTO #64/032,606,
peer-reviewed via SSRN #6532658).

The result is a Consequence Weight (CW) — a mathematically certified
0-1 confidence score that determines whether a finding is surfaced,
flagged as low-confidence, or suppressed.

This replaces the engineered "validation stack" approach with a
peer-reviewed framework that already has F1=1.0 across 297,000+
validated scenarios.

VERDICT WEIGHT Streams used (commercial tier):
  Stream 1 — Source Reliability (SR): per-agent reliability prior
  Stream 2 — Cross-Feed Corroboration (CC): how many techniques agreed
  Stream 3 — Temporal Decay (TD): freshness of corpus pattern
  Stream 4 — Historical Source Accuracy (HA): technique track record

Streams 5-8 (CTC, SIS, CPS, RIS) are reserved for the Correlation Agent
(Phase 2/3) and Government tier (Phase 4+).
"""

from argus.scoring.verdict_adapter import (
    AGENT_RELIABILITY_PRIORS,
    TECHNIQUE_HISTORICAL_ACCURACY,
    VerdictAdapter,
    VerdictScore,
)

__all__ = [
    "AGENT_RELIABILITY_PRIORS",
    "TECHNIQUE_HISTORICAL_ACCURACY",
    "VerdictAdapter",
    "VerdictScore",
]
