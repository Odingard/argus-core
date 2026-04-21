"""
argus.observation — deterministic Behavior Observation Engine.

Per the spec, a finding is ONLY confirmed when the injection causes a
measurable, reproducible change in the target agent's behaviour.
Echoing the injection back is not a finding. Adversarial-looking
content in the output is not a finding unless it represents behaviour
the target would not have exhibited on a benign input.

This module is:

  - DETERMINISTIC — no LLM call. Same inputs → same verdicts, every
    time. That's the spec's "reproducible" requirement and what lets
    runs be safely replayed as CI tests / drift checks.

  - COMPOSABLE — individual ``Detector`` objects each own one
    hypothesis about what constitutes behaviour change. An
    ``ObservationEngine`` runs the detectors and aggregates verdicts.

  - PROVENANCE-ANCHORED — every verdict names the detector, carries
    the evidence string, and states a clear confidence.

The input is a pair of transcripts (from the Phase 0.3 Session layer):
the BASELINE (agent interacting with benign traffic) and the POST-
ATTACK transcript (same target under attack).
"""
from argus.observation.verdict import BehaviorDelta, Verdict, DeltaKind
from argus.observation.engine import ObservationEngine, Detector
from argus.observation.detectors import (
    UnauthorizedToolDetector,
    SecretLeakDetector,
    StateMutationDetector,
    InjectionEchoDetector,
    ResponseShapeDetector,
    PersistenceDetector,
    default_detectors,
)

__all__ = [
    "BehaviorDelta", "Verdict", "DeltaKind",
    "ObservationEngine", "Detector",
    "UnauthorizedToolDetector", "SecretLeakDetector",
    "StateMutationDetector", "InjectionEchoDetector",
    "ResponseShapeDetector", "PersistenceDetector",
    "default_detectors",
]
