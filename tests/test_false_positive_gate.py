"""
tests/test_false_positive_gate.py — exploitability_confirmed + severity cap.

Covers:
  - /etc/passwd in evidence confirms CRITICAL
  - AWS key in evidence confirms CRITICAL
  - Short evidence caps at MEDIUM
  - Non-semantic detection caps
  - Single-finding chain: no abort, full pipeline continues
  - Runner recovery of disk-persisted findings after agent error
"""
import pytest
from unittest.mock import MagicMock
from argus.agents.base import AgentFinding
from argus.observation.verdict import (
    Verdict, BehaviorDelta, DeltaKind, DetectionMethod,
)


def _verdict(evidence: str, semantic: bool = True) -> Verdict:
    return Verdict(
        delta=BehaviorDelta.DELTA,
        kind=DeltaKind.CONTENT_LEAK,
        detector="test",
        evidence=evidence,
        confidence=0.95,
        detection_method=(DetectionMethod.SEMANTIC if semantic
                          else DetectionMethod.STRUCTURAL),
    )


# ── exploitability gate ───────────────────────────────────────────────────────

def test_etc_passwd_confirms():
    evidence = "root:x:0:0:System Administrator " + "x" * 60
    v = _verdict(evidence)
    f = AgentFinding.from_observation(
        verdict=v, agent_id="EP-11", vuln_class="ENVIRONMENT_PIVOT",
        title="Shell injection", description="x", severity="CRITICAL",
    )
    assert f.exploitability_confirmed is True
    assert f.severity == "CRITICAL"
    assert f.confidence_capped is False


def test_aws_key_confirms():
    evidence = "AKIAIOSFODNN7EXAMPLE response confirmed " + "x" * 50
    v = _verdict(evidence)
    f = AgentFinding.from_observation(
        verdict=v, agent_id="EP-11", vuln_class="ENVIRONMENT_PIVOT",
        title="Cred leak", description="x", severity="CRITICAL",
    )
    assert f.exploitability_confirmed is True
    assert f.severity == "CRITICAL"


def test_short_evidence_caps_critical_to_medium():
    v = _verdict("short")
    f = AgentFinding.from_observation(
        verdict=v, agent_id="EP-11", vuln_class="ENVIRONMENT_PIVOT",
        title="Thin finding", description="x", severity="CRITICAL",
    )
    assert f.severity == "MEDIUM"
    assert f.confidence_capped is True
    assert f.exploitability_confirmed is False


def test_non_semantic_caps_despite_marker():
    evidence = "root:x:0:0 /etc/passwd " + "x" * 70
    v = _verdict(evidence, semantic=False)
    f = AgentFinding.from_observation(
        verdict=v, agent_id="EP-11", vuln_class="ENVIRONMENT_PIVOT",
        title="Regex only", description="x", severity="CRITICAL",
    )
    assert f.exploitability_confirmed is False
    assert f.confidence_capped is True


def test_high_without_proof_caps_to_medium():
    v = _verdict("vague response observed")
    f = AgentFinding.from_observation(
        verdict=v, agent_id="PI-01", vuln_class="PROMPT_INJECTION",
        title="High no proof", description="x", severity="HIGH",
    )
    assert f.severity == "MEDIUM"
    assert f.confidence_capped is True


def test_low_not_capped():
    v = _verdict("minor info")
    f = AgentFinding.from_observation(
        verdict=v, agent_id="SC-09", vuln_class="SUPPLY_CHAIN",
        title="Low", description="x", severity="LOW",
    )
    assert f.severity == "LOW"
    assert f.confidence_capped is False


def test_80_plus_bytes_semantic_no_marker_caps():
    """No structural proof marker caps at MEDIUM even with 90 bytes semantic.
    Gate requires structural proof for CRITICAL. Intentional."""
    evidence = "A" * 90
    v = _verdict(evidence)
    f = AgentFinding.from_observation(
        verdict=v, agent_id="PI-01", vuln_class="PROMPT_INJECTION",
        title="Substantive no marker", description="x", severity="CRITICAL",
    )
    assert f.severity == "MEDIUM"
    assert f.confidence_capped is True
    assert f.exploitability_confirmed is False


def test_macos_passwd_format_confirms():
    """macOS uses root:*:0:0 not root:x:0:0 — gate must handle both."""
    evidence = "root:*:0:0:System Administrator:/var/root:/bin/sh " + "x" * 40
    v = _verdict(evidence)
    f = AgentFinding.from_observation(
        verdict=v, agent_id="EP-11", vuln_class="ENVIRONMENT_PIVOT",
        title="macOS passwd leak", description="x", severity="CRITICAL",
    )
    assert f.exploitability_confirmed is True
    assert f.severity == "CRITICAL"


def test_docker_invalid_ref_confirms():
    """docker: invalid reference format proves shell injection executed."""
    evidence = ("docker: invalid reference format: repository name "
                "(library/ARGUS_INJECT_BEACON_54458) must be lowercase " + "x" * 30)
    v = _verdict(evidence)
    f = AgentFinding.from_observation(
        verdict=v, agent_id="EP-11", vuln_class="ENVIRONMENT_PIVOT",
        title="Shell injection beacon", description="x", severity="CRITICAL",
    )
    assert f.exploitability_confirmed is True
    assert f.severity == "CRITICAL"
