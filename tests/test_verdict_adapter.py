"""Tests for the VERDICT WEIGHT adapter."""

import pytest

from argus.models.findings import (
    AttackChainStep,
    Finding,
    FindingSeverity,
    FindingStatus,
    ReproductionStep,
    ValidationResult,
)
from argus.scoring import (
    AGENT_RELIABILITY_PRIORS,
    TECHNIQUE_HISTORICAL_ACCURACY,
    VerdictAdapter,
    VerdictScore,
)


def _make_finding(
    agent_type: str = "tool_poisoning",
    technique: str = "param_desc_scan_zero_width",
    surface: str = "parameter_description",
    severity: FindingSeverity = FindingSeverity.HIGH,
    direct_evidence: bool = False,
) -> Finding:
    finding = Finding(
        agent_type=agent_type,
        agent_instance_id="test-inst",
        scan_id="scan-001",
        title="test finding",
        description="test",
        severity=severity,
        target_surface=surface,
        technique=technique,
        attack_chain=[
            AttackChainStep(
                step_number=1,
                agent_type=agent_type,
                technique=technique,
                description="test step",
                target_surface=surface,
            )
        ],
        reproduction_steps=[
            ReproductionStep(
                step_number=1,
                action="test",
                expected_result="test",
                actual_result="test",
            )
        ],
    )
    if direct_evidence:
        finding.status = FindingStatus.VALIDATED
        finding.validation = ValidationResult(
            validated=True,
            validation_method="direct_observation",
            proof_of_exploitation="canary observed",
            reproducible=True,
        )
    return finding


# ============================================================
# Source Reliability priors
# ============================================================


def test_agent_priors_exist_for_phase1():
    assert "tool_poisoning" in AGENT_RELIABILITY_PRIORS
    assert "supply_chain" in AGENT_RELIABILITY_PRIORS
    assert "prompt_injection_hunter" in AGENT_RELIABILITY_PRIORS

    # Deterministic agents should have higher priors than LLM-augmented
    assert AGENT_RELIABILITY_PRIORS["tool_poisoning"] > AGENT_RELIABILITY_PRIORS["prompt_injection_hunter"]


def test_get_source_reliability_default():
    adapter = VerdictAdapter()
    assert adapter.get_source_reliability("tool_poisoning") > 0.9
    assert adapter.get_source_reliability("nonexistent_agent") > 0.5  # default neutral


# ============================================================
# Historical Accuracy priors
# ============================================================


def test_historical_accuracy_priors_exist():
    assert "hidden_content_scan" in TECHNIQUE_HISTORICAL_ACCURACY
    assert "role_hijack_classic" in TECHNIQUE_HISTORICAL_ACCURACY
    assert "dependency_confusion_typosquat" in TECHNIQUE_HISTORICAL_ACCURACY


def test_get_historical_accuracy_family_match():
    adapter = VerdictAdapter()
    # Direct match
    correct, total = adapter.get_historical_accuracy("role_hijack_classic")
    assert correct > 0
    assert total > 0
    # Family match (variant suffix)
    correct2, _ = adapter.get_historical_accuracy("role_hijack_classic_variant")
    # Should fall back to family default
    assert correct2 > 0


def test_get_historical_accuracy_unknown_returns_neutral():
    adapter = VerdictAdapter()
    correct, total = adapter.get_historical_accuracy("totally_made_up_technique")
    assert (correct, total) == (50, 100)


# ============================================================
# Scoring
# ============================================================


@pytest.mark.asyncio
async def test_score_high_confidence_finding():
    """A direct-evidence Tool Poisoning finding should get high CW."""
    adapter = VerdictAdapter()
    finding = _make_finding(
        agent_type="tool_poisoning",
        technique="param_desc_scan_zero_width",
        direct_evidence=True,
    )
    score = await adapter.score_finding(finding)

    assert isinstance(score, VerdictScore)
    assert score.consequence_weight > 0.0
    assert score.consequence_weight <= 1.0
    assert score.action_tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert "SR" in score.streams
    assert "CC" in score.streams
    assert "TD" in score.streams
    assert "HA" in score.streams


@pytest.mark.asyncio
async def test_score_low_confidence_finding():
    """An LLM-generated novel variant with no track record should get lower CW."""
    adapter = VerdictAdapter()
    finding = _make_finding(
        agent_type="prompt_injection_hunter",
        technique="totally_unknown_novel_technique",
        direct_evidence=False,
    )
    score = await adapter.score_finding(finding)
    # Single technique, no track record, no direct evidence → low CW expected
    assert score.consequence_weight < 0.7


@pytest.mark.asyncio
async def test_corroboration_increases_cw():
    """When the same family of techniques accumulates corroborations, CW rises."""
    adapter = VerdictAdapter()
    f1 = _make_finding(technique="role_hijack_classic", direct_evidence=True)
    f2 = _make_finding(technique="role_hijack_lowercase", direct_evidence=True)
    f3 = _make_finding(technique="role_hijack_debug_mode", direct_evidence=True)

    score1 = await adapter.score_finding(f1)
    score2 = await adapter.score_finding(f2)
    score3 = await adapter.score_finding(f3)

    # Corroboration count should increase
    assert score1.n_corroborating == 1
    assert score2.n_corroborating == 2
    assert score3.n_corroborating == 3
    # CW should rise with corroboration
    assert score2.consequence_weight >= score1.consequence_weight
    assert score3.consequence_weight >= score2.consequence_weight


@pytest.mark.asyncio
async def test_concurrent_corroboration_is_safe():
    """Concurrent score_finding calls must not lose corroboration counts."""
    import asyncio

    adapter = VerdictAdapter()
    findings = [_make_finding(technique="role_hijack_classic", direct_evidence=True) for _ in range(20)]
    # Fire all 20 concurrently — race condition would lose increments
    scores = await asyncio.gather(*[adapter.score_finding(f) for f in findings])
    # Final corroboration count must be exactly 20 (no lost increments)
    counts = sorted(s.n_corroborating for s in scores)
    assert counts == list(range(1, 21))


@pytest.mark.asyncio
async def test_direct_evidence_boosts_sr():
    """Findings with validation_method=direct_observation get SR boost."""
    adapter = VerdictAdapter()
    no_evidence = _make_finding(direct_evidence=False)
    with_evidence = _make_finding(direct_evidence=True)

    s1 = await adapter.score_finding(no_evidence, n_corroborating_override=1)
    s2 = await adapter.score_finding(with_evidence, n_corroborating_override=1)

    # Direct evidence should produce a higher SR
    assert s2.source_reliability > s1.source_reliability


@pytest.mark.asyncio
async def test_classification_thresholds():
    """VerdictScore.is_validated/is_low_confidence/is_suppressed are mutually exclusive."""
    adapter = VerdictAdapter()
    finding = _make_finding(direct_evidence=True)
    score = await adapter.score_finding(finding, n_corroborating_override=10)

    classifications = sum([score.is_validated, score.is_low_confidence, score.is_suppressed])
    assert classifications == 1


@pytest.mark.asyncio
async def test_to_dict_serializable():
    """VerdictScore.to_dict() should be JSON-serializable."""
    import json

    adapter = VerdictAdapter()
    score = await adapter.score_finding(_make_finding())
    d = score.to_dict()
    # Should not raise
    json.dumps(d)
    assert "consequence_weight" in d
    assert "framework" in d
    assert d["framework"] == "VERDICT WEIGHT"


@pytest.mark.asyncio
async def test_reset_corroboration():
    adapter = VerdictAdapter()
    finding = _make_finding(technique="role_hijack_classic")
    await adapter.score_finding(finding)
    await adapter.score_finding(finding)
    assert adapter._corroboration  # has entries

    adapter.reset_corroboration()
    assert not adapter._corroboration
