"""Tests for Phase 3-4 Correlation Engine compound patterns.

Validates that the five new compound attack path patterns fire correctly
when the required agent types and marker evidence are present.
"""

from __future__ import annotations

from argus.correlation import CorrelationEngine
from argus.models.findings import (
    AttackChainStep,
    Finding,
    FindingSeverity,
    FindingStatus,
    ReproductionStep,
    ValidationResult,
)

# ============================================================
# Helpers
# ============================================================


def _make_finding(
    *,
    agent_type: str,
    title: str,
    technique: str,
    target_surface: str = "http://target.test/chat",
    severity: FindingSeverity = FindingSeverity.HIGH,
    description: str = "",
    raw_response: str = "",
) -> Finding:
    f = Finding(
        agent_type=agent_type,
        agent_instance_id="inst-1",
        scan_id="test-scan",
        title=title,
        description=description or title,
        severity=severity,
        target_surface=target_surface,
        technique=technique,
        attack_chain=[
            AttackChainStep(
                step_number=1,
                agent_type=agent_type,
                technique=technique,
                description=title,
                target_surface=target_surface,
            )
        ],
        reproduction_steps=[ReproductionStep(step_number=1, action="test", expected_result="ok")],
        raw_response=raw_response,
    )
    f.status = FindingStatus.VALIDATED
    f.validation = ValidationResult(
        validated=True,
        validation_method="direct_observation",
        proof_of_exploitation="test proof",
        reproducible=True,
    )
    return f


# ============================================================
# context_window + privilege_escalation
# ============================================================


async def test_correlation_emits_context_window_privilege_escalation():
    """Context window manipulation + privilege escalation fires compound."""
    findings = [
        _make_finding(
            agent_type="context_window",
            title="Context window overflow via multi-turn injection",
            technique="context_overflow_multi_turn",
            target_surface="http://target.test:8001",
        ),
        _make_finding(
            agent_type="privilege_escalation",
            title="Privilege escalation via tool-call chaining",
            technique="tool_chain_escalation",
            target_surface="http://target.test:8001",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    assert any("context_window" in p.title.lower() for p in paths)
    assert any("context_window_privilege_escalation" in p.description for p in paths)
    # The compound should reference both participating findings
    matched = [p for p in paths if "context_window_privilege_escalation" in p.description]
    assert len(matched) == 1
    assert len(matched[0].finding_ids) == 2


# ============================================================
# cross_agent_exfil + model_extraction (requires marker leak)
# ============================================================


async def test_correlation_emits_cross_agent_exfil_model_extraction():
    """Cross-agent exfil + model extraction fires when marker evidence present."""
    findings = [
        _make_finding(
            agent_type="cross_agent_exfil",
            title="Cross-agent relay via shared memory",
            technique="relay_shared_memory",
            target_surface="http://target.test:8001",
            raw_response="leaked secret canary token FAKE-CANARY-01",
        ),
        _make_finding(
            agent_type="model_extraction",
            title="System prompt extracted via reflection",
            technique="system_prompt_reflection",
            target_surface="http://target.test:8001",
            raw_response="extracted system prompt marker",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    matched = [p for p in paths if "cross_agent_exfil_model_extraction" in p.description]
    assert len(matched) == 1
    assert len(matched[0].finding_ids) == 2


async def test_correlation_skips_cross_agent_exfil_model_extraction_without_marker():
    """Cross-agent exfil + model extraction does NOT fire without marker evidence."""
    findings = [
        _make_finding(
            agent_type="cross_agent_exfil",
            title="Cross-agent relay attempt",
            technique="relay_shared_memory",
            target_surface="http://target.test:8001",
            raw_response="no evidence here",
        ),
        _make_finding(
            agent_type="model_extraction",
            title="Model fingerprinting attempt",
            technique="model_fingerprint",
            target_surface="http://target.test:8001",
            raw_response="no evidence here",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    matched = [p for p in paths if "cross_agent_exfil_model_extraction" in p.description]
    assert len(matched) == 0


# ============================================================
# race_condition + privilege_escalation
# ============================================================


async def test_correlation_emits_race_condition_privilege_escalation():
    """Race condition + privilege escalation fires compound."""
    findings = [
        _make_finding(
            agent_type="race_condition",
            title="TOCTOU in authorization check",
            technique="toctou_auth_bypass",
            target_surface="http://target.test:8001",
        ),
        _make_finding(
            agent_type="privilege_escalation",
            title="Privilege escalation via concurrent request",
            technique="concurrent_escalation",
            target_surface="http://target.test:8001",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    matched = [p for p in paths if "race_condition_privilege_escalation" in p.description]
    assert len(matched) == 1
    assert len(matched[0].finding_ids) == 2


# ============================================================
# model_extraction + prompt_injection_hunter (requires marker leak)
# ============================================================


async def test_correlation_emits_model_extraction_prompt_injection():
    """Model extraction + prompt injection fires when marker evidence present."""
    findings = [
        _make_finding(
            agent_type="model_extraction",
            title="System prompt extracted via jailbreak",
            technique="system_prompt_jailbreak",
            target_surface="http://target.test:8001",
            raw_response="leaked secret system prompt canary",
        ),
        _make_finding(
            agent_type="prompt_injection_hunter",
            title="Targeted injection using extracted prompt",
            technique="targeted_role_hijack",
            target_surface="http://target.test:8001",
            raw_response="marker extracted via injection",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    matched = [p for p in paths if "model_extraction_prompt_injection" in p.description]
    assert len(matched) == 1
    assert len(matched[0].finding_ids) == 2


async def test_correlation_skips_model_extraction_prompt_injection_without_marker():
    """Model extraction + prompt injection does NOT fire without marker evidence."""
    findings = [
        _make_finding(
            agent_type="model_extraction",
            title="Model fingerprinting attempt",
            technique="model_fingerprint",
            target_surface="http://target.test:8001",
            raw_response="clean output",
        ),
        _make_finding(
            agent_type="prompt_injection_hunter",
            title="Injection attempt",
            technique="role_hijack_classic",
            target_surface="http://target.test:8001",
            raw_response="clean output",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    matched = [p for p in paths if "model_extraction_prompt_injection" in p.description]
    assert len(matched) == 0


# ============================================================
# context_window + cross_agent_exfil (requires marker leak)
# ============================================================


async def test_correlation_emits_context_window_cross_agent_exfil():
    """Context window + cross-agent exfil fires when marker evidence present."""
    findings = [
        _make_finding(
            agent_type="context_window",
            title="Context window pollution with exfil payload",
            technique="context_pollution_exfil",
            target_surface="http://target.test:8001",
            raw_response="canary leak detected in context",
        ),
        _make_finding(
            agent_type="cross_agent_exfil",
            title="Data relay via polluted context",
            technique="context_relay_exfil",
            target_surface="http://target.test:8001",
            raw_response="secret marker extracted via relay",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    matched = [p for p in paths if "context_window_cross_agent_exfil" in p.description]
    assert len(matched) == 1
    assert len(matched[0].finding_ids) == 2


async def test_correlation_skips_context_window_cross_agent_exfil_without_marker():
    """Context window + cross-agent exfil does NOT fire without marker evidence."""
    findings = [
        _make_finding(
            agent_type="context_window",
            title="Context overflow attempt",
            technique="context_overflow",
            target_surface="http://target.test:8001",
            raw_response="no evidence",
        ),
        _make_finding(
            agent_type="cross_agent_exfil",
            title="Relay attempt",
            technique="relay_attempt",
            target_surface="http://target.test:8001",
            raw_response="no evidence",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    matched = [p for p in paths if "context_window_cross_agent_exfil" in p.description]
    assert len(matched) == 0


# ============================================================
# Cross-cutting: existing Phase 1-2 patterns still work
# ============================================================


async def test_phase12_patterns_unaffected_by_new_patterns():
    """Adding Phase 3-4 patterns does not break existing Phase 1-2 correlation."""
    findings = [
        _make_finding(
            agent_type="tool_poisoning",
            title="Hidden content in tool: read_document",
            technique="hidden_content_scan",
            target_surface="http://target.test:8001",
        ),
        _make_finding(
            agent_type="supply_chain",
            title="Tool output injection via read_document",
            technique="tool_output_injection",
            target_surface="http://target.test:8001",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    assert any("tool_poisoning" in p.title.lower() for p in paths)


async def test_no_compound_for_single_phase34_agent():
    """A single Phase 3-4 agent finding should not produce a compound path."""
    findings = [
        _make_finding(
            agent_type="context_window",
            title="Context overflow detected",
            technique="context_overflow",
            target_surface="http://target.test:8001",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-v2", findings)
    assert paths == []
