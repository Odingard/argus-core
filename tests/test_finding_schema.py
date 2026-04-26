"""
tests/test_finding_schema.py — Finding schema refactor (Ticket 0.7).

Locks in the runtime-evidence shape Phase-1+ agents will produce.
"""
from __future__ import annotations

import json

import pytest

from argus.agents.base import AgentFinding
from argus.observation.verdict import BehaviorDelta, DeltaKind, Verdict


# ── Backward-compat with legacy AgentFinding shape ──────────────────────────

def test_legacy_agent_finding_construction_still_works():
    """Old call sites (legacy/agents/...) used positional / no-runtime args."""
    f = AgentFinding(
        id="x", agent_id="EA-12", vuln_class="EXCESSIVE_AGENCY",
        severity="HIGH", title="t",
        description="d",
        file="path.py", technique="EA-T1",
        attack_vector="prompt -> tool",
    )
    assert f.evidence_kind == "static"   # default — no runtime evidence
    assert f.session_id == ""
    assert f.attack_variant_id == ""


def test_new_runtime_evidence_fields_default_cleanly():
    f = AgentFinding(
        id="x", agent_id="A", vuln_class="C", severity="HIGH",
        title="t", description="d",
    )
    assert f.evidence_kind == "static"
    assert f.baseline_ref == ""
    assert f.attack_variant_id == ""
    assert f.session_id == ""
    assert f.surface == ""
    assert f.verdict_kind == ""
    assert f.delta_evidence == ""


def test_to_dict_is_json_serialisable():
    f = AgentFinding(
        id="x", agent_id="A", vuln_class="C", severity="HIGH",
        title="t", description="d", session_id="abc",
        evidence_kind="behavior_delta",
    )
    json.dumps(f.to_dict())   # must not raise


# ── from_observation convenience constructor ────────────────────────────────

def test_from_observation_wires_full_provenance_chain():
    v = Verdict(
        delta=BehaviorDelta.DELTA,
        kind=DeltaKind.UNAUTHORISED_TOOL_CALL,
        detector="unauthorized_tool",
        evidence="tool 'delete_account' fired post-attack, never in baseline",
        confidence=0.95,
        turn_index=3,
        meta={"tool_name": "delete_account"},
    )
    f = AgentFinding.from_observation(
        verdict=v,
        agent_id="PI-02",
        vuln_class="PROMPT_INJECTION",
        title="Prompt injection caused unauthorised tool call",
        description="Adversarial input via corpus variant rh_003 triggered ...",
        surface="tool:delete_account",
        session_id="sess_abcdef",
        attack_variant_id="rh_003:base64:fp_xyz",
        baseline_ref="baselines/sess_abcdef.json",
        severity="CRITICAL",
    )
    # Provenance chain wired
    assert f.session_id == "sess_abcdef"
    assert f.attack_variant_id == "rh_003:base64:fp_xyz"
    assert f.baseline_ref == "baselines/sess_abcdef.json"
    assert f.surface == "tool:delete_account"
    # Verdict mapping
    assert f.verdict_kind == "UNAUTHORISED_TOOL_CALL"
    assert "delete_account" in f.delta_evidence
    assert f.attack_vector == "unauthorized_tool"
    assert f.evidence_kind == "behavior_delta"
    # Severity: this finding lacks structural proof markers and has
    # short evidence, so the gate caps it at MEDIUM. The test verifies
    # the gate is working, not that CRITICAL passes through.
    assert f.severity == "MEDIUM"
    assert f.confidence_capped == True
    assert f.confidence_cap_reason != ""
    # Auto-generated id is stable for the same inputs
    f2 = AgentFinding.from_observation(
        verdict=v,
        agent_id="PI-02",
        vuln_class="PROMPT_INJECTION",
        title="Prompt injection caused unauthorised tool call",
        description="Adversarial input via corpus variant rh_003 triggered ...",
        surface="tool:delete_account",
        session_id="sess_abcdef",
        attack_variant_id="rh_003:base64:fp_xyz",
        baseline_ref="baselines/sess_abcdef.json",
        severity="CRITICAL",
    )
    assert f.id == f2.id


def test_from_observation_rejects_non_verdict_input():
    with pytest.raises(TypeError):
        AgentFinding.from_observation(
            verdict="not-a-verdict",
            agent_id="x", vuln_class="y",
            title="t", description="d",
        )


def test_from_observation_with_no_kind_verdict():
    """AMBIGUOUS verdicts (e.g. injection echo) carry no DeltaKind."""
    v = Verdict(
        delta=BehaviorDelta.AMBIGUOUS,
        kind=None,
        detector="injection_echo",
        evidence="payload echoed without behavior change",
        confidence=0.3,
    )
    f = AgentFinding.from_observation(
        verdict=v,
        agent_id="PI-02",
        vuln_class="PROMPT_INJECTION",
        title="ambiguous echo",
        description="d",
        severity="LOW",
    )
    assert f.verdict_kind == ""
    assert f.evidence_kind == "behavior_delta"
