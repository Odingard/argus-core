"""
tests/test_chain_synthesis_v2.py — Phase 4 Correlation v2 acceptance.

Deterministic, no LLM. Verifies kill-chain ordering by MAAC phase,
OWASP mapping, severity arithmetic, and advisory draft shape.
"""
from __future__ import annotations

from argus.agents.base import AgentFinding
from argus.swarm.chain_synthesis_v2 import (
    OWASP_AGENTIC_TOP10, CompoundChain,
    synthesize_compound_chain,
)


def _make_finding(
    *, id: str, agent_id: str, vuln_class: str, severity: str = "HIGH",
    surface: str = "chat", attack_variant_id: str = "v1",
    target_id: str = "mcp://x",
) -> AgentFinding:
    return AgentFinding(
        id=id, agent_id=agent_id, vuln_class=vuln_class,
        severity=severity, title=f"t-{id}", description=f"d-{id}",
        evidence_kind="behavior_delta",
        baseline_ref=f"{target_id}::baseline",
        surface=surface,
        attack_variant_id=attack_variant_id,
        session_id=f"sess-{id}",
        verdict_kind="CONTENT_LEAK",
    )


# ── Synthesizer behaviour ───────────────────────────────────────────────────

def test_synthesize_returns_none_for_single_finding():
    f = _make_finding(id="f1", agent_id="PI-01",
                     vuln_class="PROMPT_INJECTION")
    assert synthesize_compound_chain([f], target_id="mcp://x") is None


def test_synthesize_returns_none_for_empty():
    assert synthesize_compound_chain([], target_id="mcp://x") is None


def test_synthesize_orders_steps_by_maac_phase():
    findings = [
        _make_finding(id="late",  agent_id="RC-08",
                      vuln_class="RACE_CONDITION"),       # phase 5
        _make_finding(id="early", agent_id="SC-09",
                      vuln_class="SUPPLY_CHAIN"),          # phase 1
        _make_finding(id="mid",   agent_id="MP-03",
                      vuln_class="MEMORY_POISONING"),      # phase 4
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    assert chain
    step_ids = [s.finding_id for s in chain.steps]
    assert step_ids == ["early", "mid", "late"], (
        f"chain not ordered by MAAC phase: {step_ids}"
    )


def test_synthesize_maps_each_step_to_owasp_category():
    findings = [
        _make_finding(id="a", agent_id="PI-01",
                      vuln_class="PROMPT_INJECTION"),
        _make_finding(id="b", agent_id="PE-07",
                      vuln_class="PRIVILEGE_ESCALATION"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    assert chain
    owasp_ids = {s.owasp_id for s in chain.steps}
    assert owasp_ids == {OWASP_AGENTIC_TOP10["PROMPT_INJECTION"]["id"],
                         OWASP_AGENTIC_TOP10["PRIVILEGE_ESCALATION"]["id"]}


def test_synthesize_severity_collapses_to_max():
    findings = [
        _make_finding(id="a", agent_id="PI-01",
                      vuln_class="PROMPT_INJECTION", severity="LOW"),
        _make_finding(id="b", agent_id="PE-07",
                      vuln_class="PRIVILEGE_ESCALATION", severity="CRITICAL"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    assert chain.severity == "CRITICAL"


def test_synthesize_blast_radius_escalates_with_chain_length():
    """Three HIGH steps compose into CRITICAL blast radius."""
    findings = [
        _make_finding(id=f"f{i}", agent_id="PI-01",
                      vuln_class="PROMPT_INJECTION", severity="HIGH")
        for i in range(3)
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    assert chain.blast_radius == "CRITICAL"


def test_synthesize_blast_radius_two_step_high_is_high():
    findings = [
        _make_finding(id="a", agent_id="PI-01",
                      vuln_class="PROMPT_INJECTION", severity="HIGH"),
        _make_finding(id="b", agent_id="PE-07",
                      vuln_class="PRIVILEGE_ESCALATION", severity="HIGH"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    assert chain.blast_radius == "HIGH"


def test_synthesize_includes_advisory_draft_with_cve_id():
    findings = [
        _make_finding(id="a", agent_id="PI-01",
                      vuln_class="PROMPT_INJECTION"),
        _make_finding(id="b", agent_id="ME-10",
                      vuln_class="MODEL_EXTRACTION"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    assert chain
    assert chain.cve_draft_id.startswith("ARGUS-DRAFT-CVE-")
    assert chain.advisory_draft.startswith("DRAFT ADVISORY")
    assert "PROMPT_INJECTION" in chain.advisory_draft
    assert "MODEL_EXTRACTION" in chain.advisory_draft
    assert "AAI01" in chain.advisory_draft
    assert "AAI10" in chain.advisory_draft


def test_synthesize_chain_id_is_deterministic():
    fs = [
        _make_finding(id="a", agent_id="PI-01", vuln_class="PROMPT_INJECTION"),
        _make_finding(id="b", agent_id="PE-07", vuln_class="PRIVILEGE_ESCALATION"),
    ]
    a = synthesize_compound_chain(fs, target_id="mcp://x")
    b = synthesize_compound_chain(fs, target_id="mcp://x")
    assert a.chain_id == b.chain_id


def test_synthesize_chain_id_changes_with_target():
    fs = [
        _make_finding(id="a", agent_id="PI-01", vuln_class="PROMPT_INJECTION"),
        _make_finding(id="b", agent_id="PE-07", vuln_class="PRIVILEGE_ESCALATION"),
    ]
    a = synthesize_compound_chain(fs, target_id="mcp://x")
    b = synthesize_compound_chain(fs, target_id="mcp://y")
    assert a.chain_id != b.chain_id


def test_synthesize_to_dict_round_trip():
    findings = [
        _make_finding(id="a", agent_id="PI-01",
                      vuln_class="PROMPT_INJECTION"),
        _make_finding(id="b", agent_id="ME-10",
                      vuln_class="MODEL_EXTRACTION"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    d = chain.to_dict()
    assert d["chain_id"] == chain.chain_id
    assert len(d["steps"]) == 2
    assert "owasp_id" in d["steps"][0]
    assert isinstance(d["finding_ids"], list)


def test_synthesize_handles_unknown_vuln_class_gracefully():
    findings = [
        _make_finding(id="a", agent_id="PI-01",
                      vuln_class="PROMPT_INJECTION"),
        _make_finding(id="b", agent_id="X",
                      vuln_class="UNKNOWN_NOVEL_CLASS"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    assert chain
    novel_step = next(s for s in chain.steps
                      if s.vuln_class == "UNKNOWN_NOVEL_CLASS")
    assert novel_step.owasp_id == "AAI00"
    assert novel_step.owasp_name == "Uncategorised"


def test_synthesize_full_ten_agent_chain():
    """A maximal chain covering every Phase-1..Phase-4 agent."""
    spec = [
        ("a", "SC-09", "SUPPLY_CHAIN"),
        ("b", "ME-10", "MODEL_EXTRACTION"),
        ("c", "PI-01", "PROMPT_INJECTION"),
        ("d", "CW-05", "CONTEXT_WINDOW"),
        ("e", "MP-03", "MEMORY_POISONING"),
        ("f", "TP-02", "TOOL_POISONING"),
        ("g", "PE-07", "PRIVILEGE_ESCALATION"),
        ("h", "RC-08", "RACE_CONDITION"),
        ("i", "IS-04", "IDENTITY_SPOOF"),
        ("j", "XE-06", "CROSS_AGENT_EXFIL"),
    ]
    findings = [_make_finding(id=i, agent_id=a, vuln_class=v) for i, a, v in spec]
    chain = synthesize_compound_chain(findings, target_id="mcp://10agent")
    assert chain
    assert len(chain.steps) == 10
    assert chain.severity == "HIGH"
    assert chain.blast_radius == "CRITICAL"
    # Every OWASP category should appear exactly once.
    assert len(set(chain.owasp_categories)) == 10
