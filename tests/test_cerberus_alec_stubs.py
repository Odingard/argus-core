"""
tests/test_cerberus_alec_stubs.py — Phase 4 CERBERUS / ALEC stub bridges.

Both modules are Phase-4 stubs — production format / transport lands
in Phase 5. The contracts here MUST hold so Phase-5 work doesn't
break the call sites.
"""
from __future__ import annotations

import json
from pathlib import Path

from argus.agents.base import AgentFinding
from argus.alec import (
    ALECEnvelope, build_envelope, submit_to_alec, write_envelope,
)
from argus.cerberus import (
    RuleArtifact, generate_rule, generate_rules, write_rules,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

def _f(*, id: str, agent_id: str, vuln_class: str,
       surface: str = "chat", technique: str = "T1",
       severity: str = "HIGH") -> AgentFinding:
    return AgentFinding(
        id=id, agent_id=agent_id, vuln_class=vuln_class,
        severity=severity, title=f"t-{id}", description=f"d-{id}",
        evidence_kind="behavior_delta",
        baseline_ref="mcp://x::baseline",
        surface=surface, attack_variant_id=technique,
        session_id=f"s-{id}",
    )


# ── CERBERUS ────────────────────────────────────────────────────────────────

def test_generate_rule_returns_artifact_with_integrity():
    f = _f(id="a", agent_id="PI-01", vuln_class="PROMPT_INJECTION")
    rule = generate_rule(f)
    assert isinstance(rule, RuleArtifact)
    assert rule.rule_id.startswith("CER-")
    assert rule.derived_from == ["a"]
    assert rule.integrity, "integrity hash missing"
    assert rule.vuln_class == "PROMPT_INJECTION"
    assert "agent.input" in rule.rule_body["fields"]


def test_generate_rule_per_vuln_class_produces_appropriate_body():
    cases = [
        ("PI-01", "PROMPT_INJECTION",     "agent.input"),
        ("TP-02", "TOOL_POISONING",       "tool.metadata.description"),
        ("MP-03", "MEMORY_POISONING",     "memory.write"),
        ("IS-04", "IDENTITY_SPOOF",       "handoff.envelope.identity"),
        ("CW-05", "CONTEXT_WINDOW",       "session.turn_count"),
        ("XE-06", "CROSS_AGENT_EXFIL",    "handoff.from"),
        ("PE-07", "PRIVILEGE_ESCALATION", "tool.invocation"),
        ("RC-08", "RACE_CONDITION",       "tool.invocation.timestamp"),
        ("SC-09", "SUPPLY_CHAIN",         "tool.metadata.origin"),
        ("ME-10", "MODEL_EXTRACTION",     "agent.response"),
    ]
    for agent_id, vc, expected_field in cases:
        rule = generate_rule(_f(id=f"x-{vc}", agent_id=agent_id,
                                vuln_class=vc))
        assert expected_field in rule.rule_body["fields"], (
            f"{vc} rule missing field {expected_field}; "
            f"got {rule.rule_body['fields']}"
        )


def test_generate_rules_dedups_on_same_class_surface_technique():
    findings = [
        _f(id=str(i), agent_id="PI-01",
           vuln_class="PROMPT_INJECTION",
           surface="chat", technique="PI-T1-direct")
        for i in range(50)
    ]
    rules = generate_rules(findings)
    assert len(rules) == 1, f"expected dedupe to 1 rule, got {len(rules)}"
    assert len(rules[0].derived_from) == 50


def test_generate_rules_keeps_distinct_techniques_separate():
    findings = [
        _f(id="a", agent_id="PI-01", vuln_class="PROMPT_INJECTION",
           technique="PI-T1-direct"),
        _f(id="b", agent_id="PI-01", vuln_class="PROMPT_INJECTION",
           technique="PI-T2-encoded"),
    ]
    rules = generate_rules(findings)
    assert len(rules) == 2


def test_write_rules_persists_payload(tmp_path):
    f = _f(id="a", agent_id="PI-01", vuln_class="PROMPT_INJECTION")
    rules = [generate_rule(f)]
    out = write_rules(rules, str(tmp_path))
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["rule_count"] == 1
    assert data["format_version"] == "argus.cerberus.v1"
    assert data["rules"][0]["rule_id"] == rules[0].rule_id


def test_integrity_changes_on_body_mutation():
    f = _f(id="a", agent_id="PI-01", vuln_class="PROMPT_INJECTION")
    rule = generate_rule(f)
    original = rule.integrity
    # Mutate the rule and recompute integrity — must differ.
    rule.rule_body["mutated"] = True
    from argus.cerberus.generator import _integrity
    assert _integrity(rule) != original


# ── ALEC ────────────────────────────────────────────────────────────────────

def _make_wilson_bundle(tmp_path: Path) -> Path:
    """Minimal Wilson-shaped bundle for envelope tests."""
    bundle = tmp_path / "wilson_bundle"
    bundle.mkdir()
    manifest = {
        "bundle_id": "wb-test-001",
        "target_id": "mcp://customer.example",
        "findings": [
            {"id": "a", "severity": "HIGH",
             "attack_variant_id": "PI-T1-direct", "owasp_id": "AAI01"},
            {"id": "b", "severity": "CRITICAL",
             "attack_variant_id": "PE-T2-elevated-arg", "owasp_id": "AAI07"},
        ],
    }
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (bundle / "transcript.jsonl").write_text('{"hop": 1}\n{"hop": 2}\n')
    return bundle


def test_build_envelope_from_wilson_bundle(tmp_path):
    bundle = _make_wilson_bundle(tmp_path)
    env = build_envelope(bundle)
    assert isinstance(env, ALECEnvelope)
    assert env.bundle_id == "wb-test-001"
    assert env.target_id == "mcp://customer.example"
    assert env.finding_count == 2
    assert env.severity_summary == {"HIGH": 1, "CRITICAL": 1}
    assert "PI-T1-direct" in env.techniques
    assert env.owasp_categories == ["AAI01", "AAI07"]
    assert env.envelope_id.startswith("alec-")
    assert env.integrity, "integrity hash missing"


def test_build_envelope_missing_dir_raises(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        build_envelope(tmp_path / "does_not_exist")


def test_build_envelope_handles_missing_manifest(tmp_path):
    bundle = tmp_path / "no_manifest"
    bundle.mkdir()
    env = build_envelope(bundle)
    assert env.finding_count == 0
    assert env.target_id == "unknown://target"
    assert env.bundle_id == bundle.name


def test_write_envelope_round_trip(tmp_path):
    bundle = _make_wilson_bundle(tmp_path)
    env = build_envelope(bundle)
    out = write_envelope(env, tmp_path / "alec_outbox")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["envelope_id"] == env.envelope_id
    assert data["finding_count"] == 2


def test_submit_to_alec_default_offline_writes_envelope(tmp_path):
    bundle = _make_wilson_bundle(tmp_path)
    result = submit_to_alec(bundle)
    assert result["status"] == "written"
    assert result["envelope_id"].startswith("alec-")
    assert Path(result["path"]).exists()


def test_submit_to_alec_pluggable_transport(tmp_path):
    """Transport contract: any callable taking an envelope returning a
    dict suffices. Phase-5 plugs in HTTP / mTLS / S3 here without
    touching the bridge."""
    bundle = _make_wilson_bundle(tmp_path)
    captured: dict = {}

    def fake_http(env):
        captured["env"] = env
        return {"status": "uploaded", "http_status": 202,
                "envelope_id": env.envelope_id}

    result = submit_to_alec(bundle, transport=fake_http)
    assert result["status"] == "uploaded"
    assert result["http_status"] == 202
    assert captured["env"].bundle_id == "wb-test-001"


def test_envelope_integrity_changes_on_artifact_mutation(tmp_path):
    bundle = _make_wilson_bundle(tmp_path)
    env_a = build_envelope(bundle)
    # Mutate a non-manifest artifact in the bundle.
    (bundle / "transcript.jsonl").write_text("MUTATED")
    env_b = build_envelope(bundle)
    assert env_a.integrity != env_b.integrity
