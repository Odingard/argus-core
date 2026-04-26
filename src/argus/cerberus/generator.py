"""
argus/cerberus/generator.py
CERBERUS rule generator — Phase 4 stub.

The output ``RuleArtifact`` is intentionally format-agnostic. The
``rule_body`` field carries a portable, declarative description of
what to match; downstream emitters (Sigma, YARA-L, Falco, native
CERBERUS DSL) consume it. Phase-5 lands at least one concrete
emitter; the contract here doesn't change.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from argus.agents.base import AgentFinding


@dataclass
class RuleArtifact:
    """
    One detection rule emitted from one (or one-cluster) ARGUS finding.

    ``rule_body`` is a portable dict — Phase-5 emitters render it into
    Sigma / YARA-L / Falco / native CERBERUS DSL.
    """
    rule_id:           str
    title:             str
    description:       str
    severity:          str
    derived_from:      list[str]            # ARGUS finding ids
    vuln_class:        str
    surface:           str
    techniques:        list[str]
    rule_body:         dict
    generated_at:      str
    integrity:         str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Per vuln_class match-template generator ─────────────────────────────────

def _match_template(vuln_class: str, surface: str, technique: str) -> dict:
    """
    Portable description of the runtime signal to detect. Format is
    intentionally loose — emitters know the conventions for their
    target language.
    """
    base = {
        "match_type": "behaviour_delta",
        "vuln_class": vuln_class,
        "surface":    surface,
        "techniques": [technique] if technique else [],
        "thresholds": {},
        "fields":     [],
    }

    if vuln_class == "PROMPT_INJECTION":
        base["fields"] = ["agent.input", "agent.response"]
        base["thresholds"] = {"injection_token_density": 0.05}
    elif vuln_class == "TOOL_POISONING":
        base["fields"] = ["tool.metadata.description",
                          "tool.metadata.parameters"]
        base["thresholds"] = {"poisoning_signature_hits": 1}
    elif vuln_class == "MEMORY_POISONING":
        base["fields"] = ["memory.write", "memory.retrieve"]
        base["thresholds"] = {"cross_session_canary_match": 1}
    elif vuln_class == "IDENTITY_SPOOF":
        base["fields"] = ["handoff.envelope.identity",
                          "handoff.envelope.from_agent"]
        base["thresholds"] = {"unsigned_or_mismatched_identity": 1}
    elif vuln_class == "CONTEXT_WINDOW":
        base["fields"] = ["session.turn_count", "agent.response"]
        base["thresholds"] = {"min_turns_before_compliance": 3}
    elif vuln_class == "CROSS_AGENT_EXFIL":
        base["fields"] = ["handoff.from", "handoff.to", "handoff.content"]
        base["thresholds"] = {"canary_token_propagation": 1}
    elif vuln_class == "PRIVILEGE_ESCALATION":
        base["fields"] = ["tool.invocation", "session.identity"]
        base["thresholds"] = {"deny_marker_disappeared": 1}
    elif vuln_class == "RACE_CONDITION":
        base["fields"] = ["tool.invocation.timestamp", "tool.surface"]
        base["thresholds"] = {"parallel_excess_successes": 1}
    elif vuln_class == "SUPPLY_CHAIN":
        base["fields"] = ["tool.metadata.origin", "tool.metadata.signed_by"]
        base["thresholds"] = {"untrusted_host_or_unsigned": 1}
    elif vuln_class == "MODEL_EXTRACTION":
        base["fields"] = ["agent.response"]
        base["thresholds"] = {"structural_token_disclosure": 1}
    return base


# ── Public API ──────────────────────────────────────────────────────────────

def generate_rule(finding: AgentFinding) -> RuleArtifact:
    """Build a RuleArtifact from a single AgentFinding."""
    technique = finding.attack_variant_id or finding.technique or ""
    body = _match_template(
        vuln_class=finding.vuln_class or "",
        surface=finding.surface or "",
        technique=technique,
    )
    rule_id = "CER-" + hashlib.sha256(
        f"{finding.agent_id}|{finding.vuln_class}|{finding.surface}|"
        f"{technique}|{finding.id}".encode()
    ).hexdigest()[:14]

    artifact = RuleArtifact(
        rule_id=rule_id,
        title=(f"Detect {finding.vuln_class} on {finding.surface or '*'} "
               f"({technique or finding.agent_id})"),
        description=(
            f"Generated from ARGUS finding {finding.id} ({finding.agent_id}). "
            f"{(finding.description or finding.title or '')[:300]}"
        ),
        severity=finding.severity or "HIGH",
        derived_from=[finding.id],
        vuln_class=finding.vuln_class or "",
        surface=finding.surface or "",
        techniques=[technique] if technique else [],
        rule_body=body,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    artifact.integrity = _integrity(artifact)
    return artifact


def generate_rules(findings: Iterable[AgentFinding]) -> list[RuleArtifact]:
    """Build rules for many findings, deduplicating on (vuln_class,
    surface, technique) so a corpus of 50 PI-01 findings on the same
    chat surface emits ONE rule rather than 50."""
    seen: dict[tuple, RuleArtifact] = {}
    for f in findings:
        key = (f.vuln_class, f.surface,
               f.attack_variant_id or f.technique)
        existing = seen.get(key)
        if existing is None:
            seen[key] = generate_rule(f)
        else:
            existing.derived_from.append(f.id)
            existing.integrity = _integrity(existing)
    return list(seen.values())


def write_rules(
    rules: list[RuleArtifact],
    output_dir: str | Path,
    *,
    filename: str = "cerberus_rules.json",
) -> Path:
    """Persist rules as JSON + emit Sigma YAML for each rule.

    Outputs:
      cerberus_rules.json  — machine-readable full rule set
      sigma/               — one Sigma YAML per rule (importable into SIEM)
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / filename
    payload = {
        "format_version": "argus.cerberus.v1",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "rule_count":     len(rules),
        "rules":          [r.to_dict() for r in rules],
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Sigma emitter — produces importable YAML for Splunk, Elastic,
    # Chronicle, and any other Sigma-compatible SIEM.
    try:
        sigma_dir = output_dir / "sigma"
        sigma_dir.mkdir(parents=True, exist_ok=True)
        for rule in rules:
            sigma_yaml = _emit_sigma(rule)
            sigma_path = sigma_dir / f"{rule.rule_id}.yml"
            sigma_path.write_text(sigma_yaml, encoding="utf-8")
    except Exception:
        pass

    return out_path


def _emit_sigma(rule: RuleArtifact) -> str:
    """Emit a Sigma YAML rule from an ARGUS RuleArtifact.

    Maps ARGUS vuln_class → Sigma category + product tags so the rule
    lands in the right SIEM pipeline. Format follows Sigma v1 spec.
    """
    _SEVERITY_MAP = {
        "CRITICAL": "critical", "HIGH": "high",
        "MEDIUM": "medium", "LOW": "low", "INFO": "informational",
    }
    _CATEGORY_MAP = {
        "PROMPT_INJECTION":     ("application", "ai_agent", "prompt_injection"),
        "TOOL_POISONING":       ("application", "mcp_server", "tool_poisoning"),
        "MEMORY_POISONING":     ("application", "ai_agent", "memory_manipulation"),
        "IDENTITY_SPOOF":       ("application", "ai_agent", "identity_bypass"),
        "CONTEXT_WINDOW":       ("application", "ai_agent", "context_manipulation"),
        "CROSS_AGENT_EXFIL":    ("network",     "ai_agent", "data_exfiltration"),
        "PRIVILEGE_ESCALATION": ("application", "ai_agent", "privilege_escalation"),
        "RACE_CONDITION":       ("application", "ai_agent", "race_condition"),
        "SUPPLY_CHAIN":         ("application", "mcp_server", "supply_chain"),
        "MODEL_EXTRACTION":     ("application", "ai_agent", "model_extraction"),
        "ENVIRONMENT_PIVOT":    ("process_creation", "host", "command_injection"),
    }
    cat, product, tag = _CATEGORY_MAP.get(
        rule.vuln_class, ("application", "ai_agent", "unknown")
    )
    # Detection condition from rule_body
    rb = rule.rule_body or {}
    detection_str = ""
    if rb.get("keywords"):
        kw_list = "\n        ".join(f"- '{k}'" for k in rb["keywords"][:5])
        detection_str = f"""    keywords:
        {kw_list}
    condition: keywords"""
    else:
        detection_str = "    condition: all of them"

    return f"""title: '{rule.title}'
id: {rule.rule_id}
status: experimental
description: >
    {rule.description[:200]}
    Generated by ARGUS autonomous red team — {rule.generated_at[:10]}.
    ARGUS finding IDs: {', '.join(rule.derived_from[:3])}.
author: 'ARGUS / OdinGard Security'
date: {rule.generated_at[:10]}
tags:
    - attack.{tag}
    - argus.{rule.vuln_class.lower()}
logsource:
    category: {cat}
    product: {product}
detection:
{detection_str}
falsepositives:
    - Legitimate agent orchestration matching attack surface signatures
level: {_SEVERITY_MAP.get(rule.severity, 'medium')}
"""


# ── Internals ───────────────────────────────────────────────────────────────

def _integrity(rule: RuleArtifact) -> str:
    """SHA-256 over the rule's stable identity fields. Lets a SOC
    detect tampering between emit and load."""
    raw = json.dumps({
        "rule_id":      rule.rule_id,
        "title":        rule.title,
        "vuln_class":   rule.vuln_class,
        "surface":      rule.surface,
        "techniques":   sorted(rule.techniques),
        "rule_body":    rule.rule_body,
        "derived_from": sorted(rule.derived_from),
    }, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]
