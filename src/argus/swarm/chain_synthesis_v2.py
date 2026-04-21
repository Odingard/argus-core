"""
argus/swarm/chain_synthesis_v2.py
Correlation Agent v2 — compound attack-path construction.

Per Tech_Architecture.docx §Correlation v2: "the live correlator
(v1) clusters runtime findings as they stream in. The synthesis layer
(v2) walks a validated cluster end-to-end and produces an attacker-
ready narrative: ordered kill-chain steps, OWASP Agentic AI Top-10
mapping, CVE-style draft text, and the blast-radius estimate the
operator needs to triage."

This module is deterministic and pure-Python — no LLM in the path.
The optional LLM-enrichment hook lives in the LiveCorrelator's Opus
synthesizer; v2 is the structural backbone every chain ships with.

Usage:

    from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain
    chain = synthesize_compound_chain(findings, target_id="mcp://x")
    chain.to_dict()  # JSON-serialisable artifact for reports / Wilson

Inputs are AgentFinding objects. Outputs are CompoundChain dataclasses
with kill-chain ordering, OWASP mapping per step, severity escalation,
and a draft advisory.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

from argus.agents.base import AgentFinding


# ── OWASP Agentic AI Top-10 (2025) — vuln_class → category mapping ──────────
# Source: OWASP Agentic AI Initiative, 2025. ARGUS' VULN_CLASS strings
# map to the canonical OWASP categories so reports / advisories carry
# the industry-standard taxonomy alongside ARGUS' internal taxonomy.

OWASP_AGENTIC_TOP10: dict[str, dict[str, str]] = {
    "PROMPT_INJECTION":      {"id": "AAI01",
                              "name": "Prompt Injection"},
    "TOOL_POISONING":        {"id": "AAI02",
                              "name": "Tool Poisoning"},
    "MEMORY_POISONING":      {"id": "AAI03",
                              "name": "Memory Poisoning"},
    "IDENTITY_SPOOF":        {"id": "AAI04",
                              "name": "Identity & Authentication Bypass"},
    "CONTEXT_WINDOW":        {"id": "AAI05",
                              "name": "Context-Window / Sustained Manipulation"},
    "CROSS_AGENT_EXFIL":     {"id": "AAI06",
                              "name": "Cross-Agent Data Exfiltration"},
    "PRIVILEGE_ESCALATION":  {"id": "AAI07",
                              "name": "Privilege Escalation"},
    "RACE_CONDITION":        {"id": "AAI08",
                              "name": "Concurrency / TOCTOU"},
    "SUPPLY_CHAIN":          {"id": "AAI09",
                              "name": "Supply Chain Compromise"},
    "MODEL_EXTRACTION":      {"id": "AAI10",
                              "name": "Model & Configuration Extraction"},
}

# MAAC phase ordering — first key in the kill-chain ordering. Findings
# whose agent declares a lower MAAC phase appear earlier in the chain.
DEFAULT_MAAC_PHASE_ORDER: dict[str, list[int]] = {
    "PI-01": [2],   "TP-02": [5],   "MP-03": [4],   "IS-04": [7],
    "CW-05": [2, 6], "XE-06": [7, 9], "PE-07": [5, 8], "RC-08": [5, 9],
    "SC-09": [1, 8], "ME-10": [1, 3],
}


# ── Severity arithmetic ─────────────────────────────────────────────────────

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_SEV_NAME = {v: k for k, v in _SEV_RANK.items()}


def _max_severity(findings: list[AgentFinding]) -> str:
    if not findings:
        return "LOW"
    return _SEV_NAME[max((_SEV_RANK.get(f.severity, 0) for f in findings),
                         default=1)]


def _blast_radius(findings: list[AgentFinding]) -> str:
    """Blast radius scales with chain length AND max severity. A 1-step
    HIGH is HIGH; a 3-step HIGH is CRITICAL because the chain composes."""
    if not findings:
        return "LOW"
    max_sev = _SEV_RANK.get(_max_severity(findings), 1)
    if len(findings) >= 3 and max_sev >= 3:
        return "CRITICAL"
    if len(findings) >= 2 and max_sev >= 3:
        return "HIGH"
    return _SEV_NAME[max_sev]


# ── Kill-chain step ordering ────────────────────────────────────────────────

def _phase_key(f: AgentFinding) -> tuple[int, str]:
    phases = DEFAULT_MAAC_PHASE_ORDER.get(f.agent_id, [9])
    return (min(phases) if phases else 9, f.agent_id)


# ── Output shape ────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    step:               int
    agent_id:           str
    finding_id:         str
    vuln_class:         str
    owasp_id:           str
    owasp_name:         str
    maac_phase_min:     int
    surface:            str
    technique:          str
    achieves:           str
    severity:           str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CompoundChain:
    chain_id:        str
    target_id:       str
    title:           str
    summary:         str
    steps:           list[ChainStep]
    severity:        str
    blast_radius:    str
    owasp_categories: list[str]
    advisory_draft:  str
    cve_draft_id:    str
    finding_ids:     list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "chain_id":         self.chain_id,
            "target_id":        self.target_id,
            "title":            self.title,
            "summary":          self.summary,
            "steps":            [s.to_dict() for s in self.steps],
            "severity":         self.severity,
            "blast_radius":     self.blast_radius,
            "owasp_categories": list(self.owasp_categories),
            "advisory_draft":   self.advisory_draft,
            "cve_draft_id":     self.cve_draft_id,
            "finding_ids":      list(self.finding_ids),
        }


# ── Synthesis ────────────────────────────────────────────────────────────────

def synthesize_compound_chain(
    findings: list[AgentFinding],
    *,
    target_id:        str,
    chain_id:         Optional[str] = None,
    cve_draft_prefix: str = "ARGUS-DRAFT-CVE",
) -> Optional[CompoundChain]:
    """
    Build a compound chain from a cluster of behavior-delta findings.
    Returns None if the cluster is too thin (≤1 finding) — single
    findings are advisories, not chains.
    """
    if not findings or len(findings) < 2:
        return None

    # 1) Order findings by kill-chain (MAAC phase ascending).
    ordered = sorted(findings, key=_phase_key)

    # 2) Build steps with OWASP mapping.
    steps: list[ChainStep] = []
    for i, f in enumerate(ordered, start=1):
        owasp = OWASP_AGENTIC_TOP10.get(
            f.vuln_class,
            {"id": "AAI00", "name": "Uncategorised"},
        )
        steps.append(ChainStep(
            step=i,
            agent_id=f.agent_id,
            finding_id=f.id,
            vuln_class=f.vuln_class,
            owasp_id=owasp["id"],
            owasp_name=owasp["name"],
            maac_phase_min=_phase_key(f)[0],
            surface=f.surface or "",
            technique=f.attack_variant_id or f.technique or "",
            achieves=_step_achievement_phrase(f),
            severity=f.severity or "HIGH",
        ))

    # 3) Severity / blast radius / OWASP collapse.
    severity     = _max_severity(ordered)
    blast        = _blast_radius(ordered)
    owasp_ids    = sorted({s.owasp_id for s in steps})

    # 4) Title and summary.
    title = (
        f"Compound chain: {' → '.join(s.vuln_class for s in steps)} "
        f"on {target_id}"
    )
    summary = _draft_summary(steps=steps, target_id=target_id,
                             severity=severity, blast=blast)

    # 5) Advisory + CVE draft id.
    cid = chain_id or _stable_chain_id(ordered, target_id)
    cve_id = f"{cve_draft_prefix}-{cid[:10]}"
    advisory = _advisory_draft(
        steps=steps, target_id=target_id, severity=severity,
        blast=blast, owasp_ids=owasp_ids, cve_id=cve_id,
    )

    return CompoundChain(
        chain_id=cid,
        target_id=target_id,
        title=title,
        summary=summary,
        steps=steps,
        severity=severity,
        blast_radius=blast,
        owasp_categories=owasp_ids,
        advisory_draft=advisory,
        cve_draft_id=cve_id,
        finding_ids=[s.finding_id for s in steps],
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _stable_chain_id(findings: list[AgentFinding], target_id: str) -> str:
    import hashlib
    raw = f"{target_id}|" + "|".join(sorted(f.id for f in findings))
    return "chain-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _step_achievement_phrase(f: AgentFinding) -> str:
    """One short clause describing what the step achieves in the chain."""
    achievements = {
        "PROMPT_INJECTION":     "agent followed attacker instruction",
        "TOOL_POISONING":       "tool catalog hosts poisoned metadata",
        "MEMORY_POISONING":     "attacker-planted fact retrieved later",
        "IDENTITY_SPOOF":       "handoff destination honoured spoofed identity",
        "CONTEXT_WINDOW":       "long-con bypass landed where cold attempt failed",
        "CROSS_AGENT_EXFIL":    "secret crossed peer-agent boundary",
        "PRIVILEGE_ESCALATION": "guest invoked privileged tool successfully",
        "RACE_CONDITION":       "parallel burst out-succeeded sequential baseline",
        "SUPPLY_CHAIN":         "untrusted-origin signal in tool catalog",
        "MODEL_EXTRACTION":     "model surfaced structural / config data",
    }
    return achievements.get(f.vuln_class,
                            f.title or "behaviour delta confirmed")


def _draft_summary(
    *,
    steps:     list[ChainStep],
    target_id: str,
    severity:  str,
    blast:     str,
) -> str:
    sentences = [
        f"{len(steps)}-step compound attack chain constructed against "
        f"{target_id}. Composite severity {severity}, blast radius {blast}."
    ]
    for s in steps:
        sentences.append(
            f"  Step {s.step} ({s.owasp_id}/{s.vuln_class}): "
            f"{s.achieves} via {s.technique or 'technique'} "
            f"on {s.surface or 'surface'}."
        )
    return "\n".join(sentences)


def _advisory_draft(
    *,
    steps:     list[ChainStep],
    target_id: str,
    severity:  str,
    blast:     str,
    owasp_ids: list[str],
    cve_id:    str,
) -> str:
    bullets = "\n".join(
        f"  - {s.owasp_id} ({s.vuln_class}) on {s.surface or '?'}: "
        f"{s.achieves}"
        for s in steps
    )
    return (
        f"DRAFT ADVISORY  {cve_id}\n"
        f"=================================================\n"
        f"Affected target : {target_id}\n"
        f"Severity        : {severity}\n"
        f"Blast radius    : {blast}\n"
        f"OWASP Agentic   : {', '.join(owasp_ids)}\n"
        f"\n"
        f"Composite chain ({len(steps)} steps):\n"
        f"{bullets}\n"
        f"\n"
        f"Reproduction: replay each step's recorded session_id from the\n"
        f"corresponding ARGUS run; baseline_ref on each step points to\n"
        f"the comparison transcript. The chain is reproducible because\n"
        f"every step's verdict was emitted by the deterministic\n"
        f"Observation Engine — no LLM in the validation path.\n"
        f"\n"
        f"Remediation guidance: address each step in order. Closing the\n"
        f"earliest step ({steps[0].owasp_id}) usually breaks the chain\n"
        f"the cheapest because subsequent steps depend on the foothold\n"
        f"the earlier step established.\n"
    )
