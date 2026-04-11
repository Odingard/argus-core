"""Finding schema — structured output for ARGUS attack results.

Every finding includes: attack chain, reproduction steps, OWASP mapping,
severity, validation status, and CERBERUS detection rule recommendations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    UNVALIDATED = "unvalidated"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    PARTIALLY_VALIDATED = "partially_validated"


class OWASPAgenticCategory(str, Enum):
    """OWASP Agentic AI Top 10 mapping."""

    PROMPT_INJECTION = "AA01:2025 — Agentic Prompt Injection"
    TOOL_MISUSE = "AA02:2025 — Tool Misuse and Manipulation"
    PRIVILEGE_ESCALATION = "AA03:2025 — Privilege Escalation via Agent Chaining"
    IDENTITY_SPOOFING = "AA04:2025 — Agent Identity Spoofing"
    MEMORY_POISONING = "AA05:2025 — Memory and Context Manipulation"
    CROSS_AGENT_EXFIL = "AA06:2025 — Cross-Agent Data Exfiltration"
    SUPPLY_CHAIN = "AA07:2025 — Supply Chain and Tool Dependency Attacks"
    RACE_CONDITIONS = "AA08:2025 — Race Conditions in Multi-Agent Systems"
    MODEL_EXTRACTION = "AA09:2025 — Model and Configuration Extraction"
    INSUFFICIENT_MONITORING = "AA10:2025 — Insufficient Agent Monitoring"
    PERSONA_HIJACKING = "AA11:ARGUS — Persona Hijacking and Identity Drift"
    MEMORY_BOUNDARY_COLLAPSE = "AA12:ARGUS — Memory Boundary Collapse"


class OWASPLLMCategory(str, Enum):
    """OWASP LLM Top 10 mapping."""

    PROMPT_INJECTION = "LLM01 — Prompt Injection"
    INSECURE_OUTPUT = "LLM02 — Insecure Output Handling"
    TRAINING_DATA_POISONING = "LLM03 — Training Data Poisoning"
    MODEL_DOS = "LLM04 — Model Denial of Service"
    SUPPLY_CHAIN = "LLM05 — Supply Chain Vulnerabilities"
    SENSITIVE_DISCLOSURE = "LLM06 — Sensitive Information Disclosure"
    INSECURE_PLUGIN = "LLM07 — Insecure Plugin Design"
    EXCESSIVE_AGENCY = "LLM08 — Excessive Agency"
    OVERRELIANCE = "LLM09 — Overreliance"
    MODEL_THEFT = "LLM10 — Model Theft"


class ReproductionStep(BaseModel):
    """A single step in reproducing a finding."""

    step_number: int
    action: str
    input_data: str | None = None
    expected_result: str
    actual_result: str | None = None


class AttackChainStep(BaseModel):
    """A single step in a multi-step attack chain."""

    step_number: int
    agent_type: str
    technique: str
    description: str
    input_payload: str | None = None
    output_observed: str | None = None
    target_surface: str


class ValidationResult(BaseModel):
    """Result of deterministic validation of a finding."""

    validated: bool
    validation_method: str
    proof_of_exploitation: str
    reproducible: bool
    attempts: int = 1
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RemediationGuidance(BaseModel):
    """Remediation recommendation for a finding."""

    summary: str
    detailed_steps: list[str]
    cerberus_detection_rule: str | None = None
    references: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A single validated finding from an ARGUS attack agent.

    This is the core output unit. A finding only ships when it has
    been validated with reproducible proof-of-exploitation.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Source
    agent_type: str
    agent_instance_id: str
    scan_id: str

    # Classification
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.UNVALIDATED

    # Attack details
    target_surface: str
    technique: str
    attack_chain: list[AttackChainStep]
    reproduction_steps: list[ReproductionStep]

    # OWASP mapping
    owasp_agentic: OWASPAgenticCategory | None = None
    owasp_llm: OWASPLLMCategory | None = None

    # Validation
    validation: ValidationResult | None = None

    # Remediation
    remediation: RemediationGuidance | None = None

    # Raw evidence — bounded to prevent memory exhaustion
    raw_request: str | None = Field(None, max_length=50_000)
    raw_response: str | None = Field(None, max_length=50_000)

    # VERDICT WEIGHT score — patent-pending eight-stream confidence certification
    # Set by the Orchestrator's scoring layer before findings are surfaced.
    # Schema:
    #   {
    #     "consequence_weight": float (0-1),
    #     "signal_strength": float,
    #     "doubt_index": float,
    #     "action_tier": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO",
    #     "interpretation": str,
    #     "streams": {"SR": float, "CC": float, "TD": float, "HA": float},
    #     "validated": bool,         # CW >= 0.70
    #     "low_confidence": bool,    # 0.40 <= CW < 0.70
    #     "suppressed": bool,        # CW < 0.40
    #     "framework": "VERDICT WEIGHT",
    #     "framework_version": "1.0.0"
    #   }
    verdict_score: dict | None = None

    def is_validated(self) -> bool:
        return self.status == FindingStatus.VALIDATED and self.validation is not None and self.validation.validated


class CerberusRule(BaseModel):
    """A CERBERUS detection rule generated from an ARGUS finding.

    Each rule describes how the defensive product (CERBERUS) can detect
    the same attack pattern that ARGUS discovered during a scan.
    """

    rule_id: str
    title: str
    description: str
    severity: str
    agent_source: str
    detection_logic: str
    indicators: list[str] = Field(default_factory=list)
    owasp_mapping: str = ""
    finding_id: str = ""
    recommended_action: str = ""


class CompoundAttackPath(BaseModel):
    """A multi-step attack path chaining findings from multiple agents.

    Constructed by the Correlation Agent when findings from different
    attack agents can be combined into a higher-severity exploit chain.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scan_id: str

    title: str
    description: str
    severity: FindingSeverity

    # The chain
    finding_ids: list[str]
    attack_path_steps: list[AttackChainStep]

    # What this chain achieves that individual findings don't
    compound_impact: str

    # Scoring
    exploitability_score: float = Field(ge=0.0, le=10.0)
    detectability_score: float = Field(ge=0.0, le=10.0, description="Higher = harder to detect")

    # OWASP
    owasp_agentic: list[OWASPAgenticCategory] = Field(default_factory=list)

    # Validation
    validation: ValidationResult | None = None

    # Remediation
    remediation: RemediationGuidance | None = None
    cerberus_detection_rules: list[str] = Field(default_factory=list)
