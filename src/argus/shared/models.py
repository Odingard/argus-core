"""
shared/models.py
All dataclasses shared across ARGUS ZD layers.
The Finding object is the core data structure — every layer reads and enriches it.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from enum import Enum


# ── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class VulnClass(str, Enum):
    SSRF              = "SSRF"
    DESER             = "DESER"
    AUTH_BYPASS       = "AUTH_BYPASS"
    MEM_NAMESPACE_LEAK = "MEM_NAMESPACE_LEAK"
    MESH_TRUST        = "MESH_TRUST"
    PHANTOM_MEMORY    = "PHANTOM_MEMORY"
    TRACE_LATERAL     = "TRACE_LATERAL"
    TRUST_ESCALATION  = "TRUST_ESCALATION"
    UNKNOWN           = "UNKNOWN"


# ── Layer 1 — Scanner output ──────────────────────────────────────────────────

@dataclass
class L1Finding:
    """
    Raw finding from Layer 1 scanner.
    Matches scanner_v3.py output schema exactly.
    """
    id:              str
    vuln_class:      str
    severity:        str
    title:           str
    file:            str
    line_hint:       str
    description:     str
    code_snippet:    str
    attack_vector:   Any                  # str or list[str]
    is_example:      bool = False
    poc:             Optional[str] = None
    poc_explanation: Optional[str] = None
    cvss_estimate:   Optional[str] = None
    remediation:     Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class L1Report:
    """Full scanner_v3.py output."""
    target:               str
    scanner_version:      str
    total_files_analyzed: int
    total_findings:       int
    critical_count:       int
    high_count:           int
    medium_count:         int
    low_count:            int
    chains:               list[dict]         = field(default_factory=list)
    production_findings:  list[L1Finding]    = field(default_factory=list)
    example_findings:     list[L1Finding]    = field(default_factory=list)
    repo_path:            Optional[str]      = None    # local clone path

    @classmethod
    def from_dict(cls, d: dict, repo_path: str = None) -> "L1Report":
        prod = [L1Finding(**f) for f in d.get("production_findings", [])]
        ex   = [L1Finding(**f) for f in d.get("example_findings", [])]
        return cls(
            target               = d["target"],
            scanner_version      = d.get("scanner_version", "3.0"),
            total_files_analyzed = d["total_files_analyzed"],
            total_findings       = d["total_findings"],
            critical_count       = d["critical_count"],
            high_count           = d["high_count"],
            medium_count         = d["medium_count"],
            low_count            = d["low_count"],
            chains               = d.get("chains", []),
            production_findings  = prod,
            example_findings     = ex,
            repo_path            = repo_path,
        )


# ── Layer 2 — Surface Analyzer output ────────────────────────────────────────

@dataclass
class SchemaInjectionPath:
    """Module A output — MCP schema injection surface."""
    source_file:         str
    source_function:     str
    injection_path:      list[str]          # call chain
    unsanitized_handoff: bool
    blast_radius:        str
    finding_anchor_id:   Optional[str] = None  # linked L1 finding


@dataclass
class TrustEdge:
    """Single edge in the trust propagation graph."""
    source:       str         # agent/tool/resource name
    target:       str
    edge_type:    str         # "delegation" | "tool_call" | "data_flow" | "spawn"
    trust_delta:  int         # +1 escalates, 0 same, -1 reduces
    file:         str
    line_hint:    str


@dataclass
class EscalationPath:
    """A path from low-trust to high-trust in the propagation graph."""
    path:          list[str]      # ordered node names
    edges:         list[TrustEdge]
    start_trust:   str            # "untrusted" | "low" | "medium"
    end_trust:     str            # "high" | "privileged"
    hop_count:     int
    blast_radius:  str
    finding_ids:   list[str]      # L1 findings at path nodes


@dataclass
class DeserChain:
    """Module C output — deserialization sink + call chain."""
    sink_file:     str
    sink_function: str
    sink_pattern:  str            # pickle.loads / yaml.load / eval / etc.
    call_chain:    list[str]      # reverse trace to user input
    reachable:     bool           # is this reachable from untrusted input?
    finding_id:    Optional[str] = None


@dataclass
class MemoryBoundaryGap:
    """Module D output — vector store namespace isolation failure."""
    file:              str
    function:          str
    store_type:        str         # chroma / weaviate / pinecone / in_memory
    has_namespace_filter: bool
    filter_at:         str         # "query" | "write" | "none"
    cross_tenant_risk: str         # CRITICAL / HIGH / MEDIUM
    finding_id:        Optional[str] = None


@dataclass
class AuthGapPath:
    """Module E output — entry point to privileged sink with missing auth."""
    entry_point:       str         # API route / tool handler / CLI
    entry_file:        str
    privileged_sink:   str         # exec / file_write / subprocess / DB write
    sink_file:         str
    call_chain:        list[str]   # entry → ... → sink
    auth_gates:        int         # number of auth checks found in path
    finding_id:        Optional[str] = None


@dataclass
class VulnHypothesis:
    """
    A ranked vulnerability hypothesis from Layer 2.
    This is the primary output that feeds Layer 3 fuzzing.
    """
    hypothesis_id:  str
    attack_class:   str
    title:          str
    description:    str
    likelihood:     float          # 0.0 – 1.0
    blast_radius:   str            # CRITICAL / HIGH / MEDIUM / LOW
    entry_points:   list[str]
    affected_files: list[str]
    finding_ids:    list[str]      # anchored L1 findings

    # populated by specific module
    schema_path:    Optional[SchemaInjectionPath] = None
    escalation_path: Optional[EscalationPath]     = None
    deser_chain:    Optional[DeserChain]           = None
    memory_gap:     Optional[MemoryBoundaryGap]    = None
    auth_gap:       Optional[AuthGapPath]          = None


@dataclass
class L2SurfaceMap:
    """Full Layer 2 output."""
    target:                  str
    schema_injection_paths:  list[SchemaInjectionPath]  = field(default_factory=list)
    escalation_paths:        list[EscalationPath]       = field(default_factory=list)
    deser_chains:            list[DeserChain]           = field(default_factory=list)
    memory_boundary_gaps:    list[MemoryBoundaryGap]    = field(default_factory=list)
    auth_gap_paths:          list[AuthGapPath]          = field(default_factory=list)
    ranked_hypotheses:       list[VulnHypothesis]       = field(default_factory=list)
    graph_node_count:        int = 0
    graph_edge_count:        int = 0


# ── Layer 3 — Semantic Fuzzer output ─────────────────────────────────────────

@dataclass
class FuzzPayload:
    """A single adversarial payload generated by Layer 3."""
    payload_id:        str
    hypothesis_id:     str
    modality:          str          # "schema" | "chain" | "memory"
    payload:           Any          # dict, str, or list depending on modality
    intended_effect:   str
    target_function:   str
    expected_deviation: str
    model_used:        str          # haiku or opus


@dataclass
class L3FuzzResults:
    """Full Layer 3 output."""
    target:       str
    fuzz_targets: list[dict]        = field(default_factory=list)  # grouped by hypothesis
    total_payloads: int             = 0
    schema_payloads: int            = 0
    chain_payloads: int             = 0
    memory_payloads: int            = 0


# ── Layer 4 — Behavioral Deviation output ────────────────────────────────────

@dataclass
class DeviationPrediction:
    """
    Layer 4 prediction for a single payload.
    Includes a fidelity score to discount hallucinated exploits.
    """
    payload_id:          str
    hypothesis_id:       str
    predicted_deviation: str
    confidence:          float        # 0.0 – 1.0
    fidelity_score:      float        # 0.0 – 1.0 (discounts complex syscalls / docker deps)
    combined_score:      float        # confidence * fidelity_score
    simulation_mode:     str          # "static" | "live"
    deviation_type:      str          # UNAUTHORIZED_TOOL_CALL / DATA_LEAK / RCE / etc.
    impact:              str
    trigger_conditions:  list[str]
    fidelity_notes:      str          = ""   # why score was discounted


@dataclass
class L4Deviations:
    """Full Layer 4 output."""
    target:      str
    deviations:  list[DeviationPrediction] = field(default_factory=list)
    high_confidence: int = 0          # combined_score >= 0.7
    medium_confidence: int = 0        # 0.4 <= combined_score < 0.7
    low_confidence: int = 0           # combined_score < 0.4


# ── Layer 5 — Exploit Chain output ───────────────────────────────────────────

@dataclass
class ExploitStep:
    step:     int
    action:   str
    payload:  Optional[str]
    achieves: str


@dataclass
class ExploitChain:
    """A complete, reproducible exploit chain from Layer 5."""
    chain_id:           str
    title:              str
    component_deviations: list[str]    # payload_ids
    steps:              list[ExploitStep]
    poc_code:           Optional[str]
    cvss_estimate:      Optional[str]
    mitre_atlas_ttps:   list[str]
    preconditions:      list[str]
    blast_radius:       str
    entry_point:        str            # "unauthenticated" | "low_priv" | "network"
    combined_score:     float          # max combined_score from component deviations
    owasp_llm_categories: list[str] = field(default_factory=list)


@dataclass
class L5Chains:
    """Full Layer 5 output."""
    target:  str
    chains:  list[ExploitChain] = field(default_factory=list)
    critical_count: int = 0
    high_count:     int = 0


# ── Layer 6 — CVE Pipeline + Flywheel output ─────────────────────────────────

@dataclass
class CVEDraft:
    chain_id:          str
    title:             str
    description:       str
    affected_product:  str
    affected_versions: str
    cvss_vector:       str
    cvss_score:        float
    cwe:               str
    poc_summary:       str
    remediation:       str
    owasp_llm_categories: list[str] = field(default_factory=list)
    reporter:          str = "Andre Byrd, Odingard Security (andre.byrd@odingard.com)"
    disclosure_date:   str = ""
    deadline:          str = ""


@dataclass
class FlywheelEntry:
    """
    Anonymized pattern entry for the intelligence flywheel.
    NO client/target identifying information stored.
    """
    vuln_classes:       list[str]
    attack_patterns:    list[str]
    effective_modalities: list[str]   # which fuzz modalities produced hits
    chain_pattern:      str           # abstract chain description
    blast_radius:       str
    entry_point_type:   str
    framework_type:     str           # "mcp_server" | "orchestration" | "vector_db" | "rag"
    scan_date:          str


@dataclass
class L6Output:
    """Full Layer 6 output."""
    target:          str
    cve_drafts:      list[CVEDraft]      = field(default_factory=list)
    flywheel_entries: list[FlywheelEntry] = field(default_factory=list)
    advisory_md:     Optional[str]       = None
    github_advisory: Optional[str]       = None


# ── Pipeline State — full run context ────────────────────────────────────────

@dataclass
class PipelineRun:
    """
    Carries the full state of a single ARGUS ZD pipeline run.
    Passed between layers. Written to results/ dir at each stage.
    """
    target:      str
    output_dir:  str
    repo_path:   Optional[str]    = None

    l1: Optional[L1Report]     = None
    l2: Optional[L2SurfaceMap] = None
    l3: Optional[L3FuzzResults] = None
    l4: Optional[L4Deviations] = None
    l5: Optional[L5Chains]     = None
    l6: Optional[L6Output]     = None

    completed_layers: list[int] = field(default_factory=list)
