"""
argus/impact/optimizer.py — Phase 9 Impact Optimization.

Takes a validated CompoundChain (from swarm.chain_synthesis_v2) plus
any DeterministicEvidence attached to its findings and renders a
``BlastRadiusMap`` — the single artifact that turns "a bug landed"
into "here is exactly what's at stake, and here's which regulators
will care if you don't fix it."

Trust-transitivity model:
  Each finding reveals a foothold at a surface. Surfaces linked by a
  ``TrustEdge`` are reachable via trust transitivity — e.g. a
  workspace token discovered at one surface unlocks the adjacent
  Drive / Mail / Calendar surfaces that share the same OAuth identity.
  The optimizer's default edges encode the OAuth-supply-chain-class
  topology (OAuth token → Workspace services; AWS key → S3/IAM/EC2;
  GitHub PAT → private-repo code; PaaS deploy token → prod env vars).
  Callers pass
  their own edges to model customer-specific trust relationships.

Output is a dataclass — JSON-serialisable, designed to ride inside
Wilson bundles and ALEC envelopes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from argus.agents.base import AgentFinding
from argus.impact.classify import (
    DataClassification, classify_evidence, classify_text,
)


# ── Default trust edges ────────────────────────────────────────────────────

@dataclass(frozen=True)
class TrustEdge:
    """Directed edge: pivot found via ``from_signal`` unlocks ``to_surface``."""
    from_signal:  str                 # cred-pattern name or surface-shape id
    to_surface:   str                 # logical surface identifier
    note:         str = ""


DEFAULT_TRUST_EDGES: tuple[TrustEdge, ...] = (
    # Workspace via OAuth.
    TrustEdge("google_oauth_acc",  "google_workspace.drive"),
    TrustEdge("google_oauth_acc",  "google_workspace.gmail"),
    TrustEdge("google_oauth_acc",  "google_workspace.calendar"),
    TrustEdge("google_api_key",    "google_cloud.apis"),
    TrustEdge("oauth_scope",       "oauth_identified_services"),
    TrustEdge("workspace_shape",   "google_workspace.drive"),

    # AWS.
    TrustEdge("aws_access_key",    "aws.s3"),
    TrustEdge("aws_access_key",    "aws.iam"),
    TrustEdge("aws_access_key",    "aws.ec2"),
    TrustEdge("aws_session_token", "aws.temporary_session"),
    TrustEdge("imds_shape",        "aws.instance_role"),

    # GitHub.
    TrustEdge("github_pat",        "github.private_repos"),
    TrustEdge("github_pat",        "github.org_secrets"),
    TrustEdge("github_app_tok",    "github.installation_scope"),

    # Slack.
    TrustEdge("slack_bot_token",   "slack.private_channels"),
    TrustEdge("slack_bot_token",   "slack.dm_history"),

    # Payments / finance.
    TrustEdge("stripe_live_key",   "stripe.customers"),
    TrustEdge("stripe_live_key",   "stripe.charges"),

    # PaaS.
    TrustEdge("vercel_token",      "vercel.env_vars"),
    TrustEdge("vercel_token",      "vercel.deploy_hooks"),
    TrustEdge("paas_env_shape",    "paas.production_env"),

    # JWT / bearer — generic but valuable.
    TrustEdge("jwt_bearer",        "api.jwt_identified_scope"),
    TrustEdge("generic_bearer",    "api.bearer_identified_scope"),
)


# ── Output shape ────────────────────────────────────────────────────────────

@dataclass
class BlastRadiusMap:
    """
    The Phase 9 artifact. JSON-serialisable; attached to Wilson
    bundles and ALEC envelopes as ``blast_radius.json``.
    """
    chain_id:                 str
    target_id:                str
    harm_score:               int                       # 0-100
    severity_label:           str
    directly_reached:         list[str]
    transitively_reachable:   list[str]
    data_classes_exposed:     dict[str, list[str]]
    regulatory_impact:        list[str]
    max_harm_scenario:        str
    finding_to_signals:       dict[str, list[str]]      # finding_id -> pattern names
    trust_edges_applied:      list[dict]

    def to_dict(self) -> dict:
        return {
            "chain_id":               self.chain_id,
            "target_id":              self.target_id,
            "harm_score":             self.harm_score,
            "severity_label":         self.severity_label,
            "directly_reached":       list(self.directly_reached),
            "transitively_reachable": list(self.transitively_reachable),
            "data_classes_exposed":   {k: list(v) for k, v
                                       in self.data_classes_exposed.items()},
            "regulatory_impact":      list(self.regulatory_impact),
            "max_harm_scenario":      self.max_harm_scenario,
            "finding_to_signals":     {k: list(v) for k, v
                                       in self.finding_to_signals.items()},
            "trust_edges_applied":    list(self.trust_edges_applied),
        }


# ── Harm scoring ────────────────────────────────────────────────────────────

_SEVERITY_BASE = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}
_DATA_WEIGHT   = {"SECRET":     20, "CREDENTIAL": 15, "PCI": 18,
                  "PHI":        18, "PII":         8, "BIOMETRIC": 12}
_REG_WEIGHT    = 4      # per distinct regulation touched
_TRANSIT_WEIGHT = 2     # per transitively-reachable surface


def _label_for(score: int) -> str:
    if score >= 80: return "CATASTROPHIC"
    if score >= 60: return "CRITICAL"
    if score >= 40: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"


# ── Optimizer entry point ───────────────────────────────────────────────────

def optimize_impact(
    *,
    chain,                                     # CompoundChain
    findings:       list[AgentFinding],
    evidences:      Optional[list] = None,     # list[DeterministicEvidence]
    trust_edges:    Optional[Iterable[TrustEdge]] = None,
    extra_text:     str = "",
) -> BlastRadiusMap:
    """
    Synthesise a BlastRadiusMap for a compound chain.

    ``findings`` should be the same set the chain was built from.
    ``evidences`` is an optional list of DeterministicEvidence — when
    supplied, their reachable text is classified so the map reports
    concrete data-class exposure. ``extra_text`` adds any additional
    blob (e.g. report logs) to classification.
    ``trust_edges`` overrides DEFAULT_TRUST_EDGES when the caller has
    target-specific topology to model.
    """
    edges = list(trust_edges or DEFAULT_TRUST_EDGES)

    # 1) Collect signals from finding metadata + evidence classification.
    finding_signals: dict[str, list[str]] = {}
    class_union:     dict[str, set[str]]  = {}
    reg_union:       set[str]             = set()

    def _absorb(cls: DataClassification) -> None:
        for c, names in cls.classes.items():
            class_union.setdefault(c, set()).update(names)
        reg_union.update(cls.regulatory_tags)

    for f in findings:
        signals: list[str] = []
        # Each finding may carry a `meta.pattern_name` from its verdict;
        # classify the delta_evidence blob for additional shape hits.
        blob = (f.delta_evidence or "") + "\n" + (f.description or "")
        cls = classify_text(blob, source=f"finding:{f.id}")
        _absorb(cls)
        # Pull pattern_names from all class hits — these are the
        # trust-edge keys.
        for names in cls.classes.values():
            signals.extend(names)
        # Also latch onto any shape tag encoded in the attack_variant_id
        # (EP-11 embeds the technique id there).
        if f.attack_variant_id:
            signals.append(f.attack_variant_id)
        finding_signals[f.id] = sorted(set(signals))

    # Classify any attached evidence artifacts.
    for ev in (evidences or []):
        try:
            cls = classify_evidence(ev)
            _absorb(cls)
            for c, names in cls.classes.items():
                class_union.setdefault(c, set()).update(names)
        except TypeError:
            continue

    if extra_text:
        _absorb(classify_text(extra_text, source="optimizer:extra_text"))

    # 2) Directly reached surfaces = the chain's step surfaces.
    directly: list[str] = []
    for s in chain.steps:
        if s.surface and s.surface not in directly:
            directly.append(s.surface)

    # 3) Transitive reach via trust edges.
    all_signals: set[str] = set()
    for sigs in finding_signals.values():
        all_signals.update(sigs)
    # Also mine class_union — classified patterns are themselves signals.
    for names in class_union.values():
        all_signals.update(names)

    transitively: list[str] = []
    edges_applied: list[dict] = []
    for edge in edges:
        if edge.from_signal in all_signals:
            if edge.to_surface not in directly and \
               edge.to_surface not in transitively:
                transitively.append(edge.to_surface)
                edges_applied.append({
                    "from_signal": edge.from_signal,
                    "to_surface":  edge.to_surface,
                    "note":        edge.note,
                })

    # 4) Harm score.
    score = _SEVERITY_BASE.get(chain.severity or "HIGH", 10)

    # RCE floor — if any confirmed finding is ENVIRONMENT_PIVOT,
    # the blast radius is at minimum HIGH regardless of what data
    # classes were captured. Shell execution on the host IS the
    # impact. The operator doesn't need /etc/passwd in the evidence
    # to know that arbitrary code execution on the host is severe.
    rce_confirmed = any(
        getattr(f, "vuln_class", "") == "ENVIRONMENT_PIVOT"
        and getattr(f, "exploitability_confirmed", False)
        for f in (findings or [])
    )
    if rce_confirmed:
        score = max(score, _SEVERITY_BASE["HIGH"])  # floor at HIGH(25)
        if chain.severity in ("CRITICAL", "HIGH"):
            score = max(score, _SEVERITY_BASE["CRITICAL"])  # CRITICAL floor
    for cls_name in class_union:
        score += _DATA_WEIGHT.get(cls_name, 0)
    score += _REG_WEIGHT * len(reg_union)
    score += _TRANSIT_WEIGHT * len(transitively)
    score = max(0, min(100, score))

    # 5) Narrative — worst-case scenario summary.
    max_scenario = _max_harm_narrative(
        target=chain.target_id,
        directly=directly, transitively=transitively,
        classes=class_union, regs=reg_union,
    )

    return BlastRadiusMap(
        chain_id=chain.chain_id,
        target_id=chain.target_id,
        harm_score=int(score),
        severity_label=_label_for(score),
        directly_reached=directly,
        transitively_reachable=transitively,
        data_classes_exposed={k: sorted(v) for k, v in class_union.items()},
        regulatory_impact=sorted(reg_union),
        max_harm_scenario=max_scenario,
        finding_to_signals=finding_signals,
        trust_edges_applied=edges_applied,
    )


# ── Narrative ──────────────────────────────────────────────────────────────

def _max_harm_narrative(
    *,
    target:       str,
    directly:     list[str],
    transitively: list[str],
    classes:      dict[str, set[str]],
    regs:         set[str],
) -> str:
    lines: list[str] = [
        f"Target {target} compromised via {len(directly)} directly-reached "
        f"surface(s) and {len(transitively)} transitively-reachable "
        f"downstream service(s)."
    ]
    if classes:
        data_line = "Data classes exposed: " + ", ".join(
            f"{c}({len(sorted(v))})" for c, v in classes.items()
        )
        lines.append(data_line)
    if regs:
        lines.append("Regulatory exposure: " + ", ".join(sorted(regs)))
    if transitively:
        lines.append(
            "Transitive reach includes: " + ", ".join(transitively[:8])
            + ("…" if len(transitively) > 8 else "")
        )
    # Sector-specific worst-case clause.
    if "SECRET" in classes or "CREDENTIAL" in classes:
        lines.append(
            "Worst case: adversary leverages disclosed credentials to "
            "pivot into the connected services above, exfiltrating "
            "data and establishing persistent access — the full "
            "OAuth-supply-chain-class outcome."
        )
    elif "PCI" in classes:
        lines.append("Worst case: cardholder data theft triggers PCI-DSS "
                     "breach notification requirements and payment-brand "
                     "penalties.")
    elif "PHI" in classes:
        lines.append("Worst case: protected health information disclosure "
                     "triggers HIPAA breach notification and OCR "
                     "investigation.")
    elif "PII" in classes:
        lines.append("Worst case: personal data disclosure triggers GDPR / "
                     "CCPA 72-hour regulator notification.")
    return "\n".join(lines)
