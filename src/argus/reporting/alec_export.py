"""ALEC Evidence Package Export.

Phase 4 integration: ARGUS finding reports can be incorporated into
ALEC (Autonomous Legal Evidence Chain) evidence packages.

ALEC seals evidence and produces legal documentation when incidents
occur. This module exports ARGUS scan results in a structured format
that ALEC can ingest directly — providing the red team evidence chain
that complements ALEC's incident documentation.

Output format:
  - Timestamped evidence entries with cryptographic hashes
  - Finding-level detail with reproduction steps
  - Compound attack path documentation
  - CERBERUS rule cross-references
  - Chain-of-custody metadata for legal admissibility
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from argus.models.findings import CompoundAttackPath, Finding
from argus.orchestrator.engine import ScanResult
from argus.reporting.cerberus_rules import CerberusRuleGenerator


class ALECEvidenceExporter:
    """Exports ARGUS scan results as ALEC-compatible evidence packages.

    Each evidence package contains:
    - Executive summary with scan metadata
    - Individual evidence entries for each validated finding
    - Compound attack path documentation
    - CERBERUS cross-references
    - SHA-256 integrity hashes for tamper detection

    **Requires ARGUS Enterprise.**  The tier check is enforced at
    construction time so callers get an immediate, clear error rather
    than a silent empty export.
    """

    ALEC_SCHEMA_VERSION = "1.0.0"
    EVIDENCE_FORMAT = "argus-alec-bridge"

    def __init__(self) -> None:
        from argus.tiering import Feature, require_enterprise

        require_enterprise(Feature.ALEC_EXPORT)

    def export_evidence_package(self, scan_result: ScanResult) -> dict[str, Any]:
        """Export a full ALEC evidence package from a scan result.

        Returns a JSON-serializable dictionary containing the complete
        evidence package ready for ALEC ingestion.
        """
        now = datetime.now(UTC)
        validated = scan_result.validated_findings

        # Generate CERBERUS rules for cross-reference
        cerberus_gen = CerberusRuleGenerator()
        cerberus_rules = cerberus_gen.generate_rules(validated)

        # Build evidence entries
        evidence_entries = [self._finding_to_evidence(f, index=i) for i, f in enumerate(validated)]

        # Build compound path entries
        compound_entries = [self._compound_to_evidence(p, index=i) for i, p in enumerate(scan_result.compound_paths)]

        # Build the package
        package = {
            "alec_schema_version": self.ALEC_SCHEMA_VERSION,
            "evidence_format": self.EVIDENCE_FORMAT,
            "generated_at": now.isoformat(),
            "generator": "ARGUS Autonomous AI Red Team",
            "generator_version": "0.1.0",
            "chain_of_custody": {
                "created_by": "ARGUS automated scan",
                "creation_timestamp": now.isoformat(),
                "integrity_method": "SHA-256",
                "notes": (
                    "This evidence package was generated automatically by ARGUS. "
                    "All findings have been validated with reproducible proof-of-exploitation. "
                    "Evidence entries are individually hashed for tamper detection."
                ),
            },
            "scan_metadata": {
                "scan_id": scan_result.scan_id,
                "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
                "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                "duration_seconds": scan_result.duration_seconds,
                "agents_deployed": len(scan_result.agent_results),
                "total_findings": len(scan_result.findings),
                "validated_findings": len(validated),
                "compound_attack_paths": len(scan_result.compound_paths),
            },
            "executive_summary": self._build_executive_summary(scan_result),
            "evidence_entries": evidence_entries,
            "compound_attack_paths": compound_entries,
            "cerberus_cross_references": {
                "total_rules_generated": len(cerberus_rules),
                "rules": [rule.model_dump() for rule in cerberus_rules],
            },
        }

        # Compute package-level integrity hash
        package["package_integrity_hash"] = self._compute_hash(json.dumps(package, sort_keys=True, default=str))

        return package

    def export_json(self, scan_result: ScanResult) -> str:
        """Export evidence package as a JSON string."""
        return json.dumps(
            self.export_evidence_package(scan_result),
            indent=2,
            default=str,
        )

    def _build_executive_summary(self, scan_result: ScanResult) -> dict[str, Any]:
        """Build an executive summary suitable for board/insurance/regulatory use."""
        validated = scan_result.validated_findings
        severity_counts: dict[str, int] = {}
        for f in validated:
            sev = f.severity.value.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Categorize by OWASP
        owasp_categories: dict[str, int] = {}
        for f in validated:
            if f.owasp_agentic:
                cat = f.owasp_agentic.value
                owasp_categories[cat] = owasp_categories.get(cat, 0) + 1

        return {
            "assessment_type": "Autonomous AI Red Team — Full Swarm Assessment",
            "product": "ARGUS by Odingard Security / Six Sense Enterprise Services",
            "findings_by_severity": severity_counts,
            "findings_by_owasp_category": owasp_categories,
            "compound_attack_paths_discovered": len(scan_result.compound_paths),
            "risk_narrative": self._generate_risk_narrative(scan_result),
        }

    def _generate_risk_narrative(self, scan_result: ScanResult) -> str:
        """Generate a human-readable risk narrative for the executive summary."""
        validated = scan_result.validated_findings
        if not validated:
            return (
                "ARGUS autonomous red team assessment completed with no validated "
                "findings. The target AI system demonstrated resilience against "
                "all tested attack vectors across the full OWASP Agentic AI Top 10."
            )

        critical_high = [f for f in validated if f.severity.value in ("critical", "high")]
        compound_count = len(scan_result.compound_paths)

        parts = [
            f"ARGUS autonomous red team assessment identified {len(validated)} "
            f"validated vulnerabilit{'y' if len(validated) == 1 else 'ies'} "
            f"in the target AI system.",
        ]

        if critical_high:
            parts.append(
                f"{len(critical_high)} finding(s) are rated CRITICAL or HIGH severity, "
                f"indicating exploitable vulnerabilities that could lead to data "
                f"exfiltration, privilege escalation, or system compromise."
            )

        if compound_count:
            parts.append(
                f"The Correlation Agent identified {compound_count} compound attack "
                f"path(s) where individual findings chain into higher-severity exploits "
                f"that no single vulnerability scan would detect."
            )

        parts.append(
            "Remediation guidance and CERBERUS detection rules are provided "
            "for each finding. See individual evidence entries for full "
            "reproduction steps and proof-of-exploitation."
        )

        return " ".join(parts)

    def _finding_to_evidence(self, finding: Finding, index: int) -> dict[str, Any]:
        """Convert a single finding into an ALEC evidence entry."""
        entry = {
            "evidence_id": f"ARGUS-EV-{index + 1:04d}",
            "finding_id": finding.id,
            "timestamp": finding.timestamp.isoformat(),
            "classification": {
                "severity": finding.severity.value.upper(),
                "agent_type": finding.agent_type,
                "technique": finding.technique,
                "target_surface": finding.target_surface,
            },
            "title": finding.title,
            "description": finding.description,
            "owasp_mapping": {
                "agentic": finding.owasp_agentic.value if finding.owasp_agentic else None,
                "llm": finding.owasp_llm.value if finding.owasp_llm else None,
            },
            "proof_of_exploitation": None,
            "reproduction_steps": [
                {
                    "step": step.step_number,
                    "action": step.action,
                    "input": step.input_data,
                    "expected": step.expected_result,
                    "actual": step.actual_result,
                }
                for step in finding.reproduction_steps
            ],
            "attack_chain": [
                {
                    "step": step.step_number,
                    "agent": step.agent_type,
                    "technique": step.technique,
                    "description": step.description,
                    "surface": step.target_surface,
                }
                for step in finding.attack_chain
            ],
            "remediation": None,
            "verdict_score": finding.verdict_score,
        }

        # Add validation proof if available
        if finding.validation:
            entry["proof_of_exploitation"] = {
                "validated": finding.validation.validated,
                "method": finding.validation.validation_method,
                "proof": finding.validation.proof_of_exploitation,
                "reproducible": finding.validation.reproducible,
                "attempts": finding.validation.attempts,
            }

        # Add remediation if available
        if finding.remediation:
            entry["remediation"] = {
                "summary": finding.remediation.summary,
                "steps": finding.remediation.detailed_steps,
                "cerberus_rule": finding.remediation.cerberus_detection_rule,
                "references": finding.remediation.references,
            }

        # Compute integrity hash for this evidence entry
        entry["integrity_hash"] = self._compute_hash(json.dumps(entry, sort_keys=True, default=str))

        return entry

    def _compound_to_evidence(self, path: CompoundAttackPath, index: int) -> dict[str, Any]:
        """Convert a compound attack path into an ALEC evidence entry."""
        entry = {
            "evidence_id": f"ARGUS-CP-{index + 1:04d}",
            "path_id": path.id,
            "timestamp": path.timestamp.isoformat(),
            "title": path.title,
            "description": path.description,
            "severity": path.severity.value.upper(),
            "compound_impact": path.compound_impact,
            "exploitability_score": path.exploitability_score,
            "detectability_score": path.detectability_score,
            "finding_ids": path.finding_ids,
            "attack_steps": [
                {
                    "step": step.step_number,
                    "agent": step.agent_type,
                    "technique": step.technique,
                    "description": step.description,
                    "surface": step.target_surface,
                }
                for step in path.attack_path_steps
            ],
            "owasp_categories": [cat.value for cat in path.owasp_agentic],
            "remediation": None,
        }

        if path.remediation:
            entry["remediation"] = {
                "summary": path.remediation.summary,
                "steps": path.remediation.detailed_steps,
                "references": path.remediation.references,
            }

        entry["integrity_hash"] = self._compute_hash(json.dumps(entry, sort_keys=True, default=str))

        return entry

    @staticmethod
    def _compute_hash(content: str) -> str:
        """Compute a SHA-256 hash of content for integrity verification."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
