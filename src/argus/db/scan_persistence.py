"""Scan persistence — auto-save scan results to the database.

Integrates with the Orchestrator to automatically persist every scan
result, finding, agent result, and compound attack path to the database.
This ensures scan history survives process restarts.
"""

from __future__ import annotations

import logging
from typing import Any

from argus.db.repository import ScanRepository
from argus.db.session import init_db
from argus.orchestrator.engine import ScanResult
from argus.reporting.html_report import HTMLReportGenerator
from argus.reporting.renderer import ReportRenderer

logger = logging.getLogger(__name__)


class ScanPersistence:
    """Persists scan results to the database after completion.

    Usage:
        persistence = ScanPersistence()
        persistence.save(scan_result, target_name="MyClient")
    """

    def __init__(self) -> None:
        init_db()  # Ensure tables exist
        self._repo = ScanRepository()

    def save(
        self,
        scan_result: ScanResult,
        target_name: str = "",
        target_id: str | None = None,
        initiated_by: str = "cli",
    ) -> dict[str, Any]:
        """Persist a complete ScanResult to the database.

        Saves the scan record, all agent results, all findings,
        compound attack paths, and generates/stores the HTML report.

        Returns the saved scan record dict.
        """
        summary = scan_result.summary()

        # Generate reports
        renderer = ReportRenderer()
        report_json = renderer.render_json(scan_result)

        html_gen = HTMLReportGenerator()
        report_html = html_gen.generate(scan_result, target_name=target_name)

        # 1. Create scan record
        scan_record = self._repo.create_scan(
            scan_id=scan_result.scan_id,
            target_name=target_name,
            target_id=target_id,
            initiated_by=initiated_by,
        )
        logger.info("Persisted scan record: %s", scan_result.scan_id[:8])

        # 2. Save agent results
        for ar in scan_result.agent_results:
            self._repo.save_agent_result(
                scan_id=scan_result.scan_id,
                agent_type=ar.agent_type.value if hasattr(ar.agent_type, "value") else str(ar.agent_type),
                instance_id=ar.instance_id,
                status=ar.status.value if hasattr(ar.status, "value") else str(ar.status),
                started_at=ar.started_at,
                completed_at=ar.completed_at,
                duration_seconds=ar.duration_seconds,
                findings_count=ar.findings_count,
                validated_count=ar.validated_count,
                techniques_attempted=ar.techniques_attempted,
                techniques_succeeded=ar.techniques_succeeded,
                requests_made=ar.requests_made,
                signals_emitted=ar.signals_emitted,
                errors=ar.errors,
            )
        logger.info("Persisted %d agent results", len(scan_result.agent_results))

        # 3. Save findings
        for finding in scan_result.findings:
            finding_dict = finding.model_dump()
            # Convert enum values to strings for JSON storage
            if hasattr(finding.severity, "value"):
                finding_dict["severity"] = finding.severity.value
            if hasattr(finding.status, "value"):
                finding_dict["status"] = finding.status.value
            if finding.owasp_agentic and hasattr(finding.owasp_agentic, "value"):
                finding_dict["owasp_agentic"] = finding.owasp_agentic.value
            if finding.owasp_llm and hasattr(finding.owasp_llm, "value"):
                finding_dict["owasp_llm"] = finding.owasp_llm.value
            self._repo.save_finding(scan_result.scan_id, finding_dict)
        logger.info("Persisted %d findings", len(scan_result.findings))

        # 4. Save compound attack paths
        for path in scan_result.compound_paths:
            path_dict = path.model_dump()
            if hasattr(path.severity, "value"):
                path_dict["severity"] = path.severity.value
            if path.owasp_agentic:
                path_dict["owasp_agentic"] = [
                    cat.value if hasattr(cat, "value") else str(cat) for cat in path.owasp_agentic
                ]
            self._repo.save_compound_path(scan_result.scan_id, path_dict)
        logger.info("Persisted %d compound attack paths", len(scan_result.compound_paths))

        # 5. Complete scan with aggregate stats and reports
        self._repo.complete_scan(
            scan_id=scan_result.scan_id,
            status="completed",
            agents_deployed=summary["agents_deployed"],
            agents_completed=summary["agents_completed"],
            agents_failed=summary["agents_failed"],
            total_findings=summary["total_findings"],
            validated_findings=summary["validated_findings"],
            compound_paths_count=summary["compound_attack_paths"],
            signals_exchanged=summary["signals_exchanged"],
            report_json=report_json,
            report_html=report_html,
        )
        logger.info(
            "Scan %s fully persisted — %d findings, %d compound paths",
            scan_result.scan_id[:8],
            summary["total_findings"],
            summary["compound_attack_paths"],
        )

        return scan_record

    def close(self) -> None:
        self._repo.close()
