"""SIEM Integration Export.

**Requires ARGUS Enterprise.**

Exports ARGUS findings to SIEM platforms (Splunk, Microsoft Sentinel,
Elastic SIEM) in their native ingestion formats.

This module is a stub — the full SIEM integration pipeline will be
implemented as part of the Enterprise feature set.
"""

from __future__ import annotations

from typing import Any

from argus.tiering import Feature, require_enterprise


class SIEMExporter:
    """Base class for SIEM platform integrations.

    **Requires ARGUS Enterprise.**

    Raises:
        TierRestricted: At construction if the current tier is not Enterprise.
    """

    def __init__(self) -> None:
        require_enterprise(Feature.SIEM_EXPORT)

    def export_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform ARGUS findings into SIEM-native events.

        Args:
            findings: List of finding dictionaries.

        Returns:
            List of SIEM-formatted event dictionaries.

        Raises:
            NotImplementedError: SIEM export is not yet implemented.
        """
        raise NotImplementedError(
            "SIEM export is planned for a future Enterprise release. "
            "Use JSON reports (available in Core) for manual SIEM ingestion."
        )


class SplunkExporter(SIEMExporter):
    """Export findings to Splunk HEC (HTTP Event Collector).

    Planned features:
      - HEC-formatted JSON events
      - Configurable source type and index
      - Batch upload via Splunk REST API
      - CIM (Common Information Model) field mapping
    """

    def export_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform findings into Splunk HEC events."""
        require_enterprise(Feature.SIEM_EXPORT)
        raise NotImplementedError("Splunk HEC export is planned for a future Enterprise release.")


class SentinelExporter(SIEMExporter):
    """Export findings to Microsoft Sentinel.

    Planned features:
      - Log Analytics Data Collector API format
      - Custom log table (ARGUS_Findings_CL)
      - Sentinel incident creation via API
      - KQL query templates for detection rules
    """

    def export_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform findings into Sentinel log entries."""
        require_enterprise(Feature.SIEM_EXPORT)
        raise NotImplementedError("Microsoft Sentinel export is planned for a future Enterprise release.")


__all__ = ["SIEMExporter", "SentinelExporter", "SplunkExporter"]
