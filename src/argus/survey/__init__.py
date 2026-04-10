"""SURVEY — AI Agent Attack Surface Mapper.

Nmap-equivalent for the AI agent attack surface. SURVEY discovers what an
AI target exposes BEFORE the attack agents start firing. Recon before exploit.

Capabilities:
  - EndpointProber: HTTP probing of common AI agent endpoint paths
    (/chat, /memory, /execute, /admin, /health, /tools, /v1/messages, ...)
  - CapabilityMapper: classify discovered endpoints by attack surface type
    (chat, memory, identity, execution, exfiltration, admin)
  - Tool enumeration is delegated to argus.mcp_client (already implemented)

Design notes:
  - Pure HTTP/JSON probing — no MCP-specific logic.
  - SSRF-bound: each EndpointProber instance is locked to one base URL.
  - Generic — no scenario-specific paths hardcoded. Probes the same set of
    common endpoint conventions any AI agent might expose, regardless of
    whether ARGUS is hitting a benchmark target or a customer engagement.
"""

from argus.survey.prober import (
    CapabilityMapper,
    DiscoveredEndpoint,
    EndpointProber,
    SurfaceClass,
    SurveyReport,
)

__all__ = [
    "CapabilityMapper",
    "DiscoveredEndpoint",
    "EndpointProber",
    "SurfaceClass",
    "SurveyReport",
]
