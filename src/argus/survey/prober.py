"""EndpointProber — discover AI agent attack surfaces via HTTP probing.

SURVEY's first capability. Walks a target base URL probing common endpoint
paths that AI agents typically expose, classifies each discovery by attack
surface type, and returns a SurveyReport for the attack agents to consume.

The probe set is intentionally generic — these are the conventional paths
any AI agent backend might expose, not benchmark-specific routes. SURVEY
must work the same way against an internal customer engagement as it does
against the ARGUS Gauntlet test scenarios.
"""

from __future__ import annotations

import asyncio
import logging
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SurfaceClass(str, Enum):
    """Classification of an AI agent's exposed surface."""

    CHAT = "chat"  # /chat, /v1/messages — primary user input
    MEMORY = "memory"  # /memory, /context — persistent state
    IDENTITY = "identity"  # /execute, /agents — A2A / privilege boundaries
    TOOLS = "tools"  # /tools, /functions — tool catalog
    EXFILTRATION = "exfiltration"  # /exfil-log, /audit — observability surfaces
    ADMIN = "admin"  # /admin, /config — control plane
    HEALTH = "health"  # /health, /ping, /status — liveness
    UNKNOWN = "unknown"


# Generic probe set — conventional paths any HTTP AI agent might expose.
# Each entry: (path, http_method, surface_class, optional_body)
# The classifier in CapabilityMapper does the heavy lifting; this list is
# just the seed set of things to try.
_PROBE_PATHS: list[tuple[str, str, SurfaceClass, dict[str, Any] | None]] = [
    # Health / liveness
    ("/health", "GET", SurfaceClass.HEALTH, None),
    ("/healthz", "GET", SurfaceClass.HEALTH, None),
    ("/ping", "GET", SurfaceClass.HEALTH, None),
    ("/status", "GET", SurfaceClass.HEALTH, None),
    # Chat surfaces
    ("/chat", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/v1/chat", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/v1/messages", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/api/chat", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/conversation", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    # Memory surfaces
    ("/memory", "GET", SurfaceClass.MEMORY, None),
    ("/memory/list", "GET", SurfaceClass.MEMORY, None),
    ("/context", "GET", SurfaceClass.MEMORY, None),
    # Identity / A2A / execution
    ("/execute", "POST", SurfaceClass.IDENTITY, {"command": "noop"}),
    ("/agents", "GET", SurfaceClass.IDENTITY, None),
    ("/v1/agents", "GET", SurfaceClass.IDENTITY, None),
    # Tool catalog
    ("/tools", "GET", SurfaceClass.TOOLS, None),
    ("/tools/list", "GET", SurfaceClass.TOOLS, None),
    ("/functions", "GET", SurfaceClass.TOOLS, None),
    # Exfiltration / observability surfaces (the kind benchmark scenarios expose
    # but real systems often expose too via debug endpoints)
    ("/exfil-log", "GET", SurfaceClass.EXFILTRATION, None),
    ("/audit", "GET", SurfaceClass.EXFILTRATION, None),
    ("/logs", "GET", SurfaceClass.EXFILTRATION, None),
    # Admin
    ("/admin", "GET", SurfaceClass.ADMIN, None),
    ("/config", "GET", SurfaceClass.ADMIN, None),
    ("/v1/admin", "GET", SurfaceClass.ADMIN, None),
]


class DiscoveredEndpoint(BaseModel):
    """A single endpoint discovered by SURVEY."""

    base_url: str
    path: str
    method: str
    surface_class: SurfaceClass
    status_code: int | None = None
    response_text_snippet: str = Field(default="", description="First 1KB of response body")
    response_keys: list[str] = Field(default_factory=list, description="Top-level JSON keys")
    error: str | None = None

    def is_live(self) -> bool:
        """A discovery counts if the server responded with anything other than 404 or transport error."""
        if self.error is not None:
            return False
        if self.status_code is None:
            return False
        # 404 means the path doesn't exist; 405 means it does but wrong method (still a discovery)
        return self.status_code != 404


class SurveyReport(BaseModel):
    """Aggregated survey of one target's attack surface."""

    target_base_url: str
    discovered: list[DiscoveredEndpoint] = Field(default_factory=list)
    by_surface: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Map of surface_class -> list of paths discovered",
    )

    def endpoints_for(self, surface: SurfaceClass) -> list[DiscoveredEndpoint]:
        return [d for d in self.discovered if d.surface_class == surface and d.is_live()]

    def has_surface(self, surface: SurfaceClass) -> bool:
        return any(d.surface_class == surface and d.is_live() for d in self.discovered)


class EndpointProber:
    """Probes a single base URL for common AI agent endpoint conventions.

    SSRF-bound to one base URL — all probes resolve relative paths against
    that base. Per-probe paths cannot redirect to a different host.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 5.0,
        max_concurrent: int = 8,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"EndpointProber base_url must be http(s): {base_url}")
        self._allowed_host = parsed.netloc
        self.timeout_seconds = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._transport = transport

    async def probe_all(self) -> SurveyReport:
        """Probe the full default path set against the base URL.

        Returns a SurveyReport with all discoveries (live and dead).
        """
        kwargs: dict[str, Any] = {
            "timeout": self.timeout_seconds,
            "event_hooks": {"request": [], "response": []},
            "follow_redirects": False,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport

        async with httpx.AsyncClient(**kwargs) as client:
            tasks = [
                self._probe_one(client, path, method, surface, body) for path, method, surface, body in _PROBE_PATHS
            ]
            discoveries = await asyncio.gather(*tasks)

        report = SurveyReport(target_base_url=self.base_url)
        for d in discoveries:
            report.discovered.append(d)
            if d.is_live():
                report.by_surface.setdefault(d.surface_class.value, []).append(d.path)

        logger.info(
            "SURVEY %s — %d/%d endpoints live across %d surface classes",
            self.base_url,
            sum(1 for d in discoveries if d.is_live()),
            len(discoveries),
            len(report.by_surface),
        )
        return report

    async def _probe_one(
        self,
        client: httpx.AsyncClient,
        path: str,
        method: str,
        surface: SurfaceClass,
        body: dict[str, Any] | None,
    ) -> DiscoveredEndpoint:
        url = f"{self.base_url}{path}"
        # SSRF guard: a path with an absolute scheme would let an upstream
        # caller redirect us elsewhere. Probes are constructed in code so
        # this is defense-in-depth.
        if path.startswith(("http://", "https://")):
            return DiscoveredEndpoint(
                base_url=self.base_url,
                path=path,
                method=method,
                surface_class=surface,
                error="absolute path rejected",
            )
        async with self._semaphore:
            try:
                resp = await client.request(method, url, json=body)
            except httpx.HTTPError as exc:
                return DiscoveredEndpoint(
                    base_url=self.base_url,
                    path=path,
                    method=method,
                    surface_class=surface,
                    error=f"{type(exc).__name__}: {str(exc)[:120]}",
                )

        snippet = resp.text[:1024]
        keys: list[str] = []
        try:
            data = resp.json()
            if isinstance(data, dict):
                keys = list(data.keys())[:20]
        except Exception as exc:
            logger.debug("Non-JSON response from %s: %s", url, type(exc).__name__)

        return DiscoveredEndpoint(
            base_url=self.base_url,
            path=path,
            method=method,
            surface_class=surface,
            status_code=resp.status_code,
            response_text_snippet=snippet,
            response_keys=keys,
        )


class CapabilityMapper:
    """Classifies discovered endpoints into actionable attack opportunities.

    Given a SurveyReport, returns a structured map of which agents should
    target which endpoints. This is what Phase 2+ agents consume to know
    where to attack — instead of hardcoding endpoint paths in each agent.
    """

    @staticmethod
    def map_for_phase2(report: SurveyReport) -> dict[str, list[DiscoveredEndpoint]]:
        """Return a map of {agent_type: [endpoints]} for Phase 2 agents.

        - memory_poisoning  ← MEMORY + CHAT surfaces
        - identity_spoof    ← IDENTITY surfaces (anything that takes a command/role)
        - prompt_injection  ← CHAT surfaces (already covered by Phase 1, included for chaining)
        - exfiltration_recon← EXFILTRATION + ADMIN surfaces (signal source for validation)
        """
        return {
            "memory_poisoning": [
                *report.endpoints_for(SurfaceClass.MEMORY),
                *report.endpoints_for(SurfaceClass.CHAT),
            ],
            "identity_spoof": report.endpoints_for(SurfaceClass.IDENTITY),
            "prompt_injection": report.endpoints_for(SurfaceClass.CHAT),
            "exfiltration_recon": [
                *report.endpoints_for(SurfaceClass.EXFILTRATION),
                *report.endpoints_for(SurfaceClass.ADMIN),
            ],
        }

    @staticmethod
    def map_for_phase3_4(report: SurveyReport) -> dict[str, list[DiscoveredEndpoint]]:
        """Return a map of {agent_type: [endpoints]} for Phase 3-4 agents.

        - context_window           ← CHAT surfaces (multi-turn context manipulation)
        - cross_agent_exfiltration ← IDENTITY + EXFILTRATION + CHAT (inter-agent relay)
        - privilege_escalation     ← IDENTITY + ADMIN + TOOLS (tool-chain escalation)
        - race_condition           ← CHAT + IDENTITY + TOOLS (concurrent request targets)
        - model_extraction         ← CHAT + TOOLS + ADMIN (config/prompt extraction)
        """
        return {
            "context_window": report.endpoints_for(SurfaceClass.CHAT),
            "cross_agent_exfiltration": [
                *report.endpoints_for(SurfaceClass.IDENTITY),
                *report.endpoints_for(SurfaceClass.EXFILTRATION),
                *report.endpoints_for(SurfaceClass.CHAT),
            ],
            "privilege_escalation": [
                *report.endpoints_for(SurfaceClass.IDENTITY),
                *report.endpoints_for(SurfaceClass.ADMIN),
                *report.endpoints_for(SurfaceClass.TOOLS),
            ],
            "race_condition": [
                *report.endpoints_for(SurfaceClass.CHAT),
                *report.endpoints_for(SurfaceClass.IDENTITY),
                *report.endpoints_for(SurfaceClass.TOOLS),
            ],
            "model_extraction": [
                *report.endpoints_for(SurfaceClass.CHAT),
                *report.endpoints_for(SurfaceClass.TOOLS),
                *report.endpoints_for(SurfaceClass.ADMIN),
            ],
        }

    @staticmethod
    def map_all(report: SurveyReport) -> dict[str, list[DiscoveredEndpoint]]:
        """Return a unified map of {agent_type: [endpoints]} for all agents.

        Combines Phase 2 and Phase 3-4 mappings into a single lookup.
        """
        combined = CapabilityMapper.map_for_phase2(report)
        combined.update(CapabilityMapper.map_for_phase3_4(report))
        return combined
