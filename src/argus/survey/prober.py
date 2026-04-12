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
    TOOLS = "tools"  # /tools, /functions — tool catalog (read-only enum)
    TOOL_CALL = "tool_call"  # /tools/call — POST tool invocation surface
    PAYMENT = "payment"  # /pay, /transfer — value-bearing state mutators
    EXFILTRATION = "exfiltration"  # /exfil-log, /audit — observability surfaces
    ADMIN = "admin"  # /admin, /config — control plane
    HEALTH = "health"  # /health, /ping, /status — liveness
    UNKNOWN = "unknown"


# Generic probe set — conventional paths any HTTP AI agent might expose.
# Each entry: (path, http_method, surface_class, optional_body)
# The classifier in CapabilityMapper does the heavy lifting; this list is
# just the seed set of things to try.
_PROBE_PATHS: list[tuple[str, str, SurfaceClass, dict[str, Any] | None]] = [
    # ── HEALTH / LIVENESS ──────────────────────────────────────────────
    ("/health", "GET", SurfaceClass.HEALTH, None),
    ("/healthz", "GET", SurfaceClass.HEALTH, None),
    ("/livez", "GET", SurfaceClass.HEALTH, None),
    ("/readyz", "GET", SurfaceClass.HEALTH, None),
    ("/ping", "GET", SurfaceClass.HEALTH, None),
    ("/status", "GET", SurfaceClass.HEALTH, None),
    ("/info", "GET", SurfaceClass.HEALTH, None),
    ("/version", "GET", SurfaceClass.HEALTH, None),
    ("/v2/health/live", "GET", SurfaceClass.HEALTH, None),        # KServe V2
    ("/v2/health/ready", "GET", SurfaceClass.HEALTH, None),       # KServe V2
    ("/health/readiness", "GET", SurfaceClass.HEALTH, None),      # LiteLLM
    ("/health/liveliness", "GET", SurfaceClass.HEALTH, None),     # LiteLLM
    # ── CHAT / COMPLETIONS — every convention in the wild ──────────────
    # Generic chat
    ("/chat", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/v1/chat", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/api/chat", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/conversation", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/query", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/ask", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/message", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/prompt", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    # OpenAI-compatible
    ("/v1/chat/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "messages": [{"role": "user", "content": "hello"}]}),
    ("/v1/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "prompt": "hello"}),
    ("/v1/messages", "POST", SurfaceClass.CHAT, {"model": "probe", "messages": [{"role": "user", "content": "hello"}]}),
    ("/chat/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "messages": [{"role": "user", "content": "hello"}]}),
    ("/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "prompt": "hello"}),
    ("/v1/responses", "POST", SurfaceClass.CHAT, {"model": "probe", "input": "hello"}),
    # Gateway / proxy prefixes
    ("/proxy/chat/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "messages": [{"role": "user", "content": "hello"}]}),
    ("/api/v1/chat/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "messages": [{"role": "user", "content": "hello"}]}),
    # Inference servers (vLLM, TGI, Ollama)
    ("/generate", "POST", SurfaceClass.CHAT, {"prompt": "hello"}),
    ("/generate_stream", "POST", SurfaceClass.CHAT, {"prompt": "hello"}),
    ("/infer", "POST", SurfaceClass.CHAT, {"prompt": "hello"}),
    ("/predict", "POST", SurfaceClass.CHAT, {"instances": [{"input": "hello"}]}),
    ("/api/generate", "POST", SurfaceClass.CHAT, {"model": "probe", "prompt": "hello"}),
    ("/api/chat", "POST", SurfaceClass.CHAT, {"model": "probe", "messages": [{"role": "user", "content": "hello"}]}),
    # KServe / Seldon
    ("/v2/models/model/infer", "POST", SurfaceClass.CHAT, {"inputs": [{"name": "input", "data": ["hello"]}]}),
    ("/api/v1.0/predictions", "POST", SurfaceClass.CHAT, {"data": {"ndarray": ["hello"]}}),
    # LangChain / LangServe
    ("/invoke", "POST", SurfaceClass.CHAT, {"input": "hello"}),
    ("/batch", "POST", SurfaceClass.CHAT, {"inputs": ["hello"]}),
    ("/stream", "POST", SurfaceClass.CHAT, {"input": "hello"}),
    # Domain-specific interaction surfaces
    ("/review", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/triage", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/analyze", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/orchestrate", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/assess", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/evaluate", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/process", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/submit", "POST", SurfaceClass.CHAT, {"message": "hello"}),
    ("/run", "POST", SurfaceClass.CHAT, {"input": "hello"}),
    ("/kickoff", "POST", SurfaceClass.CHAT, {"input": "hello"}),
    # ── MEMORY / CONTEXT / SESSION / DOCUMENTS ─────────────────────────
    ("/memory", "GET", SurfaceClass.MEMORY, None),
    ("/memory/list", "GET", SurfaceClass.MEMORY, None),
    ("/memory/search", "POST", SurfaceClass.MEMORY, {"query": "probe"}),
    ("/context", "GET", SurfaceClass.MEMORY, None),
    ("/session", "GET", SurfaceClass.MEMORY, None),
    ("/sessions", "GET", SurfaceClass.MEMORY, None),
    ("/history", "GET", SurfaceClass.MEMORY, None),
    ("/threads", "GET", SurfaceClass.MEMORY, None),
    ("/conversations", "GET", SurfaceClass.MEMORY, None),
    ("/state", "GET", SurfaceClass.MEMORY, None),
    # Document / RAG / knowledge base surfaces
    ("/documents", "GET", SurfaceClass.MEMORY, None),
    ("/documents/upload", "POST", SurfaceClass.MEMORY, None),
    ("/documents/load", "POST", SurfaceClass.MEMORY, None),
    ("/knowledge", "GET", SurfaceClass.MEMORY, None),
    ("/upload", "POST", SurfaceClass.MEMORY, None),
    ("/ingest", "POST", SurfaceClass.MEMORY, None),
    ("/index", "POST", SurfaceClass.MEMORY, None),
    ("/search", "POST", SurfaceClass.MEMORY, {"query": "probe"}),
    ("/retrieve", "POST", SurfaceClass.MEMORY, {"query": "probe"}),
    # Vector store APIs (Chroma, Qdrant, Pinecone)
    ("/api/v1/collections", "GET", SurfaceClass.MEMORY, None),
    ("/api/v1/heartbeat", "GET", SurfaceClass.MEMORY, None),
    ("/collections", "GET", SurfaceClass.MEMORY, None),
    ("/describe_index_stats", "GET", SurfaceClass.MEMORY, None),
    # File APIs
    ("/v1/files", "GET", SurfaceClass.MEMORY, None),
    ("/v1/vector_stores", "GET", SurfaceClass.MEMORY, None),
    ("/api/files", "GET", SurfaceClass.MEMORY, None),
    # ── IDENTITY / A2A / AGENT MANAGEMENT ──────────────────────────────
    ("/execute", "POST", SurfaceClass.IDENTITY, {"command": "noop"}),
    ("/agents", "GET", SurfaceClass.IDENTITY, None),
    ("/v1/agents", "GET", SurfaceClass.IDENTITY, None),
    ("/internal/agent-message", "POST", SurfaceClass.IDENTITY, {"message": "probe"}),
    ("/connect", "POST", SurfaceClass.IDENTITY, {}),
    # OpenAI Assistants API
    ("/v1/assistants", "GET", SurfaceClass.IDENTITY, None),
    ("/v1/threads", "GET", SurfaceClass.IDENTITY, None),
    # A2A protocol
    ("/.well-known/agent.json", "GET", SurfaceClass.IDENTITY, None),
    ("/tasks/send", "POST", SurfaceClass.IDENTITY, {"message": "probe"}),
    # CrewAI / AutoGen
    ("/api/agents", "GET", SurfaceClass.IDENTITY, None),
    ("/api/agents/run", "POST", SurfaceClass.IDENTITY, {"input": "probe"}),
    ("/api/sessions", "GET", SurfaceClass.IDENTITY, None),
    ("/api/runs", "GET", SurfaceClass.IDENTITY, None),
    ("/api/crew/status", "GET", SurfaceClass.IDENTITY, None),
    # ── TOOL CATALOG (read-only enumeration) ───────────────────────────
    ("/tools", "GET", SurfaceClass.TOOLS, None),
    ("/tools/list", "GET", SurfaceClass.TOOLS, None),
    ("/functions", "GET", SurfaceClass.TOOLS, None),
    ("/functions/list", "GET", SurfaceClass.TOOLS, None),
    ("/plugins", "GET", SurfaceClass.TOOLS, None),
    ("/actions", "GET", SurfaceClass.TOOLS, None),
    ("/skills", "GET", SurfaceClass.TOOLS, None),
    ("/supported-languages", "GET", SurfaceClass.TOOLS, None),
    ("/v1/models", "GET", SurfaceClass.TOOLS, None),
    ("/models", "GET", SurfaceClass.TOOLS, None),
    ("/api/tags", "GET", SurfaceClass.TOOLS, None),                # Ollama
    ("/api/ps", "GET", SurfaceClass.TOOLS, None),                  # Ollama running models
    ("/input_schema", "GET", SurfaceClass.TOOLS, None),            # LangServe
    ("/output_schema", "GET", SurfaceClass.TOOLS, None),           # LangServe
    ("/kernel/plugins", "GET", SurfaceClass.TOOLS, None),          # Semantic Kernel
    # ── TOOL INVOCATION (POST) ─────────────────────────────────────────
    ("/tools/call", "POST", SurfaceClass.TOOL_CALL, {"name": "noop", "arguments": {}}),
    ("/tool/call", "POST", SurfaceClass.TOOL_CALL, {"name": "noop", "arguments": {}}),
    ("/tool/execute", "POST", SurfaceClass.TOOL_CALL, {"name": "noop", "arguments": {}}),
    ("/v1/tools/call", "POST", SurfaceClass.TOOL_CALL, {"name": "noop", "arguments": {}}),
    ("/functions/call", "POST", SurfaceClass.TOOL_CALL, {"name": "noop", "arguments": {}}),
    ("/invoke", "POST", SurfaceClass.TOOL_CALL, {"name": "noop", "arguments": {}}),
    ("/confirm", "POST", SurfaceClass.TOOL_CALL, {}),
    ("/actions", "POST", SurfaceClass.TOOL_CALL, {"action": "noop"}),
    ("/kernel/invoke", "POST", SurfaceClass.TOOL_CALL, {"skill": "noop"}),
    # ── MCP PROTOCOL ──────────────────────────────────────────────────
    ("/mcp", "POST", SurfaceClass.TOOL_CALL, {"jsonrpc": "2.0", "method": "initialize", "params": {"capabilities": {}}, "id": 1}),
    ("/sse", "GET", SurfaceClass.TOOLS, None),
    ("/message", "POST", SurfaceClass.TOOL_CALL, {"jsonrpc": "2.0", "method": "tools/list", "id": 1}),
    ("/.well-known/mcp.json", "GET", SurfaceClass.TOOLS, None),
    ("/rpc", "POST", SurfaceClass.TOOL_CALL, {"jsonrpc": "2.0", "method": "initialize", "id": 1}),
    ("/jsonrpc", "POST", SurfaceClass.TOOL_CALL, {"jsonrpc": "2.0", "method": "initialize", "id": 1}),
    # ── PAYMENT / VALUE-BEARING STATE MUTATORS ─────────────────────────
    ("/pay", "POST", SurfaceClass.PAYMENT, {"account_id": "probe", "amount": 0}),
    ("/payment", "POST", SurfaceClass.PAYMENT, {"account_id": "probe", "amount": 0}),
    ("/transfer", "POST", SurfaceClass.PAYMENT, {"from": "probe", "to": "probe", "amount": 0}),
    ("/transaction", "POST", SurfaceClass.PAYMENT, {"amount": 0}),
    ("/charge", "POST", SurfaceClass.PAYMENT, {"amount": 0}),
    # ── EXFILTRATION / OBSERVABILITY ───────────────────────────────────
    ("/exfil-log", "GET", SurfaceClass.EXFILTRATION, None),
    ("/audit", "GET", SurfaceClass.EXFILTRATION, None),
    ("/audit/log", "GET", SurfaceClass.EXFILTRATION, None),
    ("/logs", "GET", SurfaceClass.EXFILTRATION, None),
    ("/transactions", "GET", SurfaceClass.EXFILTRATION, None),
    ("/metrics", "GET", SurfaceClass.EXFILTRATION, None),
    ("/stats", "GET", SurfaceClass.EXFILTRATION, None),
    ("/debug", "GET", SurfaceClass.EXFILTRATION, None),
    ("/debug/vars", "GET", SurfaceClass.EXFILTRATION, None),
    ("/spend/logs", "GET", SurfaceClass.EXFILTRATION, None),       # LiteLLM
    ("/global/spend", "GET", SurfaceClass.EXFILTRATION, None),     # LiteLLM
    ("/v1/organization/usage", "GET", SurfaceClass.EXFILTRATION, None),
    # ── GUARDRAILS / SAFETY ────────────────────────────────────────────
    ("/v1/moderations", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/moderate", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/safety/check", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/guardrails/check", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/guardrails/validate", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/filter", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/classify", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/validate", "POST", SurfaceClass.TOOLS, {"input": "test"}),
    ("/policies", "GET", SurfaceClass.TOOLS, None),
    # ── ADMIN / CONFIG / SCHEMA DISCOVERY ──────────────────────────────
    ("/admin", "GET", SurfaceClass.ADMIN, None),
    ("/admin/config", "GET", SurfaceClass.ADMIN, None),
    ("/config", "GET", SurfaceClass.ADMIN, None),
    ("/settings", "GET", SurfaceClass.ADMIN, None),
    ("/v1/admin", "GET", SurfaceClass.ADMIN, None),
    ("/internal/config", "GET", SurfaceClass.ADMIN, None),
    # Schema / docs
    ("/openapi.json", "GET", SurfaceClass.ADMIN, None),
    ("/swagger.json", "GET", SurfaceClass.ADMIN, None),
    ("/docs", "GET", SurfaceClass.ADMIN, None),
    ("/redoc", "GET", SurfaceClass.ADMIN, None),
    ("/api-docs", "GET", SurfaceClass.ADMIN, None),
    ("/.well-known/openapi.json", "GET", SurfaceClass.ADMIN, None),
    ("/schema", "GET", SurfaceClass.ADMIN, None),
    ("/graphql", "POST", SurfaceClass.ADMIN, {"query": "{__schema{types{name}}}"}),
    # Key / user management (LiteLLM, gateways)
    ("/key/info", "GET", SurfaceClass.ADMIN, None),
    ("/key/list", "GET", SurfaceClass.ADMIN, None),
    ("/user/info", "GET", SurfaceClass.ADMIN, None),
    ("/team/info", "GET", SurfaceClass.ADMIN, None),
    ("/model/info", "GET", SurfaceClass.ADMIN, None),
    # Batch / async jobs
    ("/v1/batch", "GET", SurfaceClass.ADMIN, None),
    ("/jobs", "GET", SurfaceClass.ADMIN, None),
    ("/tasks", "GET", SurfaceClass.ADMIN, None),
    ("/queue", "GET", SurfaceClass.ADMIN, None),
    # Well-known discovery
    ("/.well-known/ai-plugin.json", "GET", SurfaceClass.ADMIN, None),
    ("/.well-known/ready", "GET", SurfaceClass.HEALTH, None),      # Weaviate
    ("/.well-known/live", "GET", SurfaceClass.HEALTH, None),       # Weaviate
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
        default_headers: dict[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"EndpointProber base_url must be http(s): {base_url}")
        self._allowed_host = parsed.netloc
        self.timeout_seconds = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._transport = transport
        self._default_headers = default_headers or {}

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
                resp = await client.request(method, url, json=body, headers=self._default_headers)
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
