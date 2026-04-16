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
import json as _json
import logging
import re
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
    ("/v2/health/live", "GET", SurfaceClass.HEALTH, None),  # KServe V2
    ("/v2/health/ready", "GET", SurfaceClass.HEALTH, None),  # KServe V2
    ("/health/readiness", "GET", SurfaceClass.HEALTH, None),  # LiteLLM
    ("/health/liveliness", "GET", SurfaceClass.HEALTH, None),  # LiteLLM
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
    (
        "/v1/chat/completions",
        "POST",
        SurfaceClass.CHAT,
        {"model": "probe", "messages": [{"role": "user", "content": "hello"}]},
    ),
    ("/v1/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "prompt": "hello"}),
    ("/v1/messages", "POST", SurfaceClass.CHAT, {"model": "probe", "messages": [{"role": "user", "content": "hello"}]}),
    (
        "/chat/completions",
        "POST",
        SurfaceClass.CHAT,
        {"model": "probe", "messages": [{"role": "user", "content": "hello"}]},
    ),
    ("/completions", "POST", SurfaceClass.CHAT, {"model": "probe", "prompt": "hello"}),
    ("/v1/responses", "POST", SurfaceClass.CHAT, {"model": "probe", "input": "hello"}),
    # Gateway / proxy prefixes
    (
        "/proxy/chat/completions",
        "POST",
        SurfaceClass.CHAT,
        {"model": "probe", "messages": [{"role": "user", "content": "hello"}]},
    ),
    (
        "/api/v1/chat/completions",
        "POST",
        SurfaceClass.CHAT,
        {"model": "probe", "messages": [{"role": "user", "content": "hello"}]},
    ),
    # Inference servers (vLLM, TGI, Ollama)
    ("/generate", "POST", SurfaceClass.CHAT, {"prompt": "hello"}),
    ("/generate_stream", "POST", SurfaceClass.CHAT, {"prompt": "hello"}),
    ("/infer", "POST", SurfaceClass.CHAT, {"prompt": "hello"}),
    ("/predict", "POST", SurfaceClass.CHAT, {"instances": [{"input": "hello"}]}),
    ("/api/generate", "POST", SurfaceClass.CHAT, {"model": "probe", "prompt": "hello"}),
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
    ("/api/tags", "GET", SurfaceClass.TOOLS, None),  # Ollama
    ("/api/ps", "GET", SurfaceClass.TOOLS, None),  # Ollama running models
    ("/input_schema", "GET", SurfaceClass.TOOLS, None),  # LangServe
    ("/output_schema", "GET", SurfaceClass.TOOLS, None),  # LangServe
    ("/kernel/plugins", "GET", SurfaceClass.TOOLS, None),  # Semantic Kernel
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
    (
        "/mcp",
        "POST",
        SurfaceClass.TOOL_CALL,
        {"jsonrpc": "2.0", "method": "initialize", "params": {"capabilities": {}}, "id": 1},
    ),
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
    ("/spend/logs", "GET", SurfaceClass.EXFILTRATION, None),  # LiteLLM
    ("/global/spend", "GET", SurfaceClass.EXFILTRATION, None),  # LiteLLM
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
    ("/.well-known/ready", "GET", SurfaceClass.HEALTH, None),  # Weaviate
    ("/.well-known/live", "GET", SurfaceClass.HEALTH, None),  # Weaviate
]

# Keywords used to classify dynamically discovered paths into surface classes
_SURFACE_KEYWORDS: list[tuple[re.Pattern[str], SurfaceClass]] = [
    (re.compile(r"chat|message|conversation|ask|query|triage|review|assess", re.I), SurfaceClass.CHAT),
    (re.compile(r"memory|context|session|history|document|upload|knowledge|rag", re.I), SurfaceClass.MEMORY),
    (re.compile(r"agent|execute|orchestrat|task|internal", re.I), SurfaceClass.IDENTITY),
    (re.compile(r"\btools?\b|\bfunctions?\b|\bplugins?\b|\bactions?\b|\bskills?\b", re.I), SurfaceClass.TOOLS),
    (re.compile(r"pay|transfer|transaction|charge|financial|initiate|confirm", re.I), SurfaceClass.PAYMENT),
    (re.compile(r"audit|\blogs?\b|exfil|metric|\bstats?\b|debug|spend", re.I), SurfaceClass.EXFILTRATION),
    (re.compile(r"admin|config|setting|internal|secret", re.I), SurfaceClass.ADMIN),
    (re.compile(r"health|ping|status|ready|live", re.I), SurfaceClass.HEALTH),
]

# Body templates for POST probes against dynamically discovered endpoints
_SURFACE_BODIES: dict[SurfaceClass, dict[str, Any] | None] = {
    SurfaceClass.CHAT: {"message": "hello"},
    SurfaceClass.MEMORY: {"query": "probe"},
    SurfaceClass.IDENTITY: {"message": "probe"},
    SurfaceClass.TOOLS: {"name": "noop", "arguments": {}},
    SurfaceClass.PAYMENT: {"amount": 0},
    SurfaceClass.EXFILTRATION: None,
    SurfaceClass.ADMIN: None,
    SurfaceClass.HEALTH: None,
}


def _parse_ndjson_to_text(raw: str) -> str:
    """Parse newline-delimited JSON (NDJSON) into a single coherent text string.

    Many AI inference servers (Ollama, vLLM, TGI, LiteLLM) stream responses as
    NDJSON — one JSON object per line, each containing a token or chunk::

        {"response": "Hello"}
        {"response": " world"}
        {"done": true}

    We concatenate the text content fields from each line.  This is the T3
    transport-layer gap: chunked transfer encoding where the *application*
    framing is NDJSON rather than SSE.
    """
    parts: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = _json.loads(line)
            if not isinstance(obj, dict):
                continue
            # Skip terminal frames
            if obj.get("done") is True and not any(
                obj.get(k) for k in ("response", "content", "text", "token", "message", "output")
            ):
                continue
            # OpenAI-style: choices[0].delta.content
            choices = obj.get("choices")
            if isinstance(choices, list) and choices:
                delta = choices[0]
                if isinstance(delta, dict):
                    delta_inner = delta.get("delta", delta)
                    if isinstance(delta_inner, dict):
                        chunk = delta_inner.get("content") or delta_inner.get("text") or ""
                        if chunk:
                            parts.append(str(chunk))
                            continue
            # Generic fields: response (Ollama), content, text, token, message
            for key in ("response", "content", "text", "token", "message", "output"):
                val = obj.get(key)
                if val and isinstance(val, str):
                    parts.append(val)
                    break
        except (ValueError, TypeError, KeyError):
            # Not JSON — skip non-JSON lines in NDJSON streams
            continue
    return "".join(parts) if parts else raw


def _parse_sse_to_text(raw: str) -> str:
    """Parse a ``text/event-stream`` body into a single coherent text string.

    SSE frames look like::

        data: {"type": "token", "content": "Hello"}

        data: {"type": "token", "content": " world"}

        data: [DONE]

    We concatenate the ``content`` (or ``text`` / ``delta``) values from each
    JSON ``data:`` frame.  If frames are not JSON we fall back to concatenating
    the raw ``data:`` values (stripping the prefix).
    """
    parts: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:") :].strip()
        if not payload or payload == "[DONE]":
            continue
        # Try JSON first — most AI endpoints send structured SSE frames
        try:
            obj = _json.loads(payload)
            if isinstance(obj, dict):
                # OpenAI-style: choices[0].delta.content
                choices = obj.get("choices")
                if isinstance(choices, list) and choices:
                    delta = choices[0]
                    if isinstance(delta, dict):
                        delta_inner = delta.get("delta", delta)
                        if isinstance(delta_inner, dict):
                            chunk = delta_inner.get("content") or delta_inner.get("text") or ""
                            if chunk:
                                parts.append(str(chunk))
                                continue
                # Generic: content / text / token / message field
                for key in ("content", "text", "token", "message", "response"):
                    val = obj.get(key)
                    if val and isinstance(val, str):
                        parts.append(val)
                        break
                else:
                    # Nested under "data" key
                    inner = obj.get("data")
                    if isinstance(inner, dict):
                        for key in ("content", "text", "token", "message"):
                            val = inner.get(key)
                            if val and isinstance(val, str):
                                parts.append(val)
                                break
        except (ValueError, TypeError, KeyError):
            # Not JSON — use raw data value
            parts.append(payload)
    return "".join(parts) if parts else raw[:5000]


def build_body_for_format(
    payload: str,
    fmt: str,
    surface: str = "user_input",
    *,
    prompt_field: str = "message",
    extra_fields: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a request body in the format the target expects (T6).

    Parameters
    ----------
    payload : str
        The attack payload text.
    fmt : str
        One of ``"message"``, ``"openai"``, ``"prompt"``, ``"input"``,
        ``"formdata"``, or ``"custom"``.
    surface : str
        Surface label for context metadata.
    prompt_field : str
        The field name that carries the user prompt (default ``"message"``).
        Used by ``"formdata"`` and ``"custom"`` formats.
    extra_fields : dict[str, str] | None
        Additional static fields to include (e.g. ``{"defender": "baseline"}``
        for Gandalf).  Used by ``"formdata"`` and ``"custom"`` formats.
    """
    if fmt == "openai":
        return {"model": "probe", "messages": [{"role": "user", "content": payload}]}
    if fmt == "prompt":
        return {"prompt": payload}
    if fmt == "input":
        return {"input": payload}
    if fmt in ("formdata", "custom"):
        # Build a flat dict — caller decides whether to send as JSON or FormData
        body: dict[str, Any] = {prompt_field: payload}
        if extra_fields:
            body.update(extra_fields)
        return body
    # Default: generic message format using the configured prompt_field
    if prompt_field != "message":
        body = {prompt_field: payload}
        if extra_fields:
            body.update(extra_fields)
        return body
    body = {"message": payload, "context": {"source": surface}}
    if extra_fields:
        body.update(extra_fields)
    return body


def build_multipart_fields(payload: str, field_name: str = "file") -> dict[str, Any]:
    """Build multipart/form-data fields for T4 transport (file upload surfaces).

    Parameters
    ----------
    payload : str
        The attack payload text to embed in the uploaded content.
    field_name : str
        The form field name for the file upload (commonly ``file``, ``document``,
        ``upload``, ``attachment``).

    Returns a dict suitable for httpx ``files=`` parameter::

        {"file": ("payload.txt", payload_bytes, "text/plain")}
    """
    return {field_name: ("payload.txt", payload.encode("utf-8"), "text/plain")}


def _is_html_catchall(content_type: str, body: str) -> bool:
    """Return True if the response looks like an HTML catch-all (SPA shell, error page).

    SPA targets return the same HTML for every route — a React/Vue/Angular shell.
    Agents must not treat this as an AI response; divergence would always be 0.
    """
    if "text/html" not in content_type.lower():
        return False
    trimmed = body.lstrip()[:500].lower()
    return trimmed.startswith("<!doctype") or trimmed.startswith("<html") or "<head>" in trimmed


def is_ai_response(content_type: str, body: str) -> bool:
    """Return True if the response likely comes from an AI agent (not a static page).

    Returns False for HTML catch-all responses (SPAs), empty bodies, and
    binary content types.  Returns True for JSON, SSE, plain text with
    meaningful content, and any other content that could be AI output.
    """
    if not body or not body.strip():
        return False
    ct = content_type.lower()
    # Binary / media — never AI
    if any(t in ct for t in ("image/", "audio/", "video/", "font/", "application/octet-stream")):
        return False
    # HTML catch-all — SPA shell, not AI
    if _is_html_catchall(content_type, body):
        return False
    return True


class DiscoveredEndpoint(BaseModel):
    """A single endpoint discovered by SURVEY."""

    base_url: str
    path: str
    method: str
    surface_class: SurfaceClass
    status_code: int | None = None
    response_text_snippet: str = Field(default="", description="First 1KB of response body")
    response_keys: list[str] = Field(default_factory=list, description="Top-level JSON keys")
    content_type: str = Field(default="", description="Response Content-Type header (T5)")
    is_html_catchall: bool = Field(default=False, description="True when response is an HTML SPA shell (T1)")
    request_format: str = Field(
        default="message",
        description="Body format that got a successful response: message, openai, prompt, form (T6)",
    )
    error: str | None = None

    def is_live(self) -> bool:
        """A discovery counts if the server responded with something useful.

        Rejects: 404s, transport errors, and HTML catch-all responses (SPA shells
        that return 200 for every route but contain no AI content).
        """
        if self.error is not None:
            return False
        if self.status_code is None:
            return False
        if self.status_code == 404:
            return False
        # T1: HTML catch-all filter — SPA shells are not live AI endpoints
        if self.is_html_catchall:
            return False
        return True


class SurveyReport(BaseModel):
    """Aggregated survey of one target's attack surface."""

    target_base_url: str
    discovered: list[DiscoveredEndpoint] = Field(default_factory=list)
    by_surface: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Map of surface_class -> list of paths discovered",
    )
    auth_failure_count: int = Field(
        default=0,
        description="Number of probes that returned 401/403 — indicates missing or invalid auth",
    )

    @property
    def auth_required(self) -> bool:
        """True when the majority of probes were rejected with 401/403.

        This is a strong signal that the target requires authentication
        and the scan is running without valid credentials.
        """
        responded = [d for d in self.discovered if d.status_code is not None]
        if not responded:
            return False
        return self.auth_failure_count > len(responded) * 0.5

    def endpoints_for(self, surface: SurfaceClass, *, include_auth_rejected: bool = False) -> list[DiscoveredEndpoint]:
        """Return discovered endpoints for a surface class.

        By default, filters out 401/403 responses (they indicate the endpoint
        exists but requires auth we don't have).  When *include_auth_rejected*
        is True, 403 responses are kept — this is used by the identity_spoof
        agent which specifically probes endpoints that reject unauthenticated
        callers to see if spoofed headers bypass the check.
        """
        results: list[DiscoveredEndpoint] = []
        for d in self.discovered:
            if d.surface_class != surface or not d.is_live():
                continue
            if d.status_code in (401, 403) and not include_auth_rejected:
                continue
            results.append(d)
        return results

    def has_surface(self, surface: SurfaceClass, *, include_auth_rejected: bool = False) -> bool:
        return any(
            d.surface_class == surface and d.is_live() and (include_auth_rejected or d.status_code not in (401, 403))
            for d in self.discovered
        )


def _classify_path(path: str) -> SurfaceClass:
    """Classify a dynamically discovered path into a surface class by keyword matching."""
    for pattern, surface in _SURFACE_KEYWORDS:
        if pattern.search(path):
            return surface
    return SurfaceClass.UNKNOWN


def _infer_method(path: str, surface: SurfaceClass) -> str:
    """Infer the likely HTTP method for a discovered path."""
    # Surfaces that typically accept POST
    if surface in (SurfaceClass.CHAT, SurfaceClass.PAYMENT, SurfaceClass.TOOL_CALL):
        return "POST"
    # Surfaces that are typically GET
    if surface in (SurfaceClass.HEALTH, SurfaceClass.ADMIN, SurfaceClass.EXFILTRATION):
        return "GET"
    # Memory paths: uploads are POST, listings are GET
    if surface == SurfaceClass.MEMORY:
        if any(kw in path.lower() for kw in ("upload", "ingest", "index", "search")):
            return "POST"
        return "GET"
    # Identity: agent-message style endpoints are POST
    if surface == SurfaceClass.IDENTITY:
        return "POST"
    # Unknown — try GET first (safer)
    return "GET"


def _extract_paths_from_response(response_text: str, base_url: str) -> list[str]:
    """Extract API paths from a JSON or HTML response body.

    Looks for:
    - JSON values that look like relative paths (/foo/bar)
    - JSON values that are full URLs on the same host
    - href attributes in HTML
    """
    paths: set[str] = set()
    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc

    # Extract quoted strings that look like paths or URLs
    # Matches: "/agent/01/chat", "https://host/path", '/some/path'
    for match in re.finditer(r'["\'](/[a-zA-Z0-9_./-]+)["\']', response_text):
        candidate = match.group(1)
        # Skip static assets, images, etc.
        if not re.search(r"\.(css|js|png|jpg|gif|ico|svg|woff|ttf|map)$", candidate, re.I):
            paths.add(candidate)

    # Extract full URLs on the same host
    for match in re.finditer(r'https?://([^"\s<>]+)', response_text):
        full = match.group(0)
        parsed = urlparse(full)
        if parsed.netloc == base_host and parsed.path and parsed.path != "/":
            paths.add(parsed.path)

    # Extract href/src from HTML
    for match in re.finditer(r'href=["\']([^"\'>]+)["\']', response_text, re.I):
        href = match.group(1)
        if href.startswith("/") and not re.search(r"\.(css|js|png|jpg|gif|ico|svg)$", href, re.I):
            paths.add(href)

    return sorted(paths)


# ---------------------------------------------------------------------------
# T4: SPA Endpoint Discovery — JS bundle parsing
# ---------------------------------------------------------------------------

# Regex patterns to extract API endpoints from JavaScript bundles.
_JS_API_PATTERNS: list[re.Pattern[str]] = [
    # fetch("/api/...") or fetch('/api/...')
    re.compile(r'fetch\(["\'](/[a-zA-Z0-9_./-]+)["\']'),
    # axios.get/post/put/delete("/api/...")
    re.compile(r'axios\.(?:get|post|put|delete|patch)\(["\'](/[a-zA-Z0-9_./-]+)["\']'),
    # Quoted string literals that look like API paths: "/api/...", "/v1/...", "/v2/..."
    re.compile(r'["\'](/(?:api|v[0-9]+)/[a-zA-Z0-9_./-]+)["\']'),
    # baseURL: "/api" or baseUrl = "/api"
    re.compile(r'base[Uu][Rr][Ll]["\']?\s*[:=]\s*["\'](/[a-zA-Z0-9_./-]+)["\']'),
    # Generic endpoint-looking paths in template strings: `/api/users/${id}`
    re.compile(r"`(/(?:api|v[0-9]+)/[a-zA-Z0-9_./${}/-]+)`"),
]

# Maximum bundles to fetch per SPA root
_SPA_MAX_BUNDLES = 5
# Maximum size per bundle (bytes)
_SPA_MAX_BUNDLE_SIZE = 500_000


def _extract_script_srcs(html: str) -> list[str]:
    """Extract <script src="..."> values from HTML."""
    return re.findall(r'<script[^>]+src=["\']([^"\'>]+\.js)[^"\'>]*["\']', html, re.I)


def _extract_api_paths_from_js(js_text: str) -> set[str]:
    """Extract API endpoint paths from JavaScript source text."""
    paths: set[str] = set()
    for pattern in _JS_API_PATTERNS:
        for match in pattern.finditer(js_text):
            candidate = match.group(1)
            # Skip obvious non-API paths
            if re.search(r"\.(css|js|png|jpg|gif|ico|svg|woff|ttf|map)$", candidate, re.I):
                continue
            # Normalise template-string interpolations: /api/users/${id} → /api/users
            cleaned = re.sub(r"/\$\{[^}]*\}", "", candidate)
            if cleaned and cleaned.startswith("/"):
                paths.add(cleaned)
    return paths


async def discover_spa_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
    html: str,
) -> list[str]:
    """T4: Fetch JS bundles referenced in *html* and extract API endpoints.

    Caps at *_SPA_MAX_BUNDLES* bundles and *_SPA_MAX_BUNDLE_SIZE* bytes each
    to avoid downloading massive SPA assets.

    Returns a sorted, de-duplicated list of discovered API paths.
    """
    script_srcs = _extract_script_srcs(html)
    if not script_srcs:
        return []

    # Resolve relative script URLs against the base
    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc
    resolved: list[str] = []
    for src in script_srcs[:_SPA_MAX_BUNDLES]:
        if src.startswith(("http://", "https://")):
            # SSRF guard: only fetch scripts from the same host to prevent
            # auth token leakage to attacker-controlled URLs.
            parsed_src = urlparse(src)
            if parsed_src.netloc != base_host:
                logger.debug("T4: skipping external script src %s (host mismatch)", src)
                continue
            resolved.append(src)
        elif src.startswith("/"):
            resolved.append(f"{base_url.rstrip('/')}{src}")
        else:
            resolved.append(f"{base_url.rstrip('/')}/{src}")

    all_paths: set[str] = set()
    for url in resolved:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                continue
            # Respect size cap
            text = resp.text[:_SPA_MAX_BUNDLE_SIZE]
            found = _extract_api_paths_from_js(text)
            all_paths.update(found)
            logger.debug("T4: %s → %d API paths from %s", base_url, len(found), url)
        except Exception as exc:
            logger.debug("T4: failed to fetch JS bundle %s: %s", url, type(exc).__name__)

    if all_paths:
        logger.info(
            "T4: SPA discovery found %d API endpoints from %d JS bundles at %s",
            len(all_paths),
            len(resolved),
            base_url,
        )
    return sorted(all_paths)


class EndpointProber:
    """Probes a single base URL for common AI agent endpoint conventions.

    SSRF-bound to one base URL — all probes resolve relative paths against
    that base. Per-probe paths cannot redirect to a different host.

    Autonomous discovery: after the initial probe sweep, examines all live
    responses for embedded paths/URLs and probes those too. This lets ARGUS
    find non-standard endpoints (like /agent/01/chat) without needing hints.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 5.0,
        max_concurrent: int = 8,
        transport: httpx.AsyncBaseTransport | None = None,
        auth_token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"EndpointProber base_url must be http(s): {base_url}")
        self._allowed_host = parsed.netloc
        self.timeout_seconds = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._transport = transport
        self._auth_token = auth_token

    async def probe_all(self) -> SurveyReport:
        """Probe the full default path set, then discover and probe new paths.

        Two-phase approach:
        1. Probe the static seed set (conventional AI agent paths)
        2. Extract paths from all live responses (JSON bodies, HTML links)
           and probe any newly discovered paths — autonomous discovery.

        Returns a SurveyReport with all discoveries (live and dead).
        """
        kwargs: dict[str, Any] = {
            "timeout": self.timeout_seconds,
            "event_hooks": {"request": [], "response": []},
            "follow_redirects": False,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        if self._auth_token:
            kwargs["headers"] = {"Authorization": f"Bearer {self._auth_token}"}

        async with httpx.AsyncClient(**kwargs) as client:
            # ── Phase 1: probe the root first, then the static seed set ──
            root_discovery = await self._probe_one(
                client,
                "/",
                "GET",
                SurfaceClass.UNKNOWN,
                None,
            )
            tasks = [
                self._probe_one(client, path, method, surface, body) for path, method, surface, body in _PROBE_PATHS
            ]
            seed_discoveries = await asyncio.gather(*tasks)
            all_discoveries = [root_discovery, *seed_discoveries]

            # ── Phase 2: autonomous discovery from response bodies ──
            probed_paths = {p for p, _, _, _ in _PROBE_PATHS} | {"/"}
            new_paths: list[str] = []
            for d in all_discoveries:
                if d.response_text_snippet and d.status_code is not None and d.status_code < 500:
                    extracted = _extract_paths_from_response(
                        d.response_text_snippet,
                        self.base_url,
                    )
                    for p in extracted:
                        if p not in probed_paths:
                            probed_paths.add(p)
                            new_paths.append(p)

            # ── Phase 2b (T4): SPA JS bundle discovery ──
            # If root returned HTML with <script> tags, fetch the JS bundles
            # and extract API endpoints from them.
            if root_discovery.is_html_catchall and root_discovery.response_text_snippet:
                spa_paths = await discover_spa_endpoints(
                    client,
                    self.base_url,
                    root_discovery.response_text_snippet,
                )
                for p in spa_paths:
                    if p not in probed_paths:
                        probed_paths.add(p)
                        new_paths.append(p)

            # Cap at 50 discovered paths to avoid request explosion on verbose targets
            if len(new_paths) > 50:
                logger.warning(
                    "SURVEY %s — discovered %d paths, capping at 50",
                    self.base_url,
                    len(new_paths),
                )
                new_paths = new_paths[:50]

            if new_paths:
                logger.info(
                    "SURVEY %s — discovered %d new paths from response bodies, probing...",
                    self.base_url,
                    len(new_paths),
                )
                discovery_tasks = []
                for p in new_paths:
                    surface = _classify_path(p)
                    method = _infer_method(p, surface)
                    body = _SURFACE_BODIES.get(surface) if method == "POST" else None
                    discovery_tasks.append(self._probe_one(client, p, method, surface, body))
                    # Also try the other method — a chat endpoint might accept
                    # both GET (health) and POST (chat). Only add if we haven't
                    # already queued it.
                    alt_method = "POST" if method == "GET" else "GET"
                    alt_body = _SURFACE_BODIES.get(surface) if alt_method == "POST" else None
                    discovery_tasks.append(self._probe_one(client, p, alt_method, surface, alt_body))
                extra_discoveries = await asyncio.gather(*discovery_tasks)
                all_discoveries.extend(extra_discoveries)

        # ── Build report ──
        auth_failures = 0
        report = SurveyReport(target_base_url=self.base_url)
        for d in all_discoveries:
            report.discovered.append(d)
            if d.status_code in (401, 403):
                auth_failures += 1
            elif d.is_live():
                report.by_surface.setdefault(d.surface_class.value, []).append(d.path)

        report.auth_failure_count = auth_failures

        live_count = sum(1 for d in all_discoveries if d.is_live())
        logger.info(
            "SURVEY %s — %d/%d endpoints live across %d surface classes",
            self.base_url,
            live_count,
            len(all_discoveries),
            len(report.by_surface),
        )
        if report.auth_required:
            logger.warning(
                "SURVEY %s — %d/%d probes returned 401/403; target likely requires "
                "authentication. Set agent_api_key in the scan request to authenticate.",
                self.base_url,
                auth_failures,
                len(all_discoveries),
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

        # Use a larger snippet for the root probe to capture full endpoint indexes
        max_snippet = 8192 if path == "/" else 1024
        raw_text = resp.text
        ct = resp.headers.get("content-type", "")

        # T2: SSE — reassemble streamed text/event-stream frames into
        # a single coherent response string that agents can evaluate.
        if "text/event-stream" in ct:
            snippet = _parse_sse_to_text(raw_text)[:max_snippet]
        # T3: NDJSON — reassemble newline-delimited JSON streams
        # (Ollama, vLLM, TGI, LiteLLM chunked streaming)
        elif "application/x-ndjson" in ct or "application/jsonlines" in ct:
            snippet = _parse_ndjson_to_text(raw_text)[:max_snippet]
        elif ct == "" and raw_text.lstrip().startswith("{") and "\n{" in raw_text:
            # Heuristic: no content-type but body looks like NDJSON
            snippet = _parse_ndjson_to_text(raw_text)[:max_snippet]
        else:
            snippet = raw_text[:max_snippet]

        keys: list[str] = []
        try:
            data = resp.json()
            if isinstance(data, dict):
                keys = list(data.keys())[:20]
        except Exception as exc:
            logger.debug("Non-JSON response from %s: %s", url, type(exc).__name__)

        html_catch = _is_html_catchall(ct, snippet)

        # T6: Record the body format that succeeded so agents can reuse it
        fmt = "message"  # default
        if body is not None:
            if "messages" in body:
                fmt = "openai"
            elif "prompt" in body:
                fmt = "prompt"
            elif "input" in body:
                fmt = "input"

        return DiscoveredEndpoint(
            base_url=self.base_url,
            path=path,
            method=method,
            surface_class=surface,
            status_code=resp.status_code,
            response_text_snippet=snippet,
            response_keys=keys,
            content_type=ct,
            is_html_catchall=html_catch,
            request_format=fmt,
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
