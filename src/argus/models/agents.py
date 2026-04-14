"""Agent configuration and result models."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentType(str, Enum):
    PROMPT_INJECTION = "prompt_injection_hunter"
    TOOL_POISONING = "tool_poisoning"
    MEMORY_POISONING = "memory_poisoning"
    IDENTITY_SPOOF = "identity_spoof"
    CONTEXT_WINDOW = "context_window"
    CROSS_AGENT_EXFIL = "cross_agent_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RACE_CONDITION = "race_condition"
    SUPPLY_CHAIN = "supply_chain"
    MODEL_EXTRACTION = "model_extraction"
    PERSONA_HIJACKING = "persona_hijacking"
    MEMORY_BOUNDARY_COLLAPSE = "memory_boundary_collapse"
    MCP_SCANNER = "mcp_scanner"
    CORRELATION = "correlation"


class AgentStatus(str, Enum):
    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"  # target returned 401/403 on all probes — auth missing or invalid


class AgentConfig(BaseModel):
    """Configuration for deploying an attack agent."""

    agent_type: AgentType
    instance_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str

    # Target
    target: TargetConfig

    # Execution
    timeout_seconds: int = 300
    max_techniques: int | None = None
    llm_provider: str = "anthropic"
    llm_model: str = "claude-sonnet-4-20250514"

    # Demo pacing — artificial delay between techniques (seconds).
    # Default 0 = production speed. Set higher for live demos so panels visibly update.
    demo_pace_seconds: float = 0.0

    # Corpus
    corpus_tags: list[str] = Field(default_factory=list)

    # Agent-specific params
    params: dict[str, Any] = Field(default_factory=dict)


class TargetConfig(BaseModel):
    """Configuration describing the target AI system under test."""

    name: str
    description: str | None = None

    # MCP targets
    mcp_server_urls: list[str] = Field(default_factory=list)
    mcp_server_configs: list[dict[str, Any]] = Field(default_factory=list)

    # Agent targets
    agent_endpoint: str | None = None
    agent_api_key: str | None = None

    # Multi-agent targets
    agent_endpoints: list[str] = Field(default_factory=list)

    # Context
    system_prompt: str | None = None
    available_tools: list[dict[str, Any]] = Field(default_factory=list)

    # Constraints
    non_destructive: bool = True
    max_requests_per_minute: int = 60


# Fix forward reference
AgentConfig.model_rebuild()


class AgentResult(BaseModel):
    """Result from a completed attack agent run."""

    agent_type: AgentType
    instance_id: str
    scan_id: str
    status: AgentStatus

    # Timing
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float | None = None

    # Findings
    findings: list[str] = Field(default_factory=list, description="Finding IDs")
    findings_count: int = 0
    validated_count: int = 0

    # Execution stats
    techniques_attempted: int = 0
    techniques_succeeded: int = 0
    requests_made: int = 0

    # Errors
    errors: list[str] = Field(default_factory=list)

    # Signals sent to correlation agent
    signals_emitted: int = 0


class ScanIntelligence:
    """Shared intelligence context for inter-agent finding chaining.

    Phase 1 agents (model_extraction) write extracted info here.
    Phase 2 agents (prompt_injection, etc.) read it to craft targeted attacks.

    Thread-safe: uses asyncio.Lock for concurrent writes.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # Extracted model identity (e.g. "claude-3", "gpt-4", "llama-3")
        self.model_name: str | None = None
        # Fragments of the system prompt extracted by model_extraction
        self.system_prompt_fragments: list[str] = []
        # Tool names the target has access to
        self.tool_names: list[str] = []
        # Behavioral boundaries discovered (topics refused, actions forbidden)
        self.refusal_topics: list[str] = []
        # Raw extraction evidence for downstream agents
        self.extraction_evidence: list[dict[str, Any]] = []

    async def record_model_name(self, name: str) -> None:
        async with self._lock:
            self.model_name = name

    async def record_system_prompt_fragment(self, fragment: str) -> None:
        async with self._lock:
            if fragment not in self.system_prompt_fragments:
                self.system_prompt_fragments.append(fragment)

    async def record_tool_names(self, names: list[str]) -> None:
        async with self._lock:
            for n in names:
                if n not in self.tool_names:
                    self.tool_names.append(n)

    async def record_refusal(self, topic: str) -> None:
        async with self._lock:
            if topic not in self.refusal_topics:
                self.refusal_topics.append(topic)

    async def record_evidence(self, evidence: dict[str, Any]) -> None:
        async with self._lock:
            self.extraction_evidence.append(evidence)

    @property
    def has_intel(self) -> bool:
        """Return True if any intelligence has been collected."""
        return bool(self.model_name or self.system_prompt_fragments or self.tool_names or self.refusal_topics)

    def summary(self) -> str:
        """Human-readable summary of collected intelligence for LLM context."""
        parts: list[str] = []
        if self.model_name:
            parts.append(f"Model: {self.model_name}")
        if self.system_prompt_fragments:
            joined = " | ".join(f[:200] for f in self.system_prompt_fragments[:5])
            parts.append(f"System prompt fragments: {joined}")
        if self.tool_names:
            parts.append(f"Tools: {', '.join(self.tool_names[:20])}")
        if self.refusal_topics:
            parts.append(f"Refused topics: {', '.join(self.refusal_topics[:10])}")
        return "; ".join(parts) if parts else "No intelligence collected"
