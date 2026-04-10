"""Agent configuration and result models."""

from __future__ import annotations

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
    CORRELATION = "correlation"


class AgentStatus(str, Enum):
    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


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
