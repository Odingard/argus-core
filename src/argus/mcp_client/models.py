"""MCP protocol models for ARGUS attack client."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class MCPToolParameter(BaseModel):
    """A parameter definition for an MCP tool."""
    name: str
    description: str | None = None
    type: str = "string"
    required: bool = False
    enum: list[str] | None = None
    default: Any | None = None


class MCPTool(BaseModel):
    """An MCP tool definition as seen by the attacker client."""
    name: str
    description: str | None = None
    parameters: list[MCPToolParameter] = Field(default_factory=list)
    input_schema: dict[str, Any] | None = None

    # Attack-relevant metadata
    raw_definition: dict[str, Any] | None = None
    hidden_content_detected: bool = False
    hidden_content: str | None = None


class MCPServerConfig(BaseModel):
    """Configuration for connecting to an MCP server under test."""
    name: str
    transport: str = "stdio"  # stdio, sse, streamable-http

    # stdio transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)

    # HTTP transports
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    # Auth
    api_key: str | None = None

    # Testing constraints
    timeout_seconds: int = 30
    max_concurrent_calls: int = 5


class MCPCallResult(BaseModel):
    """Result from calling an MCP tool."""
    tool_name: str
    success: bool
    result: Any | None = None
    error: str | None = None
    raw_response: dict[str, Any] | None = None
    duration_ms: float | None = None
