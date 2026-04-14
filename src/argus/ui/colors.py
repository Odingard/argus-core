"""Shared agent color map for all ARGUS terminal UIs (live dashboard, CLI, reports)."""

from __future__ import annotations

from argus.models.agents import AgentType

# Each agent gets a distinct Rich color for easy visual tracking in terminal output.
AGENT_COLORS: dict[AgentType, str] = {
    # Phase 1
    AgentType.PROMPT_INJECTION: "bright_red",
    AgentType.TOOL_POISONING: "bright_magenta",
    AgentType.SUPPLY_CHAIN: "bright_yellow",
    # Phase 2
    AgentType.MEMORY_POISONING: "bright_blue",
    AgentType.IDENTITY_SPOOF: "bright_cyan",
    # Phase 3
    AgentType.CONTEXT_WINDOW: "bright_green",
    AgentType.CROSS_AGENT_EXFIL: "red",
    AgentType.PRIVILEGE_ESCALATION: "magenta",
    AgentType.RACE_CONDITION: "yellow",
    # Phase 4
    AgentType.MODEL_EXTRACTION: "blue",
    # Phase 5
    AgentType.PERSONA_HIJACKING: "green",
    AgentType.MEMORY_BOUNDARY_COLLAPSE: "cyan",
    # MCP Scanner
    AgentType.MCP_SCANNER: "bright_yellow",
    # Correlation
    AgentType.CORRELATION: "bright_white",
}


def agent_color(agent_type: AgentType) -> str:
    """Return the Rich color string for the given agent type."""
    return AGENT_COLORS.get(agent_type, "white")


def agent_color_by_value(agent_value: str) -> str:
    """Return the Rich color string for an agent type given its string value."""
    for at in AgentType:
        if at.value == agent_value:
            return AGENT_COLORS.get(at, "white")
    return "white"
