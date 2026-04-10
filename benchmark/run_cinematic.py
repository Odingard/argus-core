"""ARGUS Gauntlet — Cinematic Live Demo.

Runs the ARGUS attack swarm against the benchmark with the cinematic
retro-terminal dashboard. Designed for screen recording and demo capture.

Usage:
    1. Start scenarios:  docker compose -f benchmark/docker-compose.yml up -d
    2. Run cinematic:    python benchmark/run_cinematic.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Make ARGUS importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from argus.agents import (
    IdentitySpoofAgent,
    MemoryPoisoningAgent,
    PromptInjectionHunter,
    SupplyChainAgent,
    ToolPoisoningAgent,
)
from argus.models.agents import AgentType, TargetConfig
from argus.orchestrator.engine import Orchestrator
from argus.ui import CinematicDashboard


async def main() -> int:
    target = TargetConfig(
        name="ARGUS Gauntlet",
        mcp_server_urls=[
            "http://localhost:8001",  # Scenario 01 — Tool Poisoning MCP
            "http://localhost:8003",  # Scenario 02 — Memory Poisoning
            "http://localhost:8005",  # Scenario 03 — Identity Spoof
            "http://localhost:8007",  # Scenario 04 — Privilege Chain
            "http://localhost:8009",  # Scenario 05 — Injection Gauntlet
            "http://localhost:8011",  # Scenario 06 — Supply Chain
            "http://localhost:8013",  # Scenario 07 — Race Condition
        ],
        agent_endpoint="http://localhost:8002/chat",  # Scenario 01 — Target agent
        non_destructive=False,  # benchmark scenarios are throwaway docker — aggressive probes OK
        max_requests_per_minute=120,
    )

    orchestrator = Orchestrator()
    orchestrator.register_agent(AgentType.PROMPT_INJECTION, PromptInjectionHunter)
    orchestrator.register_agent(AgentType.TOOL_POISONING, ToolPoisoningAgent)
    orchestrator.register_agent(AgentType.SUPPLY_CHAIN, SupplyChainAgent)
    orchestrator.register_agent(AgentType.MEMORY_POISONING, MemoryPoisoningAgent)
    orchestrator.register_agent(AgentType.IDENTITY_SPOOF, IdentitySpoofAgent)

    dashboard = CinematicDashboard()
    result = await dashboard.run(
        orchestrator,
        target,
        timeout=300.0,
        demo_pace_seconds=0.5,
    )

    # Score and print summary
    sys.path.insert(0, str(Path(__file__).parent / "scoring"))
    from score import load_rubric, render_text_report, score_all

    findings_doc = {
        "scan_id": result.scan_id,
        "target": target.name,
        "findings": [f.model_dump() for f in result.findings],
        "compound_attack_paths": [p.model_dump() for p in result.compound_paths],
    }

    rubric = load_rubric()
    report = score_all(rubric, findings_doc)
    print()
    print(render_text_report(report))

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
