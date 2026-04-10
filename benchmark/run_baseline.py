"""ARGUS Gauntlet — Baseline Score Runner.

Runs ARGUS Phase 1 agents against the deployed benchmark scenarios
and produces a baseline score report.

Usage:
    1. Start scenarios:  docker compose -f benchmark/docker-compose.yml up -d
    2. Run baseline:     python benchmark/run_baseline.py
    3. View score:       cat benchmark/baseline-score.json
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Make ARGUS importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from argus.agents import PromptInjectionHunter, SupplyChainAgent, ToolPoisoningAgent
from argus.models.agents import AgentType, TargetConfig
from argus.orchestrator.engine import Orchestrator

BENCHMARK_DIR = Path(__file__).parent
FINDINGS_OUT = BENCHMARK_DIR / "baseline-findings.json"
SCORE_OUT = BENCHMARK_DIR / "baseline-score.json"


async def run_benchmark() -> dict:
    """Run all Phase 1 agents against the deployed benchmark scenarios.

    Targets all 7 official benchmark scenarios. Phase 1 agents will only
    detect vulnerabilities in scenarios their techniques cover (01, 05, 06).
    Scenarios 02-04 and 07 will score 0 honestly until Phase 2/3 ships.
    """
    print("=" * 70)
    print("  ARGUS Gauntlet — Baseline Run")
    print("=" * 70)
    print()

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
        non_destructive=True,
        max_requests_per_minute=120,
    )

    orchestrator = Orchestrator()
    orchestrator.register_agent(AgentType.PROMPT_INJECTION, PromptInjectionHunter)
    orchestrator.register_agent(AgentType.TOOL_POISONING, ToolPoisoningAgent)
    orchestrator.register_agent(AgentType.SUPPLY_CHAIN, SupplyChainAgent)

    print(f"Target: {target.name}")
    print(f"MCP URLs: {target.mcp_server_urls}")
    print(f"Agent endpoint: {target.agent_endpoint}")
    print()
    print("Deploying 3 agents simultaneously...")
    print()

    result = await orchestrator.run_scan(target=target, timeout=300.0)

    summary = result.summary()
    print(f"Scan complete in {summary['duration_seconds']:.1f}s")
    print(f"Findings: {summary['total_findings']} total, {summary['validated_findings']} validated")
    print(f"Compound paths: {summary['compound_attack_paths']}")
    print()

    # Build findings document for scorer
    findings_doc = {
        "scan_id": result.scan_id,
        "target": target.name,
        "findings": [f.model_dump() for f in result.findings],
        "compound_attack_paths": [p.model_dump() for p in result.compound_paths],
    }

    FINDINGS_OUT.write_text(json.dumps(findings_doc, indent=2, default=str))
    print(f"Findings written to: {FINDINGS_OUT}")

    return findings_doc


def score_findings(findings_doc: dict) -> dict:
    """Score the findings document using the rubric."""
    sys.path.insert(0, str(BENCHMARK_DIR / "scoring"))
    from score import load_rubric, render_text_report, score_all

    rubric = load_rubric()
    report = score_all(rubric, findings_doc)

    SCORE_OUT.write_text(json.dumps(report, indent=2))
    print()
    print(render_text_report(report))
    print(f"Score report written to: {SCORE_OUT}")

    return report


def main() -> int:
    try:
        findings_doc = asyncio.run(run_benchmark())
    except Exception as exc:
        print(f"\nERROR: Benchmark run failed: {exc}", file=sys.stderr)
        print("Make sure scenarios are running:")
        print("  docker compose -f benchmark/docker-compose.yml up -d")
        return 1

    score_findings(findings_doc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
