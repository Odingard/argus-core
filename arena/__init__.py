"""ARGUS Arena — Intentionally Vulnerable AI Agent Targets.

A suite of 12 Dockerized vulnerable AI agents, each purpose-built for one
of ARGUS's 12 attack domains.  Anyone can ``docker compose up`` and point
ARGUS at them for blind, reproducible, measurable security testing.

Usage (standalone)::

    cd arena/
    docker compose up -d          # start all 12 targets
    argus scan arena --all        # ARGUS attacks them blind

Usage (without Docker — single process)::

    python -m arena.runner        # starts all 12 on ports 9001-9012

Each scenario exposes:
- ``/health``   — liveness probe
- ``/chat``     — primary chat endpoint (POST)
- ``/tools``    — MCP-compatible tool listing (GET)
- ``/tools/call`` — MCP-compatible tool invocation (POST)
- ``/mcp``      — JSON-RPC MCP endpoint (POST)
- Scenario-specific surfaces (memory, admin, debug, etc.)
"""

__all__ = ["SCENARIO_PORTS"]

# Canonical port assignments — one per scenario.
SCENARIO_PORTS: dict[str, int] = {
    "arena-01-prompt-leak": 9001,
    "arena-02-tool-poison": 9002,
    "arena-03-supply-chain": 9003,
    "arena-04-memory-poison": 9004,
    "arena-05-identity-spoof": 9005,
    "arena-06-context-window": 9006,
    "arena-07-exfil-relay": 9007,
    "arena-08-priv-escalation": 9008,
    "arena-09-race-condition": 9009,
    "arena-10-model-extraction": 9010,
    "arena-11-persona-hijack": 9011,
    "arena-12-memory-boundary": 9012,
}
