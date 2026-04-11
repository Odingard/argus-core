"""ARGUS Test Harness — Mock Vulnerable AI Target.

A lightweight FastAPI server that simulates a vulnerable AI agent for
local testing and development. The mock target has intentional
vulnerabilities that each ARGUS agent can find, providing deterministic,
repeatable results.

Vulnerabilities included:
- Prompt injection susceptibility (follows injected instructions)
- Tool poisoning (hidden content in tool descriptions)
- Memory poisoning (stores and retrieves adversarial content)
- Identity spoof (accepts claimed identity headers)
- Persona hijacking susceptibility (drifts under adversarial pressure)
- Memory boundary collapse (leaks content across session boundaries)
- Context window exploitation (follows buried instructions)
- Privilege escalation (confused deputy via tool chaining)

Usage:
    argus test-target start     # Start mock target on localhost:9999
    argus test-target status    # Check if mock target is running

Then run a scan against it:
    ARGUS_WEB_ALLOW_PRIVATE=1 argus scan mock-target \\
        --agent-endpoint http://localhost:9999/chat
"""

from argus.test_harness.mock_target import create_mock_app

__all__ = ["create_mock_app"]
