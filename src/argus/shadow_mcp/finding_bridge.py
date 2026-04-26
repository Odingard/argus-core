"""
argus/shadow_mcp/finding_bridge.py — Convert ShadowObservation → AgentFinding.

Shadow MCP harvest() triggers are "High-Priority Anchors" — they prove the
target agent followed injected instructions from a malicious MCP server.
This is a reasoning flaw confirmation, not just a code vulnerability.

Converting to AgentFinding allows harvest triggers to:
  - Satisfy chain synthesis (no secondary finding needed)
  - Gate layer6 CVE pipeline (is_validated=True)
  - Appear in HTML report findings table
  - Feed the attack graph knowledge base
  - Trigger turn-fire rules for follower agents
"""
from __future__ import annotations

from argus.agents.base import AgentFinding
from argus.shadow_mcp.server import ShadowObservation


def observation_to_finding(obs: ShadowObservation,
                            target_id: str) -> AgentFinding:
    """Convert a confirmed ShadowMCP observation to an AgentFinding anchor."""
    f = AgentFinding(
        id=f"shadow-{obs.tool_call[:8]}-{hash(obs.evidence) % 99999:05d}",
        agent_id="SHADOW-MCP",
        vuln_class="TOOL_POISONING",
        severity="CRITICAL",
        title=(
            f"Shadow MCP trigger confirmed: agent called "
            f"{obs.tool_call!r} after receiving poisoned tool definition"
        ),
        description=(
            f"The target agent called tool {obs.tool_call!r} with "
            f"parameters {obs.parameters} after ARGUS served a tool "
            f"catalog containing injected instructions. This proves the "
            f"agent follows tool description instructions without "
            f"verification — a reasoning flaw exploitable by any "
            f"malicious MCP server the agent connects to. "
            f"Evidence: {obs.evidence}"
        ),
        surface=f"shadow_mcp::{obs.tool_call}",
        technique="SHADOW_MCP_TRIGGER",
        delta_evidence=(
            f"[Proof Grade: IRREFUTABLE]\n\n"
            f"--- Shadow MCP Trigger ---\n"
            f"  Tool called: {obs.tool_call}\n"
            f"  Parameters:  {obs.parameters}\n"
            f"  Evidence:    {obs.evidence}\n"
        ),
        exploitability_confirmed=True,
        confidence_capped=False,
        proof_grade="IRREFUTABLE",
    )
    return f


def harvest_to_findings(observations: list[ShadowObservation],
                        target_id: str) -> list[AgentFinding]:
    """Convert all triggered shadow observations to AgentFindings.
    These are High-Priority Anchors — they satisfy chain synthesis
    independently, no secondary finding required."""
    return [observation_to_finding(o, target_id)
            for o in observations if o.triggered]
