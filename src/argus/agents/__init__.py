"""ARGUS Attack Agents.

Each agent is a specialized offensive AI agent targeting a distinct
AI-specific attack domain. Agents are short-lived, narrowly scoped,
and deployed simultaneously at T=0.

Phase 1 Agents:
  1. Prompt Injection Hunter — all input surfaces, direct/indirect/encoded/multi-step
  2. Tool Poisoning Agent — MCP tool definitions, hidden instructions, cross-tool chaining
  9. Supply Chain Agent — external MCP trust, dependency confusion, tool integrity

Phase 2 Agents:
  3. Memory Poisoning Agent — plant adversarial content in memory, trigger retrieval leak
  4. Identity Spoof Agent — bypass A2A authentication via claimed identity headers

Phase 3 Agents:
  5. Context Window Agent — context overflow, long-con multi-turn exploitation
  6. Cross-Agent Exfiltration Agent — data leakage between agents / shared resources
  7. Privilege Escalation Agent — tool-call chaining for unauthorized access
  8. Race Condition Agent — TOCTOU, parallel session isolation, transaction atomicity

Phase 4 Agents:
  10. Model Extraction Agent — system prompt, tool inventory, config fingerprinting

Phase 5 Agents:
  11. Persona Hijacking Agent — identity drift, role boundary erosion, goal substitution
  12. Memory Boundary Collapse Agent — context bleed, preference contamination, hierarchy collapse
"""

from argus.agents.base import LLMAttackAgent
from argus.agents.context_window import ContextWindowAgent
from argus.agents.cross_agent_exfil import CrossAgentExfilAgent
from argus.agents.identity_spoof import IdentitySpoofAgent
from argus.agents.memory_boundary_collapse import MemoryBoundaryCollapseAgent
from argus.agents.memory_poisoning import MemoryPoisoningAgent
from argus.agents.model_extraction import ModelExtractionAgent
from argus.agents.persona_hijacking import PersonaHijackingAgent
from argus.agents.privilege_escalation import PrivilegeEscalationAgent
from argus.agents.prompt_injection import PromptInjectionHunter
from argus.agents.race_condition import RaceConditionAgent
from argus.agents.supply_chain import SupplyChainAgent
from argus.agents.tool_poisoning import ToolPoisoningAgent

__all__ = [
    "LLMAttackAgent",
    "PromptInjectionHunter",
    "ToolPoisoningAgent",
    "SupplyChainAgent",
    "MemoryPoisoningAgent",
    "IdentitySpoofAgent",
    "ContextWindowAgent",
    "CrossAgentExfilAgent",
    "PrivilegeEscalationAgent",
    "RaceConditionAgent",
    "ModelExtractionAgent",
    "PersonaHijackingAgent",
    "MemoryBoundaryCollapseAgent",
]
