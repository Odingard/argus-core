"""
argus.adapter — Target Adapter framework.

Every offensive agent interacts with the target exclusively through a
``BaseAdapter``. Adapters own the wire protocol; agents own the attack
substance. This decoupling is what lets ARGUS talk to MCP servers,
arbitrary HTTP agent APIs, stdio MCP processes, and (Phase 2) Google
A2A / LangGraph handoff channels with the same attack code.

Contract a Phase-1+ agent sees:

    async with MCPAdapter(url="http://.../sse") as adapter:
        surfaces = await adapter.enumerate()           # Surfaces catalog
        baseline = await adapter.interact(benign)      # Baseline observation
        for variant in corpus.sample(...):             # Attack loop
            obs = await adapter.interact(
                Request(surface="tool:xyz", payload=variant.payload)
            )
            # Observation is what the Phase 0.4 Observer judges.

No adapter ever surfaces a "finding" — findings come from the
Observation Engine (Phase 0.4) comparing baseline vs. post-attack
observations. Adapters are plumbing.
"""
from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
    AdapterError, ConnectionState,
)
from argus.adapter.http_agent import HTTPAgentAdapter
from argus.adapter.mcp import MCPAdapter
from argus.adapter.stdio import StdioAdapter
from argus.adapter.a2a import A2AAdapter, A2ABackend, InMemoryA2ABackend, Peer
from argus.adapter.generic_agent import (
    GenericAgentAdapter, GenericAgentBackend, GenericAgentMemoryLayer,
    GenericAgentTool, InMemoryGenericAgentBackend,
)
from argus.adapter.real_crewai import (
    CrewAIConfig, RealCrewAIAdapter,
)

__all__ = [
    "AdapterObservation", "BaseAdapter", "Request", "Response", "Surface",
    "AdapterError", "ConnectionState",
    "MCPAdapter", "HTTPAgentAdapter", "StdioAdapter",
    "A2AAdapter", "A2ABackend", "InMemoryA2ABackend", "Peer",
    "GenericAgentAdapter", "GenericAgentBackend", "GenericAgentTool",
    "GenericAgentMemoryLayer", "InMemoryGenericAgentBackend",
    "CrewAIConfig", "RealCrewAIAdapter",
]
