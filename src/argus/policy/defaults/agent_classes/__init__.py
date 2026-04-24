"""
argus/policy/defaults/agent_classes — Tier-2 per-class policies.

Each module exports a ``POLICIES`` list[Policy] the registry imports
for its agent class. Adding a new agent class is a one-module drop-
in: create ``<class>.py`` with a POLICIES list and extend the
AgentClass enum + registry wiring.
"""
from argus.policy.defaults.agent_classes import support_bot
from argus.policy.defaults.agent_classes import code_interpreter
from argus.policy.defaults.agent_classes import financial_agent
from argus.policy.defaults.agent_classes import developer_agent

__all__ = [
    "support_bot", "code_interpreter",
    "financial_agent", "developer_agent",
]
