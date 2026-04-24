"""
argus.policy.defaults — ship-with-ARGUS policy library.

Tier-1 globals live in ``globals_.py``; tier-2 agent-class
defaults live in ``agent_classes/<class>.py``. Each module
exports a ``POLICIES`` list[Policy] the registry imports.
"""
from argus.policy.defaults import globals_
from argus.policy.defaults import agent_classes

__all__ = ["globals_", "agent_classes"]
