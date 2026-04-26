"""
argus/plugins/__init__.py — Plugin interface for custom ARGUS agents.

Operators drop Python files into a plugins directory or pass
--plugins /path/to/agent.py on the CLI. Any class in that file
subclassing BaseAgent with an AGENT_ID gets registered and added
to the engagement slate automatically.

Usage (operator-facing):
    # my_salesforce_agent.py
    from argus.agents.base import BaseAgent, AgentFinding

    class SalesforceToolAudit(BaseAgent):
        AGENT_ID  = "SF-01"
        VULN_CLASS = "TOOL_POISONING"

        async def run_async(self, *, target_id, output_dir, **kwargs):
            # Your custom logic here
            return self.findings

CLI:
    argus engage <target> --plugins ./my_salesforce_agent.py

Python API:
    from argus.plugins import load_plugins, register_plugin
    load_plugins(["/path/to/agent.py"])
    results = run_engagement(target_url=..., extra_agents=["SF-01"])
"""
from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Optional


_REGISTRY: dict[str, type] = {}   # agent_id → class


def register_plugin(cls: type) -> None:
    """Register an agent class by its AGENT_ID."""
    aid = getattr(cls, "AGENT_ID", None)
    if not aid:
        raise ValueError(f"Plugin class {cls.__name__} missing AGENT_ID")
    _REGISTRY[aid] = cls
    print(f"  [plugins] registered {cls.__name__} as {aid}")


def load_plugins(paths: list[str | Path]) -> list[str]:
    """Load plugin files and register all BaseAgent subclasses found.
    Returns list of registered agent IDs."""
    from argus.agents.base import BaseAgent
    registered = []
    for path in paths:
        p = Path(path).resolve()
        if not p.exists():
            print(f"  [plugins] WARNING: {p} not found — skipping")
            continue
        spec = importlib.util.spec_from_file_location(p.stem, p)
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        sys.modules[p.stem] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"  [plugins] ERROR loading {p}: {e}")
            continue
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if (obj is not BaseAgent
                    and issubclass(obj, BaseAgent)
                    and hasattr(obj, "AGENT_ID")):
                register_plugin(obj)
                registered.append(obj.AGENT_ID)
    return registered


def get_plugin(agent_id: str) -> Optional[type]:
    return _REGISTRY.get(agent_id)


def list_plugins() -> list[str]:
    return list(_REGISTRY.keys())


def run_plugin_agent(agent_id: str, **kwargs) -> list:
    """Instantiate and run a registered plugin agent."""
    cls = get_plugin(agent_id)
    if cls is None:
        raise KeyError(f"No plugin registered for agent_id={agent_id!r}")
    agent = cls(
        adapter_factory=kwargs.pop("factory", None),
        evolve_corpus=kwargs.pop("ev_corpus", None),
    )
    if kwargs.get("eng_seed"):
        agent.eng_seed = kwargs["eng_seed"]
    import asyncio
    return asyncio.run(agent.run_async(
        target_id=kwargs.get("target_id", "unknown"),
        output_dir=str(kwargs.get("output_dir", ".")),
    ))
