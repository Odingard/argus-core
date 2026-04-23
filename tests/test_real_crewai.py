"""
tests/test_real_crewai.py — in-process real-crewai adapter.

Tests against a STUB crew-shaped object (duck-typed). The production
path imports the real `crewai` package; tests inject a builder
that returns the stub, so nothing touches the real package or the
LLM API.
"""
from __future__ import annotations

import asyncio

import pytest

from argus.adapter import RealCrewAIAdapter, CrewAIConfig
from argus.adapter.base import AdapterError, Request
from argus.engagement import target_for_url


# ── Duck-typed crew fixtures ──────────────────────────────────────────────

class _StubTool:
    def __init__(self, name, behaviour=None):
        self.name = name
        self._behaviour = behaviour or (lambda **kw: "tool-ok")

    def run(self, **kw):
        return self._behaviour(**kw)


class _StubAgent:
    def __init__(self, role, backstory="", tools=None,
                 allow_delegation=False):
        self.role = role
        self.backstory = backstory
        self.tools = list(tools or [])
        self.allow_delegation = allow_delegation
        self.calls = []

    def execute_task(self, task):
        self.calls.append(task)
        return (f"[{self.role}] executed: "
                f"{getattr(task, 'description', str(task))}")


class _StubCrew:
    def __init__(self, agents):
        self.agents = list(agents)
        self._history = []


def _make_crew(config: CrewAIConfig):
    by_role = {}
    for a in config.agents:
        by_role[a.role] = _StubAgent(
            role=a.role, backstory=a.backstory,
            allow_delegation=a.allow_delegation,
            tools=[_StubTool(t) for t in a.tools],
        )
    return _StubCrew(agents=list(by_role.values()))


# ── Config loader ────────────────────────────────────────────────────────

def test_config_from_dict_round_trips():
    data = {
        "crew": [
            {"role": "r1", "goal": "g", "backstory": "b",
             "tools": ["T1"], "allow_delegation": True},
        ],
        "tasks": [
            {"agent": "r1", "description": "do a thing"},
        ],
        "tools": {
            "T1": {"import": "some.mod.T1",
                   "init_kwargs": {"x": 1}},
        },
        "llm": {"provider": "openai", "model": "gpt-4o-mini"},
        "memory": True,
    }
    cfg = CrewAIConfig.from_dict(data)
    assert len(cfg.agents) == 1
    assert cfg.agents[0].role == "r1"
    assert cfg.agents[0].allow_delegation is True
    assert cfg.tools["T1"].import_path == "some.mod.T1"
    assert cfg.memory is True
    assert cfg.llm_config["provider"] == "openai"


def test_config_from_yaml_loads_example(tmp_path):
    import yaml as _yaml
    data = {
        "crew": [{"role": "r", "goal": "g", "backstory": "b",
                  "tools": []}],
        "tasks": [{"agent": "r", "description": "d"}],
    }
    p = tmp_path / "c.yaml"
    p.write_text(_yaml.safe_dump(data))
    cfg = CrewAIConfig.from_yaml(p)
    assert len(cfg.agents) == 1


# ── Adapter enumeration (no crewai needed) ───────────────────────────────

def test_enumerate_emits_chat_surface_per_agent():
    cfg = CrewAIConfig.from_dict({
        "crew": [
            {"role": "alpha", "goal": "", "backstory": "b"},
            {"role": "beta",  "goal": "", "backstory": "b2",
             "allow_delegation": True},
        ],
    })
    a = RealCrewAIAdapter(config=cfg, crew_builder=_make_crew)

    async def go():
        async with a:
            return await a.enumerate()

    surfaces = asyncio.run(go())
    names = {s.name for s in surfaces}
    assert "chat:alpha" in names
    assert "chat:beta" in names
    # Only the delegator exposes a handoff surface.
    assert "handoff:beta" in names
    assert "handoff:alpha" not in names


def test_enumerate_includes_memory_surface_when_enabled():
    cfg = CrewAIConfig.from_dict({
        "crew": [{"role": "r", "goal": "", "backstory": "b"}],
        "memory": True,
    })
    a = RealCrewAIAdapter(config=cfg, crew_builder=_make_crew)

    async def go():
        async with a:
            return await a.enumerate()

    names = {s.name for s in asyncio.run(go())}
    assert "memory:crew_state" in names


def test_enumerate_includes_tool_surfaces():
    cfg = CrewAIConfig.from_dict({
        "crew":  [{"role": "r", "goal": "", "backstory": "b",
                   "tools": []}],
        "tools": {"FileWriteTool": {"import": "crewai_tools.FileWriteTool"}},
    })
    a = RealCrewAIAdapter(config=cfg, crew_builder=_make_crew)
    async def go():
        async with a:
            return await a.enumerate()
    names = {s.name for s in asyncio.run(go())}
    assert "tool:FileWriteTool" in names


# ── Adapter invocation (stubbed) ─────────────────────────────────────────

def test_chat_interact_calls_agent_execute_task():
    cfg = CrewAIConfig.from_dict({
        "crew": [{"role": "r", "goal": "", "backstory": "b"}],
    })
    a = RealCrewAIAdapter(config=cfg, crew_builder=_make_crew)

    async def go():
        async with a:
            return await a.interact(Request(
                surface="chat:r", payload="hi there",
            ))

    obs = asyncio.run(go())
    assert obs.response.status == "ok"
    assert "[r] executed: hi there" in str(obs.response.body)


def test_unknown_chat_role_returns_clean_error():
    cfg = CrewAIConfig.from_dict({
        "crew": [{"role": "r", "goal": "", "backstory": "b"}],
    })
    a = RealCrewAIAdapter(config=cfg, crew_builder=_make_crew)
    async def go():
        async with a:
            return await a.interact(Request(
                surface="chat:unknown", payload="x",
            ))
    obs = asyncio.run(go())
    assert "no agent with role='unknown'" in str(obs.response.body)


def test_tool_interact_calls_tool_run():
    cfg = CrewAIConfig.from_dict({
        "crew":  [{"role": "r", "goal": "", "backstory": "b",
                   "tools": ["T"]}],
        "tools": {"T": {"import": "x.y.T"}},
    })
    a = RealCrewAIAdapter(config=cfg, crew_builder=_make_crew)

    async def go():
        async with a:
            return await a.interact(Request(
                surface="tool:T", payload={"arg": 1},
            ))

    obs = asyncio.run(go())
    assert "tool-ok" in str(obs.response.body)


def test_handoff_dispatches_to_target_agent():
    cfg = CrewAIConfig.from_dict({
        "crew": [
            {"role": "caller", "goal": "", "backstory": "b",
             "allow_delegation": True},
            {"role": "target", "goal": "", "backstory": "b"},
        ],
    })
    a = RealCrewAIAdapter(config=cfg, crew_builder=_make_crew)
    async def go():
        async with a:
            return await a.interact(Request(
                surface="handoff:target",
                payload={"content": "delegated hello"},
            ))
    obs = asyncio.run(go())
    assert "[target] executed: delegated hello" in str(obs.response.body)


# ── Real import failure is surfaced cleanly ─────────────────────────────

def test_connect_without_crew_builder_and_no_crewai_raises_cleanly(
    monkeypatch,
):
    """When crewai isn't installed AND no stub builder is injected,
    the adapter raises a clear AdapterError with install instructions."""
    # Simulate 'crewai not importable'.
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "crewai",
                        None)        # type: ignore
    cfg = CrewAIConfig.from_dict({
        "crew": [{"role": "r", "goal": "", "backstory": "b"}],
    })
    a = RealCrewAIAdapter(config=cfg)       # no crew_builder
    async def go():
        async with a:
            pass
    with pytest.raises(AdapterError) as exc:
        asyncio.run(go())
    assert "crewai is not installed" in str(exc.value)


# ── Engagement-registry integration ─────────────────────────────────────

def test_real_crewai_registered_in_registry():
    spec = target_for_url("real-crewai:///path/to/config.yaml")
    assert spec is not None
    assert spec.scheme == "real-crewai"
    assert "real" in spec.description.lower()
