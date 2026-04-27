"""
argus/adapter/real_crewai.py — in-process adapter for the REAL
crewAI package.

Where ``argus.labrat.crewai_shaped.CrewAILabrat`` is a SHAPE model
— a fixture that looks like a crewAI deployment without importing
the library — this adapter instantiates an actual ``crewai.Crew``
from a YAML config and attacks it via the package's public Python
API. Findings here are against real crewAI code paths; they can
be promoted to CVE disclosures.

Config shape (``real-crewai://path/to/config.yaml``):

    llm:
      provider: openai           # openai | anthropic | azure
      model:    gpt-4o-mini
      api_key_env: OPENAI_API_KEY
    crew:
      - role: researcher
        goal: "Find facts."
        backstory: "Senior research analyst."
        tools: []                # names; tool registry declared below
      - role: writer
        goal: "Draft articles."
        backstory: "Technical writer."
        tools: [FileWriteTool]
        allow_delegation: false
    tasks:
      - agent: researcher
        description: "Research the given topic."
      - agent: writer
        description: "Write a draft from the research."
    tools:
      FileWriteTool:
        import: crewai_tools.FileWriteTool

Enumeration surface emitted to ARGUS agents:
    chat:<role>          per-agent entrypoint
    handoff:<role>       handoff edges (only when allow_delegation)
    tool:<tool_name>     each bound tool
    memory:crew_state    if the crew enables memory

Runtime behaviour:
    _interact(Request(surface='chat:<role>', payload=text))
        → calls <role>.execute_task(Task(description=text))
        → returns the real LLM response (costs real tokens)

    _interact(Request(surface='tool:<name>', payload=args))
        → calls tool.run(**args)
        → real side effects (!) — run inside sandboxed labrat
          when the tool has system-level access.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import yaml                    # optional — falls back to JSON
except ImportError:                # pragma: no cover
    yaml = None                    # type: ignore

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Response, Surface,
)


# ── Config loader ───────────────────────────────────────────────────────────

@dataclass
class _AgentSpec:
    role:             str
    goal:             str
    backstory:        str
    tools:            list[str] = field(default_factory=list)
    allow_delegation: bool      = False


@dataclass
class _TaskSpec:
    agent:       str
    description: str


@dataclass
class _ToolSpec:
    name:        str
    import_path: str      # "pkg.module.Attr"
    init_kwargs: dict     = field(default_factory=dict)


@dataclass
class CrewAIConfig:
    agents:      list[_AgentSpec] = field(default_factory=list)
    tasks:       list[_TaskSpec]  = field(default_factory=list)
    tools:       dict[str, _ToolSpec] = field(default_factory=dict)
    llm_config:  dict             = field(default_factory=dict)
    memory:      bool             = False

    @classmethod
    def from_yaml(cls, path: str | Path) -> "CrewAIConfig":
        if yaml is None:
            raise AdapterError(
                "PyYAML not installed — required for real-crewai:// "
                "config files. Install with: pip install pyyaml"
            )
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data or {})

    @classmethod
    def from_dict(cls, data: dict) -> "CrewAIConfig":
        crew = [_AgentSpec(
            role=a["role"], goal=a.get("goal", ""),
            backstory=a.get("backstory", ""),
            tools=list(a.get("tools", [])),
            allow_delegation=bool(a.get("allow_delegation", False)),
        ) for a in data.get("crew", [])]
        tasks = [_TaskSpec(
            agent=t["agent"],
            description=t.get("description", ""),
        ) for t in data.get("tasks", [])]
        tools = {}
        for tname, tdef in (data.get("tools") or {}).items():
            tools[tname] = _ToolSpec(
                name=tname,
                import_path=tdef["import"],
                init_kwargs=dict(tdef.get("init_kwargs") or {}),
            )
        return cls(
            agents=crew, tasks=tasks, tools=tools,
            llm_config=dict(data.get("llm") or {}),
            memory=bool(data.get("memory", False)),
        )


# ── Adapter ────────────────────────────────────────────────────────────────

CrewBuilder = Callable[[CrewAIConfig], Any]
"""Factory that turns a config into a crewai.Crew-shaped object.
Tests inject a stub builder so nothing touches the real crewai
package or OpenAI."""


class RealCrewAIAdapter(BaseAdapter):
    """
    Engage a real crewAI deployment.

    Construction:

        adapter = RealCrewAIAdapter(config_path="examples/crew.yaml")

    The adapter imports ``crewai`` lazily at ``connect()`` time —
    the engagement runner can enumerate surfaces without the
    package installed (useful for dry-runs). Any actual interact()
    call requires crewai + an LLM backend with a valid API key
    (whichever provider the config declares).
    """

    def __init__(
        self,
        *,
        config_path:    Optional[str | Path] = None,
        config:         Optional[CrewAIConfig] = None,
        crew_builder:   Optional[CrewBuilder] = None,
        target_id:      Optional[str] = None,
        connect_timeout: float = 30.0,
        request_timeout: float = 120.0,    # real LLM roundtrips
    ) -> None:
        if config is None:
            if config_path is None:
                raise AdapterError(
                    "RealCrewAIAdapter needs either config= or "
                    "config_path=."
                )
            config = CrewAIConfig.from_yaml(config_path)

        slug = (Path(config_path).name
                if config_path else "real-crewai")
        super().__init__(
            target_id=target_id or f"real-crewai://{slug}",
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        self._config = config
        self._crew_builder = crew_builder
        self._crew = None          # populated at connect

    # ── BaseAdapter contract ────────────────────────────────────────

    async def _connect(self) -> None:
        if self._crew_builder is not None:
            self._crew = self._crew_builder(self._config)
            return
        # Real path: import crewai, instantiate.
        try:
            import crewai                     # noqa: F401
        except ImportError as e:
            import sys as _sys
            py = _sys.executable
            raise AdapterError(
                "crewai is not installed in the Python interpreter "
                f"running ARGUS ({py}). Install it with:\n"
                f"    {py} -m pip install crewai"
            ) from e
        self._crew = _build_real_crew(self._config)

    async def _disconnect(self) -> None:
        self._crew = None

    async def _enumerate(self) -> list[Surface]:
        surfaces: list[Surface] = []
        for a in self._config.agents:
            surfaces.append(Surface(
                kind="chat", name=f"chat:{a.role}",
                description=(f"crewAI agent role={a.role!r}. "
                             f"Backstory: {a.backstory[:200]}"),
                schema={"meta": {
                    "role": a.role, "goal": a.goal,
                    "tools": a.tools,
                    "allow_delegation": a.allow_delegation,
                }},
            ))
            if a.allow_delegation:
                surfaces.append(Surface(
                    kind="handoff", name=f"handoff:{a.role}",
                    description=f"Delegation edge into {a.role}.",
                    schema={"envelope": {"from_agent": "string",
                                         "to_agent":   a.role,
                                         "identity":   "string",
                                         "content":    "string"}},
                ))
        for tname, tspec in self._config.tools.items():
            surfaces.append(Surface(
                kind="tool", name=f"tool:{tname}",
                description=(f"Tool {tname} (import: "
                             f"{tspec.import_path})"),
                schema={"meta": {"import": tspec.import_path}},
            ))
        if self._config.memory:
            surfaces.append(Surface(
                kind="memory", name="memory:crew_state",
                description="crewAI cross-task shared memory.",
                schema={"kind": "read_write", "layer_id": "crew_state"},
            ))
        return surfaces

    async def _interact(self, request: Request) -> AdapterObservation:
        if self._crew is None:
            raise AdapterError(
                "RealCrewAIAdapter not connected"
            )
        surface = request.surface
        payload = request.payload
        try:
            if surface.startswith("chat:"):
                role = surface.split(":", 1)[1]
                body = await self._invoke_agent(role, payload)
            elif surface.startswith("tool:"):
                tname = surface.split(":", 1)[1]
                body = await self._invoke_tool(tname, payload)
            elif surface.startswith("handoff:"):
                dest = surface.split(":", 1)[1]
                body = await self._invoke_handoff(dest, payload)
            elif surface.startswith("memory:"):
                body = await self._access_memory(
                    surface.split(":", 1)[1], payload,
                )
            else:
                body = f"unknown surface {surface!r}"
        except Exception as e:
            body = f"ERROR {type(e).__name__}: {e}"
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )

    # ── Invocation ──────────────────────────────────────────────────

    async def _invoke_agent(self, role: str, payload: Any) -> Any:
        """Dispatch to the crew's agent. Uses duck-typed shape so a
        test stub matches the real crewai.Agent's method surface."""
        agent = _find_by_attr(
            self._crew_agents(), "role", role,
        )
        if agent is None:
            return f"no agent with role={role!r}"
        text = _coerce_text(payload)
        # crewai agents expose .execute_task(task) where task is a
        # Task object; we wrap the text in the simplest shape.
        if hasattr(agent, "execute_task"):
            task = self._make_task(text, role=role)
            return _call_maybe_async(agent.execute_task, task)
        if hasattr(agent, "kickoff"):
            return _call_maybe_async(agent.kickoff, text)
        return f"agent {role!r} has no execute_task / kickoff method"

    async def _invoke_tool(self, tname: str, payload: Any) -> Any:
        tool = self._find_tool(tname)
        if tool is None:
            return f"no tool named {tname!r}"
        kwargs = payload if isinstance(payload, dict) else {}
        if hasattr(tool, "run"):
            return _call_maybe_async(tool.run, **kwargs)
        if hasattr(tool, "__call__"):
            return _call_maybe_async(tool, **kwargs)
        return f"tool {tname!r} has no run() or __call__"

    async def _invoke_handoff(self, dest: str, payload: Any) -> Any:
        text = (payload.get("content")
                if isinstance(payload, dict) else str(payload))
        return await self._invoke_agent(dest, text or "")

    async def _access_memory(self, layer: str, payload: Any) -> Any:
        # crewai memory shapes vary by version; default to read-only
        # surface that returns the crew's recent history if available.
        if not self._config.memory:
            return {"layer": layer, "contents": []}
        crew = self._crew
        history = getattr(crew, "_history", None) \
            or getattr(crew, "history", None) or []
        op = (payload or {}).get("operation", "read") \
            if isinstance(payload, dict) else "read"
        if op == "write":
            val = (payload or {}).get("value")
            if hasattr(crew, "_history"):
                crew._history.append(val)
            return {"layer": layer, "written": True}
        return {"layer": layer, "contents": list(history)[-10:]}

    # ── Crew introspection helpers ──────────────────────────────────

    def _crew_agents(self) -> list[Any]:
        crew = self._crew
        for attr in ("agents", "_agents"):
            v = getattr(crew, attr, None)
            if v is not None:
                return list(v)
        return []

    def _find_tool(self, name: str) -> Optional[Any]:
        for a in self._crew_agents():
            for t in getattr(a, "tools", []) or []:
                if getattr(t, "name", "") == name:
                    return t
        return None

    def _make_task(self, text: str, *, role: str) -> Any:
        # Prefer a crewai.Task if available; else a duck-typed stub.
        try:
            from crewai import Task       # type: ignore
            return Task(description=text, expected_output="a response")
        except Exception:
            return type("Task", (), {
                "description":     text,
                "expected_output": "a response",
                "agent_role":      role,
            })()


# ── Crew construction ──────────────────────────────────────────────────────

def _build_real_crew(config: CrewAIConfig):
    """Real crewai instantiation path. Imported lazily; the test
    path skips this via crew_builder=..."""
    # pragma: no cover — exercised only when crewai is installed
    # AND the operator has passed a YAML config. Tests use the
    # builder injection.
    from importlib import import_module
    from crewai import Agent, Crew, Task

    # Resolve llm from config.
    llm = _resolve_llm(config.llm_config)

    # Build tool registry.
    tools: dict[str, Any] = {}
    for tname, tspec in config.tools.items():
        mod_path, _, attr = tspec.import_path.rpartition(".")
        # import_path comes from operator-supplied YAML — the plug-in
        # seam that lets operators instantiate their own crewAI tools
        # without monkey-patching argus. Untrusted YAML should not be
        # fed into argus at all; treating import_module as a sink
        # here isn't a meaningful defense.
        mod = import_module(mod_path)  # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
        cls = getattr(mod, attr)
        tools[tname] = cls(**tspec.init_kwargs)

    agents_by_role = {}
    for a in config.agents:
        agents_by_role[a.role] = Agent(
            role=a.role, goal=a.goal, backstory=a.backstory,
            tools=[tools[t] for t in a.tools if t in tools],
            allow_delegation=a.allow_delegation,
            llm=llm,
        )

    tasks = []
    for t in config.tasks:
        ag = agents_by_role.get(t.agent)
        if ag is None:
            continue
        tasks.append(Task(
            description=t.description,
            expected_output="a response",
            agent=ag,
        ))

    return Crew(
        agents=list(agents_by_role.values()),
        tasks=tasks,
        memory=config.memory,
    )


def _resolve_llm(llm_cfg: dict):       # pragma: no cover
    """Build the crewAI ``LLM`` instance the crew uses for its internal
    agent calls, with failover propagated into litellm's runtime.

    The construction goes through ``ArgusClient.build_litellm_kwargs(...)``
    so that the chain ARGUS would use for its own LLM calls (judge, etc.)
    is the same chain crewai's agents use internally. ``is_litellm=True``
    is set explicitly to force the litellm dispatch path — without it,
    crewai routes through native provider classes (anthropic.Anthropic,
    openai.OpenAI) which do not honour ``fallbacks=[...]`` kwargs.

    The chain is read from ``ARGUS_LLM_CHAIN`` (or the per-call override
    in the YAML config). With no chain set, behaviour is identical to
    pre-failover: a single primary model, single attempt.
    """
    if not llm_cfg:
        return None
    provider = (llm_cfg.get("provider") or "openai").lower()
    key_env = llm_cfg.get("api_key_env") or {
        "openai":    "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "azure":     "AZURE_OPENAI_API_KEY",
        "gemini":    "GEMINI_API_KEY",
    }.get(provider, "OPENAI_API_KEY")
    if not os.environ.get(key_env):
        raise AdapterError(
            f"real-crewai needs {key_env!r} in the environment. "
            f"Export it or switch providers in the config."
        )
    model = llm_cfg.get("model") or "gpt-4o-mini"
    # Per-call chain override in YAML, if provided. Falls through to
    # ARGUS_LLM_CHAIN env var if absent (handled inside build_litellm_kwargs).
    yaml_chain = llm_cfg.get("chain")
    try:
        from argus.shared.client import ArgusClient
        from crewai import LLM    # type: ignore
        litellm_kw = ArgusClient.build_litellm_kwargs(
            provider, model, chain=yaml_chain,
        )
        # is_litellm=True forces crewai through litellm so fallbacks
        # are honoured. Without this flag native providers handle the
        # call directly and silently ignore the fallbacks list.
        return LLM(is_litellm=True, **litellm_kw)
    except Exception:
        # Fall through — let crewai pick a default. Logged via warnings
        # so a misconfigured chain doesn't silently kill the engagement.
        import warnings
        warnings.warn(
            "real-crewai: failed to construct LLM with failover chain, "
            "falling back to crewai default", RuntimeWarning,
        )
        return None


# ── Shared duck-typed helpers (test-friendly) ─────────────────────────────

def _find_by_attr(xs: list, attr: str, value: str):
    for x in xs:
        if getattr(x, attr, None) == value:
            return x
    return None


def _coerce_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        return str(payload.get("content") or payload.get("text") or payload)
    return str(payload)


def _call_maybe_async(fn, *args, **kwargs):
    """Support tools / agents that return either a plain value or a
    coroutine. The adapter's caller is an async context so we
    normalise."""
    import asyncio
    out = fn(*args, **kwargs)
    if asyncio.iscoroutine(out):
        # Run in the current loop.
        return asyncio.get_event_loop().run_until_complete(out)
    return out
