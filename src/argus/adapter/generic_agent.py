"""
argus/adapter/generic_agent.py — GenericAgent target adapter.

Targets the lsdefine/GenericAgent class of self-evolving LLM agent
(paper arXiv 2604.17091, released 2026-04-21). The threat model:

  • ~9 atomic tools give the agent direct system control
    (``code_run``, ``file_read``, ``file_write``, ``file_patch``,
    ``web_scan``, ``web_execute_js``, ``ask_user`` + backend-specific
    mouse/keyboard/ADB variants).
  • Two memory-management tools (``update_working_checkpoint``,
    ``start_long_term_update``) write to a layered memory system
    (L0 Meta Rules → L1 Insight Index → L2 Global Facts → L3 Task
    Skills → L4 Session Archive).
  • ``code_run`` is the self-evolution primitive — the agent
    crystallises temporary execution paths into permanent skills.
    That makes it the highest-value pivot surface ARGUS has
    modelled to date.

This adapter is backend-pluggable (same shape as ``A2AAdapter``):
  • ``GenericAgentBackend`` — transport-specific contract.
  • ``InMemoryGenericAgentBackend`` — ships with the module for
    tests and labrat use. Real target clients (HTTP / stdio /
    Streamlit bridge) subclass the backend and override
    ``list_tools`` / ``list_memory_layers`` / ``invoke``.

Surfaces emitted by ``enumerate()``:
    tool:<atomic-tool>        one per atomic-tool registered
    memory:<layer-id>         one per memory layer (L0..L4 by default)

Request payload for ``tool:<name>`` is the tool's argument dict
(exactly what GenericAgent's loop would emit). Request payload for
``memory:<layer>`` is {"operation": "read|write|query", "value": ...}.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Response, Surface,
)


# ── Backend contract ────────────────────────────────────────────────────────

@dataclass
class GenericAgentTool:
    """One atomic tool the agent exposes."""
    name:        str
    description: str = ""
    # Minimal schema so ARGUS' adapters / audits have something to scan.
    schema:      dict = field(default_factory=dict)


@dataclass
class GenericAgentMemoryLayer:
    """One layer of the layered-memory system.

    ``layer_id`` follows the GenericAgent paper's convention (L0, L1,
    L2, L3, L4). ``kind`` distinguishes read-only layers (L0 meta
    rules) from write-on-crystallize layers (L2/L3/L4)."""
    layer_id:    str
    kind:        str = "read_write"        # "read_only" | "read_write"
    description: str = ""


class GenericAgentBackend(Protocol):
    """Transport-specific backend the adapter delegates to."""

    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def list_tools(self) -> list[GenericAgentTool]: ...
    async def list_memory_layers(self) -> list[GenericAgentMemoryLayer]: ...
    async def invoke(
        self, *, surface_name: str, payload: Any,
    ) -> Response: ...


# ── In-memory backend (tests + labrat) ──────────────────────────────────────

ToolHandlerFn   = Callable[[Any], "Response | dict | str"]
MemoryHandlerFn = Callable[[Any], "Response | dict | str"]

# Canonical tool set per the GenericAgent README. Real targets may
# expose more (mouse/kbd/ADB); the adapter enumerates whatever the
# backend registers — this is just the default ship set.
#
# Each entry is (name, description, schema). Schemas declare the
# tool's input shape the way a real MCP tool does via inputSchema —
# this is what lets ARGUS's schema-first surface matchers classify
# these tools correctly without hand-maintained name catalogs.
# Missing schemas here (the earlier empty-dict default) caused
# EP-11's surface matchers to miss the tools after the
# keyword-catalog refactor; the honest fix is making the fixture
# mirror real tool shape.
DEFAULT_ATOMIC_TOOLS = (
    ("code_run",        "Execute arbitrary code (Python / shell).",
        {"type": "object",
         "properties": {"code":     {"type": "string"},
                        "language": {"type": "string"}},
         "required":   ["code"]}),
    ("file_read",       "Read a file from the host filesystem.",
        {"type": "object",
         "properties": {"path": {"type": "string"}},
         "required":   ["path"]}),
    ("file_write",      "Write a file to the host filesystem.",
        {"type": "object",
         "properties": {"path":    {"type": "string"},
                        "content": {"type": "string"}},
         "required":   ["path", "content"]}),
    ("file_patch",      "Patch / modify an existing file in-place.",
        {"type": "object",
         "properties": {"path":  {"type": "string"},
                        "patch": {"type": "string"}},
         "required":   ["path", "patch"]}),
    ("web_scan",        "Fetch and perceive web content.",
        {"type": "object",
         "properties": {"url": {"type": "string"}},
         "required":   ["url"]}),
    ("web_execute_js",  "Execute JavaScript in a real browser session.",
        {"type": "object",
         "properties": {"url":  {"type": "string"},
                        "code": {"type": "string"}},
         "required":   ["url", "code"]}),
    ("ask_user",        "Human-in-the-loop confirmation prompt.",
        {"type": "object",
         "properties": {"prompt": {"type": "string"}},
         "required":   ["prompt"]}),
)
DEFAULT_MEMORY_TOOLS = (
    ("update_working_checkpoint", "Persist context mid-session.",
        {"type": "object",
         "properties": {"content": {"type": "string"}},
         "required":   ["content"]}),
    ("start_long_term_update",    "Crystallise into L2/L3/L4 memory.",
        {"type": "object",
         "properties": {"layer_id": {"type": "string"},
                        "content":  {"type": "string"}},
         "required":   ["layer_id", "content"]}),
)
DEFAULT_MEMORY_LAYERS = (
    ("L0", "read_only",  "Meta rules / system constraints"),
    ("L1", "read_write", "Insight index — minimal routing memory"),
    ("L2", "read_write", "Global facts — stable long-term knowledge"),
    ("L3", "read_write", "Task skills / SOPs — reusable workflows"),
    ("L4", "read_write", "Session archive — distilled task records"),
)


class InMemoryGenericAgentBackend:
    """
    In-process backend. Register tool handlers and memory layers;
    the adapter routes requests to them. Useful for modelling a
    GenericAgent-class target in tests without standing up a real
    LLM / host.
    """

    def __init__(
        self,
        tools:         Optional[dict[str, ToolHandlerFn]]   = None,
        memory_layers: Optional[dict[str, MemoryHandlerFn]] = None,
        *,
        tool_descriptions:  Optional[dict[str, str]] = None,
        layer_kinds:        Optional[dict[str, str]] = None,
        layer_descriptions: Optional[dict[str, str]] = None,
    ) -> None:
        # Seed with GenericAgent's documented tool + layer set.
        self._tools:      dict[str, ToolHandlerFn] = {}
        self._descs:      dict[str, str]           = {}
        self._schemas:    dict[str, dict]          = {}
        for name, desc, schema in DEFAULT_ATOMIC_TOOLS + DEFAULT_MEMORY_TOOLS:
            self._tools[name]   = self._default_tool_handler
            self._descs[name]   = desc
            self._schemas[name] = dict(schema) if schema else {}

        self._layers:        dict[str, MemoryHandlerFn] = {}
        self._layer_kinds:   dict[str, str]             = {}
        self._layer_descs:   dict[str, str]             = {}
        self._layer_state:   dict[str, list]            = {}
        for lid, kind, desc in DEFAULT_MEMORY_LAYERS:
            # Seed the state dict BEFORE building the handler — the
            # default handler closes over self._layer_state[lid].
            self._layer_state[lid] = []
            self._layer_kinds[lid] = kind
            self._layer_descs[lid] = desc
            self._layers[lid] = self._default_layer_handler(lid)

        # Caller-supplied overrides.
        if tools:
            self._tools.update(tools)
        if tool_descriptions:
            self._descs.update(tool_descriptions)
        if memory_layers:
            self._layers.update(memory_layers)
        if layer_kinds:
            self._layer_kinds.update(layer_kinds)
        if layer_descriptions:
            self._layer_descs.update(layer_descriptions)

        self._connected = False

    # ── Public test helpers ─────────────────────────────────────────────

    def set_tool(
        self, name: str, handler: ToolHandlerFn, *, description: str = "",
    ) -> None:
        self._tools[name] = handler
        if description:
            self._descs[name] = description

    def set_memory_layer(
        self,
        layer_id:    str,
        handler:     MemoryHandlerFn,
        *,
        kind:        str = "read_write",
        description: str = "",
    ) -> None:
        self._layers[layer_id]      = handler
        self._layer_kinds[layer_id] = kind
        if description:
            self._layer_descs[layer_id] = description
        self._layer_state.setdefault(layer_id, [])

    def layer_contents(self, layer_id: str) -> list:
        """Read the raw list stored in a memory layer (test inspection)."""
        return list(self._layer_state.get(layer_id, []))

    # ── Backend contract ────────────────────────────────────────────────

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_tools(self) -> list[GenericAgentTool]:
        return [
            GenericAgentTool(
                name=name,
                description=self._descs.get(name, ""),
                schema=self._schemas.get(name, {}),
            )
            for name in self._tools
        ]

    async def list_memory_layers(self) -> list[GenericAgentMemoryLayer]:
        return [
            GenericAgentMemoryLayer(
                layer_id=lid,
                kind=self._layer_kinds.get(lid, "read_write"),
                description=self._layer_descs.get(lid, ""),
            )
            for lid in self._layers
        ]

    async def invoke(
        self, *, surface_name: str, payload: Any,
    ) -> Response:
        if surface_name.startswith("tool:"):
            tool_name = surface_name.split(":", 1)[1]
            handler = self._tools.get(tool_name)
            if handler is None:
                return Response(status="error",
                                body=f"unknown tool: {tool_name}")
            return self._coerce(handler(payload))
        if surface_name.startswith("memory:"):
            layer_id = surface_name.split(":", 1)[1]
            handler = self._layers.get(layer_id)
            if handler is None:
                return Response(status="error",
                                body=f"unknown memory layer: {layer_id}")
            return self._coerce(handler(payload))
        return Response(
            status="error",
            body=f"GenericAgentAdapter only routes tool:* / memory:* — "
                 f"got {surface_name!r}",
        )

    # ── Defaults ────────────────────────────────────────────────────────

    def _default_tool_handler(self, _payload: Any) -> str:
        # Base "the tool was invoked" echo. Real test scenarios override
        # per-tool handlers to return vulnerability-specific responses.
        return "ok"

    def _default_layer_handler(self, layer_id: str) -> MemoryHandlerFn:
        state = self._layer_state[layer_id]

        def handler(payload: Any) -> dict:
            op = ""
            if isinstance(payload, dict):
                op = str(payload.get("operation") or "").lower()
            if op == "read" or op == "query":
                return {"layer": layer_id, "contents": list(state)}
            if op == "write":
                value = payload.get("value") if isinstance(payload, dict) else payload
                state.append(value)
                return {"layer": layer_id, "written": True}
            # Default — treat payload as a read.
            return {"layer": layer_id, "contents": list(state)}

        return handler

    @staticmethod
    def _coerce(out: Any) -> Response:
        if isinstance(out, Response):
            return out
        if isinstance(out, (dict, list)):
            return Response(status="ok", body=out)
        return Response(status="ok", body=str(out))


# ── Adapter ─────────────────────────────────────────────────────────────────

class GenericAgentAdapter(BaseAdapter):
    """Thin wrapper over a ``GenericAgentBackend``. Surfaces enumerate
    as ``tool:<name>`` and ``memory:<layer-id>`` so every ARGUS agent
    (PI / TP / MP / EP / …) can target the same adapter consistently."""

    def __init__(
        self,
        *,
        backend:         GenericAgentBackend,
        target_id:       str = "",
        connect_timeout: float = 15.0,
        request_timeout: float = 30.0,
    ) -> None:
        super().__init__(
            target_id=target_id or "generic-agent://in-memory",
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        if backend is None:
            raise AdapterError(
                "GenericAgentAdapter requires a backend. Pass "
                "InMemoryGenericAgentBackend for tests or a real "
                "transport client for live targets."
            )
        self._backend = backend

    async def _connect(self) -> None:
        await self._backend.connect()

    async def _disconnect(self) -> None:
        await self._backend.disconnect()

    async def _enumerate(self) -> list[Surface]:
        tools   = await self._backend.list_tools()
        layers  = await self._backend.list_memory_layers()
        out: list[Surface] = []
        for t in tools:
            out.append(Surface(
                kind="tool",
                name=f"tool:{t.name}",
                description=t.description,
                schema=t.schema or {},
            ))
        for layer in layers:
            out.append(Surface(
                kind="memory",
                name=f"memory:{layer.layer_id}",
                description=layer.description,
                schema={"kind": layer.kind, "layer_id": layer.layer_id},
            ))
        return out

    async def _interact(self, request: Request) -> AdapterObservation:
        response = await self._backend.invoke(
            surface_name=request.surface,
            payload=request.payload,
        )
        return AdapterObservation(
            request_id=request.id,
            surface=request.surface,
            response=response,
        )
