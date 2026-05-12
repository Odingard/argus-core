"""Shared helpers for Layer-1 (Tool/MCP Poisoning) attack classes.

Layer-1 variants ship as ``Variant`` objects whose ``tools`` and
``resources`` fields are populated. The shared render hook turns the
mutator's rendered payload into the right combination of messages, tools
and resources for the target transport.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from ...core.canary import CanarySet
from ...core.generator import Generator
from ...core.mutator import CompositeMutator, Mutator
from ...core.recon_profile import ReconProfile
from ...core.seed import Seed
from ...core.variant import Message, ResourceSpec, ToolSpec


def deep_format_canary(value: Any, canary: str, _depth: int = 0, _seen: set | None = None) -> Any:
    """Recursively substitute ``{canary}`` in any string-value within a structure.

    Cycle-safe (the schema mutator can produce ``$ref`` cycles). Capped at
    depth 32 to avoid pathological structures.
    """
    if _depth > 32:
        return value
    if isinstance(value, str):
        if "{canary}" in value:
            return value.replace("{canary}", canary)
        return value
    if isinstance(value, (list, tuple, dict)):
        if _seen is None:
            _seen = set()
        ident = id(value)
        if ident in _seen:
            return value
        _seen = _seen | {ident}
    if isinstance(value, list):
        return [deep_format_canary(v, canary, _depth + 1, _seen) for v in value]
    if isinstance(value, tuple):
        return tuple(deep_format_canary(v, canary, _depth + 1, _seen) for v in value)
    if isinstance(value, dict):
        return {k: deep_format_canary(v, canary, _depth + 1, _seen) for k, v in value.items()}
    return value


def make_layer1_render(
    *,
    default_user_prompt: str = "Please use the available tool to help me.",
    extra_messages_before: tuple[Message, ...] = (),
    extra_messages_after: tuple[Message, ...] = (),
    forced_tool_name: str | None = None,
):
    """Factory: build a render hook for Layer-1 classes.

    The hook resolves the mutator's output dict into:
      - ``messages``: chat turns to send (user/system/assistant/tool)
      - ``tools``: poisoned tool definitions
      - ``resources``: poisoned MCP-style resources
    """

    def render(seed: Seed, rendered: dict[str, Any], canaries: CanarySet) -> dict[str, Any]:
        messages: list[Message] = list(extra_messages_before)
        if "messages" in rendered and rendered["messages"]:
            messages.extend(rendered["messages"])
        else:
            text_template = rendered.get("template", seed.template)
            text = text_template.replace("{canary}", canaries.primary)
            for k, options in seed.placeholders.items():
                text = text.replace("{" + k + "}", str(options[0]))
            messages.append(Message(role="user", content=text or default_user_prompt))
        messages.extend(extra_messages_after)

        tools: list[ToolSpec] = []
        if "_schema_tool" in rendered:
            spec_dict = copy.deepcopy(rendered["_schema_tool"])
            spec_dict = deep_format_canary(spec_dict, canaries.primary)
            tool_name = (
                forced_tool_name or spec_dict.get("name") or seed.meta.get("tool_template", {}).get("name", "tool")
            )
            tools.append(
                ToolSpec(
                    name=tool_name,
                    description=spec_dict.get("description", "") or "",
                    parameters_schema=spec_dict.get("parameters") or {"type": "object"},
                    annotations=spec_dict.get("annotations", {}),
                )
            )

        if "_extra_tools" in rendered:
            for t in rendered["_extra_tools"]:
                tools.append(
                    ToolSpec(
                        name=t["name"],
                        description=deep_format_canary(t.get("description", ""), canaries.primary),
                        parameters_schema=deep_format_canary(
                            t.get("parameters_schema", {"type": "object"}), canaries.primary
                        ),
                        annotations=t.get("annotations", {}),
                    )
                )

        resources: list[ResourceSpec] = []
        if "_resources" in rendered:
            for r in rendered["_resources"]:
                resources.append(
                    ResourceSpec(
                        uri=r["uri"],
                        mime_type=r.get("mime_type", "text/plain"),
                        description=deep_format_canary(r.get("description", ""), canaries.primary),
                        payload_b64=r.get("payload_b64", ""),
                        annotations=r.get("annotations", {}),
                    )
                )

        return {
            "messages": tuple(messages),
            "tools": tuple(tools),
            "resources": tuple(resources),
            "rag_corpus": tuple(rendered.get("rag_corpus", ())),
        }

    return render


def make_generator(
    *,
    seeds: tuple[Seed, ...],
    mutators: tuple[Mutator, ...],
    seed_value: int,
    render,
    matcher_ids: tuple[str, ...] = ("canary-echo", "behavioral-drift", "state-machine"),
    max_variants: int = 25_000,
    recon: ReconProfile | None = None,
) -> Generator:
    """Build a Generator with the given seeds + mutator chain."""
    chain = (CompositeMutator(*mutators),) if len(mutators) > 1 else mutators
    return Generator(
        seeds=seeds,
        mutators=chain,
        seed_value=seed_value,
        render=render,
        matcher_ids=matcher_ids,
        max_variants=max_variants,
        recon=recon,
    )


def base_tool_schema(*, kind: str = "search") -> dict[str, Any]:
    """A small set of base parameter schemas the schema-mutator can deform."""
    if kind == "search":
        return {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "search query"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "include_archived": {"type": "boolean"},
            },
            "required": ["query"],
        }
    if kind == "filesystem":
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "mode": {"type": "string", "enum": ["read", "write", "append"]},
                "encoding": {"type": "string", "default": "utf-8"},
            },
            "required": ["path"],
        }
    if kind == "http":
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                "body": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            },
            "required": ["url", "method"],
        }
    if kind == "shell":
        return {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout": {"type": "integer"},
                "working_dir": {"type": "string"},
            },
            "required": ["command"],
        }
    if kind == "database":
        return {
            "type": "object",
            "properties": {
                "sql": {"type": "string"},
                "params": {"type": "array", "items": {"type": "string"}},
                "readonly": {"type": "boolean", "default": True},
            },
            "required": ["sql"],
        }
    if kind == "email":
        return {
            "type": "object",
            "properties": {
                "to": {"type": "string", "format": "email"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "body"],
        }
    if kind == "calendar":
        return {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
            },
            "required": ["title", "start"],
        }
    if kind == "crm":
        return {
            "type": "object",
            "properties": {
                "contact_id": {"type": "string"},
                "field": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["contact_id", "field"],
        }
    if kind == "ticket":
        return {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "body": {"type": "string"},
                "priority": {"type": "string", "enum": ["low", "med", "high"]},
            },
            "required": ["title"],
        }
    if kind == "vector":
        return {
            "type": "object",
            "properties": {
                "vector": {"type": "array", "items": {"type": "number"}},
                "k": {"type": "integer", "minimum": 1},
                "namespace": {"type": "string"},
            },
            "required": ["vector"],
        }
    raise ValueError(f"unknown base_tool_schema kind: {kind}")


BASE_KINDS: tuple[str, ...] = (
    "search",
    "filesystem",
    "http",
    "shell",
    "database",
    "email",
    "calendar",
    "crm",
    "ticket",
    "vector",
)


def render_message_seed(seed: Seed, canary: str) -> str:
    """Format a seed.template with canary + first-option placeholders."""
    text = seed.template.replace("{canary}", canary)
    for k, options in seed.placeholders.items():
        text = text.replace("{" + k + "}", str(options[0]))
    return text


def jsonify_for_log(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str, indent=2)
    except Exception:  # noqa: BLE001
        return repr(obj)
