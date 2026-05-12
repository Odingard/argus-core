"""Variant — the unit of execution.

A ``Variant`` is what gets sent to a target. It carries:
- the rendered payload (string or structured tool definition / RAG corpus)
- the canary set used to detect success
- structural matchers used to grade the response
- metadata describing the seed + mutator chain that produced it

Variants are content-hashed by ``variant_id`` so they're trivially
deduplicable across generator runs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .canary import CanarySet
from .types import Role


@dataclass(frozen=True, slots=True)
class Message:
    role: Role
    content: str
    name: str | None = None


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Tool description carried by a variant when the attack ships as a tool def."""

    name: str
    description: str
    parameters_schema: dict[str, Any]
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    """MCP-style resource carried as part of an attack."""

    uri: str
    mime_type: str
    description: str
    payload_b64: str = ""
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Variant:
    """A concrete attack instance ready to be dispatched."""

    variant_id: str
    seed_id: str
    attack_class: str
    layer: str
    messages: tuple[Message, ...]
    tools: tuple[ToolSpec, ...] = ()
    resources: tuple[ResourceSpec, ...] = ()
    rag_corpus: tuple[str, ...] = ()
    canaries: CanarySet | None = None
    matcher_ids: tuple[str, ...] = ()
    mutator_chain: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    carrier_surface: str = "user_turn"
    """Phase P — which carrier surface the variant rides into the target.

    One of ``user_turn`` (default, direct delivery on the user role),
    ``tool_result`` (planted into a tool-call response the target
    consumes), ``rag_document`` (planted into a retrieval corpus),
    ``roleplay_persona`` (planted into a system-role persona prompt),
    or ``system_reflection`` (planted into a reflected metadata
    field the target reads as authoritative).

    Layers / classes that have not opted into carrier rendering keep
    ``user_turn`` so existing dispatch is bit-for-bit unchanged
    (AGENTS.md rule #7 — deterministic backwards compatibility).
    """


def hash_variant(
    *,
    seed_id: str,
    mutator_chain: tuple[str, ...],
    rendered: dict[str, Any],
) -> str:
    """Stable content hash for a variant, used as ``variant_id``."""
    blob = json.dumps(
        {"seed": seed_id, "mutators": list(mutator_chain), "rendered": rendered},
        sort_keys=True,
        default=str,
    ).encode()
    return hashlib.blake2b(blob, digest_size=12).hexdigest()
