"""
argus.personas — specialist offensive personas (Raptor pattern).

Each persona is a short system-prompt bias + preferred vuln classes +
confidence tuning. Agents opt in by setting ``PERSONA = "name"`` on the
class. ``get_persona(name)`` returns a dict the agent can inject into
its Haiku/Opus prompts so the specialist flavor rides along.

Seeds (loose archetypes, not namesakes — we follow the No Competitor
Names rule but keep recognizable specialist flavors):

    auditor      — deep source read, multi-file flows, reachability
    reverser     — pattern recognition on opaque blobs, protocol oddities
    fuzzer       — edge cases, encoding boundaries, parser confusion
    chainer      — multi-step composition, trust-boundary hops
    protocoler   — wire format abuse, framing, sequence attacks

Custom personas drop in without code changes via ``register_persona(...)``.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Persona:
    name:                 str
    system_bias:          str
    preferred_classes:    tuple[str, ...]
    confidence_nudge:     float = 0.0   # added to score for preferred classes
    severity_floor:       str = "MEDIUM"


# ── Ship-seeded personas ──────────────────────────────────────────────────────

_SEEDS: dict[str, Persona] = {
    "auditor": Persona(
        name="auditor",
        system_bias=(
            "You are a senior code auditor. Read deeply across files, "
            "trace data flow from entry points to sinks, and insist on "
            "reachability evidence. If you cannot cite the source path "
            "that exposes the sink, the finding is not yet valid."
        ),
        preferred_classes=(
            "DESER", "AUTH_BYPASS", "TRACE_LATERAL", "EXCESSIVE_AGENCY",
        ),
        confidence_nudge=0.05,
    ),
    "reverser": Persona(
        name="reverser",
        system_bias=(
            "You are a reverse engineer. Look for patterns in generated "
            "code, fingerprintable framework quirks, and implicit assumptions "
            "the framework makes that an attacker can subvert. Prefer "
            "structural flaws over instance bugs."
        ),
        preferred_classes=(
            "MODEL_EXTRACTION", "PHANTOM_MEMORY", "MESH_TRUST",
        ),
        confidence_nudge=0.03,
    ),
    "fuzzer": Persona(
        name="fuzzer",
        system_bias=(
            "You are an offensive fuzzer. Target encoding boundaries, "
            "parser confusion, JSON-schema edge cases, and tokenizer "
            "boundaries. Your priors favor payloads that survive "
            "normalization and filtering."
        ),
        preferred_classes=(
            "RACE_CONDITION", "PROMPT_INJECTION", "PROTO_INJECT",
        ),
        confidence_nudge=0.04,
    ),
    "chainer": Persona(
        name="chainer",
        system_bias=(
            "You are a multi-step exploit composer. A single finding is "
            "rarely interesting; what matters is whether finding A makes "
            "finding B reachable. Every claim you promote must include "
            "an explicit hop diagram."
        ),
        preferred_classes=(
            "TRUST_ESCALATION", "HANDOFF_BOUNDARY", "ORCHESTRATION_DRIFT",
        ),
        confidence_nudge=0.06,
        severity_floor="HIGH",
    ),
    "protocoler": Persona(
        name="protocoler",
        system_bias=(
            "You are a protocol-layer specialist. MCP, JSON-RPC, SSE, "
            "WebSocket framing, batch-request ordering, progress-token "
            "correlation — these are your stomping grounds."
        ),
        preferred_classes=(
            "AUTH_BYPASS", "PROTO_INJECT", "PHANTOM_MEMORY",
        ),
        confidence_nudge=0.04,
    ),
}


# ── Public API ────────────────────────────────────────────────────────────────

def get_persona(name: str) -> Persona | None:
    return _SEEDS.get(name.lower()) if name else None


def persona_prompt_prefix(persona_name: str) -> str:
    """
    Short prefix to prepend to an agent's Haiku/Opus prompt. Empty string
    when the persona is unknown, so agents without a persona (or typos)
    degrade silently to the base behaviour.
    """
    p = get_persona(persona_name)
    if not p:
        return ""
    return f"[PERSONA: {p.name}]\n{p.system_bias}\n\n"
