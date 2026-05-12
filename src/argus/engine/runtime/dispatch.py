"""Phase M — autonomous transport dispatch (``--transport auto``).

AGENTS.md rule #1: real autonomous red-team capabilities only. A real
operator never types ``--transport openai`` vs ``--transport argt``;
they just point ARGUS at a target and the engine figures it out.

Heuristic, deterministic, side-effect-free:

* If ``target`` looks like an HTTP(S) URL, the engagement is against a
  hosted endpoint:

  * if the URL path contains ``mcp`` / ``rpc`` / ``messages`` or the
    host looks MCP-shaped, we declare it MCP-capable. Recon is then
    expected to perform the actual JSON-RPC introspection (see
    :mod:`argus.engine.recon.mcp_introspect`); the transport itself
    stays ``argt`` because every variant fire is still an HTTP POST
    of the rendered chat payload.
  * otherwise it's a plain HTTP chat target → ``argt``.

* If ``target`` looks like a model identifier, we route to the
  matching provider transport:

  * ``claude*`` / ``anthropic.*`` → ``anthropic``;
  * ``llama*`` / ``mistral*`` / ``qwen*`` / ``phi*`` / contains ``::``
    or ``/`` (Ollama tag convention) → ``ollama``;
  * everything else → ``openai`` (gpt-*, o*, default).

The decision is reported as a structured :class:`DispatchDecision` so
the CLI can echo a transparent banner and emit the choice as an
``engagement_started`` event (downstream consumers — including the
Phase M reporting layer — pull ``transport`` directly off that
event, AGENTS.md rule #9).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

# Provider transports the dispatcher is allowed to choose.
VALID_TRANSPORTS: Final[tuple[str, ...]] = ("openai", "anthropic", "ollama", "argt")

# Substrings that strongly imply MCP / JSON-RPC chat surfaces.
_MCP_PATH_HINTS: Final[tuple[str, ...]] = ("mcp", "rpc", "messages", "jsonrpc")

# Model-id prefixes that select a non-OpenAI provider transport.
_ANTHROPIC_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^claude[-_.]"),
    re.compile(r"^anthropic[./:]"),
)
_OLLAMA_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^llama[-_.0-9]"),
    re.compile(r"^mistral[-_.0-9]"),
    re.compile(r"^qwen[-_.0-9]"),
    re.compile(r"^phi[-_.0-9]"),
    re.compile(r"^gemma[-_.0-9]"),
    re.compile(r"^codellama"),
    re.compile(r"^.+::.+"),  # ollama tag form (model::tag)
)


@dataclass(frozen=True, slots=True)
class DispatchDecision:
    """The dispatcher's transport + recon strategy choice.

    Fields are deliberately small and primitive so the decision can be
    serialised verbatim into a JSONL ``engagement_started`` event
    (deterministic per rule #7 — same target string in, same decision
    out, always).
    """

    transport: str
    """Resolved transport name from :data:`VALID_TRANSPORTS`."""
    mcp_capable: bool
    """True iff the dispatcher believes the target speaks MCP /
    JSON-RPC and recon should attempt :func:`introspect_http`."""
    target_kind: str
    """Either ``"url"`` or ``"model_id"`` — what the dispatcher saw."""
    reason: str
    """Single-line, human-readable rationale. Mirrored into the JSONL
    audit trail so AGENTS.md rule #9 holds even when the choice is
    surprising."""


def auto_dispatch(target: str) -> DispatchDecision:
    """Project a free-form ``--target`` string into a transport plan.

    Pure function: no I/O, no clock, no env. Identical inputs always
    produce identical decisions (rule #7).
    """
    target_norm = (target or "").strip()
    if not target_norm:
        return DispatchDecision(
            transport="openai",
            mcp_capable=False,
            target_kind="model_id",
            reason="empty target — defaulting to openai transport",
        )

    parsed = urlparse(target_norm)
    is_url = parsed.scheme in ("http", "https") and bool(parsed.netloc)

    if is_url:
        path = (parsed.path or "").lower()
        host = (parsed.hostname or "").lower()
        mcp_capable = any(hint in path for hint in _MCP_PATH_HINTS) or any(hint in host for hint in _MCP_PATH_HINTS)
        reason = (
            "URL target — JSON-RPC / MCP path hints found, recon will introspect"
            if mcp_capable
            else "URL target — no MCP path hints, treating as raw HTTP chat surface"
        )
        return DispatchDecision(
            transport="argt",
            mcp_capable=mcp_capable,
            target_kind="url",
            reason=reason,
        )

    # Treat as a provider model id.
    lower = target_norm.lower()
    if any(pat.match(lower) for pat in _ANTHROPIC_PATTERNS):
        return DispatchDecision(
            transport="anthropic",
            mcp_capable=False,
            target_kind="model_id",
            reason=f"model id {target_norm!r} matches anthropic pattern",
        )
    if any(pat.match(lower) for pat in _OLLAMA_PATTERNS):
        return DispatchDecision(
            transport="ollama",
            mcp_capable=False,
            target_kind="model_id",
            reason=f"model id {target_norm!r} matches ollama / open-weights pattern",
        )
    return DispatchDecision(
        transport="openai",
        mcp_capable=False,
        target_kind="model_id",
        reason=f"model id {target_norm!r} routed to openai (default)",
    )
