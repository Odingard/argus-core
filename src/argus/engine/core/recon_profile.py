"""Recon profile — consolidated harvest from active + passive recon and
prior-layer findings.

A ``ReconProfile`` is a frozen, hashable bundle of artefacts that have been
harvested about a target before any seed is fired. The profile is supplied
to the Generator (and to opt-in mutators) so seeds can be parameterised
against the *specific* target rather than fired as universal templates.

Design contract:

* All fields are tuples of strings. Order is significant for determinism —
  the first artefact in a tuple is the canonical fallback when only one
  slot is available.
* Every artefact is sanitised on intake: control characters stripped, length
  capped at ``_MAX_ARTEFACT_LEN`` characters, deduplicated. This is the
  defence against a target poisoning recon with adversarial strings that
  would alter the variant pipeline if substituted verbatim.
* The profile is hashable and ``__eq__``-comparable, so the
  ``(seed_value, ReconProfile)`` pair fully determines the variant set
  produced by ``Generator.generate()``.
* Three loaders produce profiles from canonical sources:
  ``from_manifest`` (active MCP recon), ``from_surface`` (passive recon),
  ``from_findings_jsonl`` (prior-layer extraction harvest).
* Profiles compose via ``merge`` so a supervisor can fold artefacts from
  multiple sources into a single profile per engagement.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_MAX_ARTEFACT_LEN = 200
"""Hard cap on a single artefact string after sanitisation."""

_MAX_ARTEFACTS_PER_FIELD = 64
"""Hard cap on artefact count per field after dedup."""

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_FIELDS: tuple[str, ...] = (
    "tool_names",
    "tool_descriptions",
    "tool_parameter_keys",
    "resource_uris",
    "resource_descriptions",
    "prompt_names",
    "framework_hints",
    "transport_hints",
    "system_prompt_fragments",
    "persona_fragments",
    "rag_citations",
    "rag_corpus_excerpts",
    "auth_boundary_keys",
    "agent_role_names",
    "agent_envelope_styles",
    "leaked_credentials",
    # Phase K — MCP-specific recon slots.
    "manifest_hashes",
    "agent_cards",
    "delegation_endpoints",
    "a2a_token_format",
    "memory_writers",
    "rag_endpoints",
    "citation_format",
)


def _sanitise(value: Any) -> str:
    """Truncate + strip control chars from an artefact string."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    cleaned = _CONTROL_CHARS.sub("", text).strip()
    return cleaned[:_MAX_ARTEFACT_LEN]


def _normalise(values: Iterable[Any]) -> tuple[str, ...]:
    """Sanitise + dedupe + cap an iterable of strings.

    Order of first appearance is preserved for determinism. Empty strings
    are dropped silently.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for v in values:
        s = _sanitise(v)
        if not s:
            continue
        if s in seen_set:
            continue
        seen.append(s)
        seen_set.add(s)
        if len(seen) >= _MAX_ARTEFACTS_PER_FIELD:
            break
    return tuple(seen)


@dataclass(frozen=True, slots=True)
class ReconProfile:
    """Consolidated recon harvest used to parameterise seeds.

    Every field is a tuple of sanitised strings (so the dataclass is hashable)
    plus two scalar metadata fields.
    """

    tool_names: tuple[str, ...] = ()
    tool_descriptions: tuple[str, ...] = ()
    tool_parameter_keys: tuple[str, ...] = ()
    resource_uris: tuple[str, ...] = ()
    resource_descriptions: tuple[str, ...] = ()
    prompt_names: tuple[str, ...] = ()
    framework_hints: tuple[str, ...] = ()
    transport_hints: tuple[str, ...] = ()
    system_prompt_fragments: tuple[str, ...] = ()
    persona_fragments: tuple[str, ...] = ()
    rag_citations: tuple[str, ...] = ()
    rag_corpus_excerpts: tuple[str, ...] = ()
    auth_boundary_keys: tuple[str, ...] = ()
    agent_role_names: tuple[str, ...] = ()
    agent_envelope_styles: tuple[str, ...] = ()
    leaked_credentials: tuple[str, ...] = ()
    """Credentials surfaced by Layer-4 ext-credential-leak.

    Phase C harvests this slot from canary-bearing API key / token /
    JWT / connection-string responses. Phase E
    (tp-credential-exercise) consumes it to render tool calls that
    actually exercise the leaked secret. Storing it on ``ReconProfile``
    rather than at runtime keeps the chain synthesizer's beam search
    deterministic — the slot participates in the same
    ``valid_heads``/``successors`` machinery every other artefact uses.
    """
    # Phase K — MCP-specific recon slots populated by extended
    # ``from_manifest`` and consumed by ``tp-mcp-supply-chain``,
    # ``mas-a2a-token-replay`` and ``ci-tool-result-rag-feedback``.
    manifest_hashes: tuple[str, ...] = ()
    """SHA-256 prefix (16 hex chars) per tool's ``parameters_schema``.

    The introspector derives this deterministically from the recon
    snapshot so supply-chain mutators can compare manifest-time vs
    call-time hashes (``tp-mcp-supply-chain``). Storing the digest on
    the recon profile keeps the chain synthesizer's plausibility
    gate deterministic per AGENTS.md rule #7.
    """
    agent_cards: tuple[str, ...] = ()
    """Names / identifiers of agent cards announced by the target.

    Sourced from A2A protocol envelopes (``server_info.agent_card`` /
    ``server_info.cards``) when present, plus any ``annotations.card_id``
    declared on a tool. Consumed by ``mas-a2a-token-replay`` for
    agent-card spoofing variants.
    """
    delegation_endpoints: tuple[str, ...] = ()
    """Tool / resource URIs that look like A2A delegation handoffs.

    Detected by name heuristics (``delegate``, ``handoff``, ``forward``,
    ``escalate``) plus explicit ``annotations.kind=delegation`` flags.
    Consumed by ``mas-a2a-token-replay`` for delegation-depth abuse and
    confused-deputy variants.
    """
    a2a_token_format: tuple[str, ...] = ()
    """Authentication / token format hints (``bearer``, ``jwt``,
    ``oauth2-rfc8693``, ``agent-card-bound``) extracted from
    ``server_info.auth`` and per-tool ``annotations.auth_format``.
    Consumed by ``mas-a2a-token-replay`` for token-binding mismatch
    and expired-credential tolerance variants.
    """
    memory_writers: tuple[str, ...] = ()
    """Tools that look like they write to the agent's long-term memory.

    Detected by name heuristics (``remember``, ``memory.save``,
    ``persist``, ``store_fact``, ``upsert``). Consumed by
    ``ci-tool-result-rag-feedback`` for tool-output-driven memory
    injection variants and cross-session carryover variants (the
    latter pairs with Phase J's ``EngagementMemory``).
    """
    rag_endpoints: tuple[str, ...] = ()
    """Tools / resources that look like retrieval / index endpoints.

    Detected by name heuristics (``search``, ``retrieve``, ``query``,
    ``index``, ``embed``, ``rag``) plus ``annotations.kind=rag``.
    Consumed by ``ci-tool-result-rag-feedback`` for runtime
    tool-output → RAG-index poison variants.
    """
    citation_format: tuple[str, ...] = ()
    """Citation / attribution format hints used by the agent.

    Extracted from ``server_info.citation_format`` if declared, or
    inferred from observed assistant-reply citation styles (``[n]``,
    ``[source: ...]``, ``(see ...)``, ``<cite ...>``). Consumed by
    ``ci-tool-result-rag-feedback`` for citation-attribution spoofing.
    """
    source_path: str = ""
    captured_at: str = ""

    def is_empty(self) -> bool:
        """True iff every artefact field is empty (metadata fields ignored)."""
        return not any(getattr(self, f) for f in _FIELDS)

    def get(self, field_name: str) -> tuple[str, ...]:
        """Return the artefact tuple for a field name, ``()`` if unknown."""
        if field_name not in _FIELDS:
            return ()
        value = getattr(self, field_name)
        return value if isinstance(value, tuple) else ()

    def merge(self, other: ReconProfile) -> ReconProfile:
        """Return a new profile combining artefacts from ``self + other``.

        Per-field union; later-occurring duplicates are dropped (idempotent on
        identical inputs).
        """
        kwargs: dict[str, Any] = {}
        for f in _FIELDS:
            kwargs[f] = _normalise(getattr(self, f) + getattr(other, f))
        kwargs["source_path"] = self.source_path or other.source_path
        kwargs["captured_at"] = other.captured_at or self.captured_at
        return ReconProfile(**kwargs)

    @classmethod
    def empty(cls) -> ReconProfile:
        return cls()

    @classmethod
    def from_manifest(cls, manifest: Any) -> ReconProfile:
        """Build a profile from an MCP ``TargetManifest``."""
        if manifest is None:
            return cls()
        tools = tuple(getattr(manifest, "tools", ()) or ())
        resources = tuple(getattr(manifest, "resources", ()) or ())
        prompts = tuple(getattr(manifest, "prompts", ()) or ())
        server_info = getattr(manifest, "server_info", None) or {}
        param_keys: list[str] = []
        manifest_hashes: list[str] = []
        agent_cards: list[str] = []
        delegation_endpoints: list[str] = []
        a2a_token_format: list[str] = []
        memory_writers: list[str] = []
        rag_endpoints: list[str] = []
        for t in tools:
            schema = getattr(t, "parameters_schema", None)
            if isinstance(schema, dict):
                props = schema.get("properties")
                if isinstance(props, dict):
                    param_keys.extend(props.keys())
            t_name = getattr(t, "name", "") or ""
            annotations = getattr(t, "annotations", None) or {}
            digest = _hash_tool_manifest(t_name, schema, annotations)
            if digest:
                manifest_hashes.append(f"{t_name}={digest}")
            card_id = annotations.get("card_id") if isinstance(annotations, dict) else None
            if card_id:
                agent_cards.append(str(card_id))
            kind = annotations.get("kind") if isinstance(annotations, dict) else None
            if isinstance(kind, str) and kind.lower() in {"delegation", "handoff"} or _looks_like_delegation(t_name):
                delegation_endpoints.append(t_name)
            if isinstance(annotations, dict):
                auth_fmt = annotations.get("auth_format")
                if auth_fmt:
                    a2a_token_format.append(str(auth_fmt))
            if _looks_like_memory_writer(t_name):
                memory_writers.append(t_name)
            if (isinstance(kind, str) and kind.lower() == "rag") or _looks_like_rag_endpoint(t_name):
                rag_endpoints.append(t_name)
        if isinstance(server_info, dict):
            card_info = server_info.get("agent_card") or server_info.get("cards")
            if isinstance(card_info, str):
                agent_cards.append(card_info)
            elif isinstance(card_info, list | tuple):
                agent_cards.extend(str(c) for c in card_info if c)
            elif isinstance(card_info, dict) and card_info.get("name"):
                agent_cards.append(str(card_info["name"]))
            auth_info = server_info.get("auth")
            if isinstance(auth_info, str):
                a2a_token_format.append(auth_info)
            elif isinstance(auth_info, dict):
                fmt = auth_info.get("format") or auth_info.get("type")
                if fmt:
                    a2a_token_format.append(str(fmt))
            citation_fmt = server_info.get("citation_format")
            citation_seeds: list[str] = []
            if isinstance(citation_fmt, str):
                citation_seeds.append(citation_fmt)
            elif isinstance(citation_fmt, list | tuple):
                citation_seeds.extend(str(c) for c in citation_fmt if c)
        else:
            citation_seeds = []
        # Pick up resource URIs that look like delegation / rag endpoints
        # too — A2A delegation is sometimes exposed as a resource rather
        # than a tool.
        for r in resources:
            r_uri = getattr(r, "uri", "") or ""
            r_anns = getattr(r, "annotations", None) or {}
            r_kind = r_anns.get("kind") if isinstance(r_anns, dict) else None
            if isinstance(r_kind, str) and r_kind.lower() in {"delegation", "handoff"} or _looks_like_delegation(r_uri):
                delegation_endpoints.append(r_uri)
            if (isinstance(r_kind, str) and r_kind.lower() == "rag") or _looks_like_rag_endpoint(r_uri):
                rag_endpoints.append(r_uri)
        return cls(
            tool_names=_normalise(getattr(t, "name", "") for t in tools),
            tool_descriptions=_normalise(getattr(t, "description", "") for t in tools),
            tool_parameter_keys=_normalise(param_keys),
            resource_uris=_normalise(getattr(r, "uri", "") for r in resources),
            resource_descriptions=_normalise(getattr(r, "description", "") for r in resources),
            prompt_names=_normalise(getattr(p, "name", "") for p in prompts),
            transport_hints=_normalise([getattr(manifest, "transport", "")]),
            manifest_hashes=_normalise(manifest_hashes),
            agent_cards=_normalise(agent_cards),
            delegation_endpoints=_normalise(delegation_endpoints),
            a2a_token_format=_normalise(a2a_token_format),
            memory_writers=_normalise(memory_writers),
            rag_endpoints=_normalise(rag_endpoints),
            citation_format=_normalise(citation_seeds),
            source_path="manifest",
            captured_at=datetime.now(UTC).isoformat(),
        )

    @classmethod
    def from_surface(cls, surface: Any) -> ReconProfile:
        """Build a profile from a passive recon ``SurfaceMap``-shaped object."""
        if surface is None:
            return cls()
        return cls(
            framework_hints=_normalise(getattr(surface, "framework_hints", ()) or ()),
            transport_hints=_normalise(getattr(surface, "transports", ()) or ()),
            tool_names=_normalise(getattr(surface, "tool_names", ()) or ()),
            agent_role_names=_normalise(getattr(surface, "agent_role_names", ()) or ()),
            source_path="surface",
            captured_at=datetime.now(UTC).isoformat(),
        )

    @classmethod
    def from_findings_jsonl(cls, path: str | Path) -> ReconProfile:
        """Build a profile from a JSONL findings file produced by the supervisor.

        Walks ``type=finding`` rows and extracts artefacts based on
        ``attack_class``. Lines that fail to parse are skipped; missing files
        produce an empty profile.
        """
        p = Path(path)
        if not p.exists():
            return cls()
        sys_prompt: list[str] = []
        personas: list[str] = []
        rag_excerpts: list[str] = []
        rag_cites: list[str] = []
        auth_keys: list[str] = []
        roles: list[str] = []
        envelopes: list[str] = []
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("type") != "finding":
                    continue
                ev = row.get("evidence") or {}
                frag = ev.get("fragment") or ""
                klass = row.get("attack_class", "") or ""
                if klass == "ext-system-prompt-leak":
                    sys_prompt.append(frag)
                    persona = _first_persona(frag)
                    if persona:
                        personas.append(persona)
                elif klass == "ext-rag-corpus-leak":
                    rag_excerpts.append(frag)
                    rag_cites.extend(_extract_citations(frag))
                elif klass == "ext-auth-boundary-leak":
                    auth_keys.extend(_extract_auth_keys(frag))
                elif klass.startswith("mas-"):
                    roles.extend(_extract_role_names(frag))
                    style = (row.get("metadata") or {}).get("envelope_style")
                    if style:
                        envelopes.append(str(style))
        return cls(
            system_prompt_fragments=_normalise(sys_prompt),
            persona_fragments=_normalise(personas),
            rag_corpus_excerpts=_normalise(rag_excerpts),
            rag_citations=_normalise(rag_cites),
            auth_boundary_keys=_normalise(auth_keys),
            agent_role_names=_normalise(roles),
            agent_envelope_styles=_normalise(envelopes),
            source_path=str(p),
            captured_at=datetime.now(UTC).isoformat(),
        )


_PERSONA_RE = re.compile(r"\b([A-Z][A-Za-z0-9]+(?:Bot|Agent|Assistant|GPT|AI))\b")
_CITATION_RE = re.compile(r"\[([^\[\]\n]{1,80})\]")
_AUTH_KEY_RE = re.compile(r"\b(role|username|user_id|scope|tenant|org_id|auth)\b\s*[:=]\s*([\w@.\-]+)")
_ROLE_NAME_RE = re.compile(
    r"\b(supervisor|router|planner|executor|judge|reviewer|critic|worker|coordinator)\b",
    re.IGNORECASE,
)


def _first_persona(text: str) -> str:
    if not text:
        return ""
    m = _PERSONA_RE.search(text)
    return m.group(1) if m else ""


def _extract_citations(text: str) -> list[str]:
    return _CITATION_RE.findall(text or "")


def _extract_auth_keys(text: str) -> list[str]:
    return [f"{k}={v}" for k, v in _AUTH_KEY_RE.findall(text or "")]


def _extract_role_names(text: str) -> list[str]:
    return [m.lower() for m in _ROLE_NAME_RE.findall(text or "")]


# ---------------------------------------------------------------------------
# Phase K — MCP recon helpers
#
# These helpers populate the supply-chain / A2A / RAG-feedback slots from
# the introspected ``TargetManifest``. They are pure and deterministic
# (AGENTS.md rule #7) — same input → same output, no clock / network /
# RNG reads.
# ---------------------------------------------------------------------------


_DELEGATION_HINTS: tuple[str, ...] = (
    "delegate",
    "handoff",
    "hand_off",
    "forward_to",
    "forward",
    "escalate",
    "route_to",
    "dispatch_to",
    "transfer_to",
)

_MEMORY_WRITER_HINTS: tuple[str, ...] = (
    "remember",
    "memory.save",
    "memory_save",
    "memory.write",
    "memory_write",
    "persist",
    "store_fact",
    "store_note",
    "upsert",
    "save_memory",
    "save_note",
    "append_memory",
)

_RAG_ENDPOINT_HINTS: tuple[str, ...] = (
    "search",
    "retrieve",
    "query",
    "index",
    "embed",
    "rag",
    "lookup",
    "vector_search",
    "knowledge_lookup",
    "kb_search",
)


def _hash_tool_manifest(name: str, schema: Any, annotations: Any) -> str:
    """Deterministic 16-hex SHA-256 prefix of ``(name, schema, annotations)``.

    Used by ``tp-mcp-supply-chain`` to detect manifest-time vs call-time
    drift. The hash is stable across runs (rule #7) and short enough to
    fit into a recon-profile slot without truncation.
    """
    try:
        payload = json.dumps(
            {
                "name": name,
                "schema": schema if isinstance(schema, dict) else {},
                "annotations": annotations if isinstance(annotations, dict) else {},
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError):
        return ""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _name_matches(name: str, hints: tuple[str, ...]) -> bool:
    if not name:
        return False
    lowered = name.lower()
    return any(h in lowered for h in hints)


def _looks_like_delegation(name: str) -> bool:
    return _name_matches(name, _DELEGATION_HINTS)


def _looks_like_memory_writer(name: str) -> bool:
    return _name_matches(name, _MEMORY_WRITER_HINTS)


def _looks_like_rag_endpoint(name: str) -> bool:
    return _name_matches(name, _RAG_ENDPOINT_HINTS)


_ = field  # keep unused-import linter quiet on dataclass.field re-export
