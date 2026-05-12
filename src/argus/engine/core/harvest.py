"""Deterministic harvest helpers — structural extraction from a probe.

A class that participates in chain composition (i.e. has non-empty
``ChainNode.produces``) registers a ``harvest`` callable on its
``AttackClass``. The callable consumes a confirmed-landed
``ProbeResult`` and returns a dict keyed on ``ReconProfile`` field
names. The chain runner then merges those tuples into the running
``ChainContext`` via ``ReconProfile.merge`` (PR #13).

These helpers are deterministic — same probe → same artefacts every
time. No LLM calls, no randomness, no I/O. The structural patterns
mirror the matchers already shipped under ``argus.engine.grading``;
``harvest`` is the inverse of "did this land" — given that a finding
landed, what concrete artefacts can be lifted out of the response?

Length / control-character / dedup hardening is centralised in
``ReconProfile._normalise``; harvesters return raw tuples and the
merge step downstream sanitises everything in one place.
"""

from __future__ import annotations

import re

# Module-level patterns are precompiled once and reused across every
# harvest call so per-probe overhead stays minimal.
_PERSONA_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"You are\s+(?:an?\s+)?([A-Z][\w\- ]{2,80})"),
    re.compile(r"persona[:=]\s*['\"]?([\w\- ]{2,80})['\"]?", re.IGNORECASE),
    re.compile(r"name\s*[:=]\s*['\"]([\w\- ]{2,80})['\"]"),
    re.compile(r"role[:=]\s*['\"]?([\w\- ]{2,80})['\"]?", re.IGNORECASE),
)

_FRAMEWORK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(LangChain|LangGraph|CrewAI|AutoGen|LlamaIndex|"
        r"OpenAI Assistants?|Anthropic Claude|Ollama|"
        r"Cloudflare Workers AI|FastAPI|MCP|Model Context Protocol)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"runtime\s*[:=]\s*['\"]?([\w\-\. ]{3,40})['\"]?",
        re.IGNORECASE,
    ),
)

_TOOL_NAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"['\"]name['\"]\s*:\s*['\"]([A-Za-z][\w\-.]{1,60})['\"]"),
    re.compile(
        r"\btool[:\s]+([A-Za-z][\w\-.]{1,60})\b",
        re.IGNORECASE,
    ),
    re.compile(r"@mcp\.tool[(\s]+name\s*=\s*['\"]([\w\-.]{1,60})['\"]"),
    re.compile(r"^\s*-\s*([a-z][\w\-]{1,60})\s*[:\-]", re.MULTILINE),
)

_PARAM_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"['\"]([A-Za-z_][\w]{0,40})['\"]\s*:\s*\{\s*['\"]type['\"]"),
    re.compile(r"\bparameters?[:\s]+([A-Za-z_]\w{0,40})\b", re.IGNORECASE),
    re.compile(r"required[:\s]*\[\s*([\"\'\w\s,]+?)\s*\]"),
)

_RAG_CITATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\[(\d{1,3})\]"),
    re.compile(r"\[source[:\s]?([\w\-\./]+)\]", re.IGNORECASE),
    re.compile(r"\[doc[:\s]?([\w\-\./]+)\]", re.IGNORECASE),
    re.compile(r"\bcitation[:\s]+([\w\-\./]{2,80})", re.IGNORECASE),
)

_RAG_EXCERPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Quoted blocks of >= 24 chars are excerpt candidates.
    re.compile(r'["\u201c]([^"\u201d]{24,400})["\u201d]'),
    re.compile(r"```(?:text|markdown|md)?\s*([^`]{24,400})```", re.DOTALL),
    re.compile(r"^>\s+(.{24,400})$", re.MULTILINE),
)

_AGENT_ROLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:agent|sub[- ]?agent|worker|crew|node|tool[- ]?caller)\s*"
        r"[:=]?\s*['\"]?([\w\- ]{2,40})['\"]?",
        re.IGNORECASE,
    ),
    re.compile(r"role\s*[:=]\s*['\"]([\w\- ]{2,40})['\"]"),
    re.compile(r"node_id\s*[:=]\s*['\"]([\w\-]{2,40})['\"]"),
)


def _collect(
    patterns: tuple[re.Pattern[str], ...],
    text: str,
    *,
    cap: int = 32,
) -> tuple[str, ...]:
    """Run patterns over ``text`` and return up to ``cap`` deduplicated matches.

    Order is preserved (first occurrence wins) so harvest is deterministic
    on a fixed probe. Whitespace is collapsed and entries shorter than 2
    chars are dropped.
    """
    out: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            value = match.group(1).strip()
            value = re.sub(r"\s+", " ", value)
            if len(value) < 2:
                continue
            if value in seen:
                continue
            seen.add(value)
            out.append(value)
            if len(out) >= cap:
                return tuple(out)
    return tuple(out)


def harvest_persona_and_framework(text: str) -> dict[str, tuple[str, ...]]:
    """Extract persona fragments + framework hints from a leak probe.

    Used by ``ext-system-prompt-leak``. The structural matchers PR #11
    ships look for "You are" / "persona:" / framework brand strings; the
    harvest is the same patterns reified as artefacts.
    """
    out: dict[str, tuple[str, ...]] = {}
    persona = _collect(_PERSONA_PATTERNS, text)
    if persona:
        out["persona_fragments"] = persona
    framework = _collect(_FRAMEWORK_PATTERNS, text)
    if framework:
        out["framework_hints"] = framework
    return out


def harvest_tool_schema(text: str) -> dict[str, tuple[str, ...]]:
    """Extract tool names + parameter keys from a tool-schema leak probe."""
    out: dict[str, tuple[str, ...]] = {}
    tool_names = _collect(_TOOL_NAME_PATTERNS, text)
    if tool_names:
        out["tool_names"] = tool_names
    params: list[str] = []
    seen: set[str] = set()
    for pattern in _PARAM_KEY_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1)
            for token in re.split(r"[,\s\"\']+", raw):
                token = token.strip()
                if not token or len(token) < 2 or token in seen:
                    continue
                if not re.match(r"^[A-Za-z_][\w]*$", token):
                    continue
                seen.add(token)
                params.append(token)
                if len(params) >= 32:
                    break
            if len(params) >= 32:
                break
        if len(params) >= 32:
            break
    if params:
        out["tool_parameter_keys"] = tuple(params)
    return out


def harvest_rag_corpus(text: str) -> dict[str, tuple[str, ...]]:
    """Extract RAG citations + corpus excerpts from a RAG-leak probe."""
    out: dict[str, tuple[str, ...]] = {}
    citations = _collect(_RAG_CITATION_PATTERNS, text)
    if citations:
        out["rag_citations"] = citations
    excerpts = _collect(_RAG_EXCERPT_PATTERNS, text, cap=16)
    if excerpts:
        out["rag_corpus_excerpts"] = excerpts
    return out


def harvest_agent_roles(text: str) -> dict[str, tuple[str, ...]]:
    """Extract agent role names from a multi-agent handoff probe."""
    roles = _collect(_AGENT_ROLE_PATTERNS, text)
    if roles:
        return {"agent_role_names": roles}
    return {}


def harvest_protocol_artefacts(text: str) -> dict[str, tuple[str, ...]]:
    """Extract tool names + envelope styles from a protocol-exploit probe.

    ``tp-protocol-exploit`` lands when the target accepts a hijacked
    tool definition or routes through a shadow tool. The probe response
    then surfaces the legitimate tool's name (the chain consumer needs
    that for its next-step substitution) plus any structural envelope
    keywords (``ROUTE`` / ``ESCALATE`` / ``HANDOFF``) the target echoed.
    """
    out: dict[str, tuple[str, ...]] = {}
    tool_names = _collect(_TOOL_NAME_PATTERNS, text)
    if tool_names:
        out["tool_names"] = tool_names
    envelope_styles: list[str] = []
    seen: set[str] = set()
    for keyword in (
        "json-envelope",
        "prefix-marker",
        "structural-tag",
        "citation",
        "nested-quote",
    ):
        if keyword in seen:
            continue
        token = keyword.replace("-", "_")
        if keyword in text.lower() or token in text.lower() or _envelope_style_signature(keyword, text):
            seen.add(keyword)
            envelope_styles.append(keyword)
    if envelope_styles:
        out["agent_envelope_styles"] = tuple(envelope_styles)
    return out


def _envelope_style_signature(style: str, text: str) -> bool:
    """Heuristic envelope-style detection from probe text."""
    lowered = text.lower()
    if style == "json-envelope":
        return '"authority"' in lowered or '"payload"' in lowered
    if style == "prefix-marker":
        return "from_supervisor:" in lowered or "supervisor_directive:" in lowered
    if style == "structural-tag":
        return "<handoff" in lowered or "<supervisor" in lowered
    if style == "citation":
        return "[supervisor]" in lowered or "[handoff]" in lowered
    if style == "nested-quote":
        return ">>> " in text or ">> " in text
    return False


__all__ = [
    "harvest_agent_roles",
    "harvest_persona_and_framework",
    "harvest_protocol_artefacts",
    "harvest_rag_corpus",
    "harvest_tool_schema",
]
