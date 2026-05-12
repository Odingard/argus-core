"""AI-surface fingerprinter.

Classifies discovered hosts by likely AI surface (chat / agent / mcp /
rag / tool / unknown) using two signals:

1. **Hostname pattern** (always run, fully passive). The subdomain
   prefix carries operator intent — ``chat.X``, ``agent.X``,
   ``mcp.X``, ``rag.X``, ``copilot.X`` etc. We classify with a
   prefix lexicon plus a small token set drawn from real production
   AI deployments.
2. **Active probe** (only when ``--active`` is enabled). Sends one
   ``HEAD`` and one ``OPTIONS`` request and inspects the response
   headers / status. Identifies common server frameworks
   (Vercel / Cloudflare / FastAPI / Express) and AI-specific paths
   (``/v1/chat/completions``, ``/api/messages``, ``/mcp``,
   ``/agent``, ``/chat``). The probe is rate-limited and stops after
   one round-trip per host — no banner grabbing, no fuzzing.

Fingerprinting never enforces scope; the orchestrator filters every
host through :class:`~..scope.Scope` before passing it here, so this
module trusts the input list.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

_AI_PREFIX_LEXICON: dict[str, str] = {
    "chat": "chat",
    "chatbot": "chat",
    "assistant": "agent",
    "agent": "agent",
    "agents": "agent",
    "ai": "chat",
    "bot": "chat",
    "copilot": "agent",
    "rag": "rag",
    "kb": "rag",
    "search": "rag",
    "answers": "rag",
    "mcp": "mcp",
    "tools": "tool",
    "functions": "tool",
    "api": "api",
    "llm": "chat",
    "gpt": "chat",
    "claude": "chat",
    "gemini": "chat",
    "ollama": "chat",
    "openai": "chat",
}

_AI_PATH_HINTS: dict[str, str] = {
    "/v1/chat/completions": "chat",
    "/api/chat": "chat",
    "/chat": "chat",
    "/api/messages": "chat",
    "/v1/messages": "chat",
    "/api/agent": "agent",
    "/agent": "agent",
    "/mcp": "mcp",
    "/sse": "mcp",
    "/v1/embeddings": "rag",
    "/api/search": "rag",
    "/api/tools": "tool",
}

_HEADERS = {"User-Agent": "argus-engine-recon/1.0"}


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """Per-host classification result."""

    host: str
    surface: str  # one of: chat / agent / mcp / rag / tool / api / unknown
    confidence: float  # 0.0 - 1.0
    framework: str = ""  # e.g. "vercel", "cloudflare", "fastapi", ""
    evidence: tuple[tuple[str, str], ...] = ()
    score: float = 0.0  # attackability score for ranking


def _passive_classify(host: str) -> tuple[str, float, tuple[tuple[str, str], ...]]:
    """Classify ``host`` using subdomain prefix tokens only."""
    label = host.split(".", 1)[0].lower() if "." in host else host.lower()
    # Direct hit on lexicon.
    direct = _AI_PREFIX_LEXICON.get(label)
    if direct is not None:
        return direct, 0.7, (("prefix_match", label),)
    # Compound prefix, e.g. "chat-prod", "agent-staging".
    for token, surface in _AI_PREFIX_LEXICON.items():
        if label.startswith(token + "-") or label.endswith("-" + token):
            return surface, 0.55, (("prefix_compound", f"{label}~{token}"),)
    # Full-host token sweep for noisy embeddings (e.g. "secure-chatbot.x.com").
    full = host.lower()
    for token, surface in _AI_PREFIX_LEXICON.items():
        if f"-{token}-" in full or f".{token}." in full:
            return surface, 0.4, (("token_in_host", token),)
    return "unknown", 0.0, ()


def _attackability(surface: str, framework: str) -> float:
    """Heuristic 0..1 ranking score.

    Higher = more interesting to engage. The ranker is intentionally
    conservative — it nudges; it does not gate. The supervisor still
    fires every in-scope target if budget allows.
    """
    base = {
        "agent": 0.95,
        "mcp": 0.9,
        "chat": 0.8,
        "tool": 0.75,
        "rag": 0.7,
        "api": 0.5,
        "unknown": 0.2,
    }.get(surface, 0.2)
    # Vercel + Cloudflare AI surfaces are high-density targets.
    if framework in {"vercel", "cloudflare"}:
        base = min(1.0, base + 0.05)
    return round(base, 3)


def classify_passive(hosts: list[str]) -> list[Fingerprint]:
    """Pure subdomain-name classification — no network I/O."""
    fps: list[Fingerprint] = []
    for h in hosts:
        surface, conf, ev = _passive_classify(h)
        fps.append(
            Fingerprint(
                host=h,
                surface=surface,
                confidence=conf,
                evidence=ev,
                score=_attackability(surface, ""),
            )
        )
    return fps


async def _probe_one(client: httpx.AsyncClient, host: str) -> Fingerprint:
    base = f"https://{host}"
    surface, conf, ev = _passive_classify(host)
    framework = ""
    evidence: list[tuple[str, str]] = list(ev)
    try:
        head = await client.head(base, timeout=10.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        evidence.append(("probe_error", str(exc)[:120]))
        return Fingerprint(
            host=host,
            surface=surface,
            confidence=conf,
            framework=framework,
            evidence=tuple(evidence),
            score=_attackability(surface, framework),
        )

    server = head.headers.get("server", "").lower()
    powered = head.headers.get("x-powered-by", "").lower()
    via = head.headers.get("via", "").lower()
    if "vercel" in server or "vercel" in via:
        framework = "vercel"
    elif "cloudflare" in server or "cloudflare" in via:
        framework = "cloudflare"
    elif "uvicorn" in server or "fastapi" in powered:
        framework = "fastapi"
    elif "express" in powered:
        framework = "express"
    elif "nginx" in server:
        framework = "nginx"
    if framework:
        evidence.append(("framework", framework))
    evidence.append(("status", str(head.status_code)))

    # Lightweight path probe — at most one extra request per host.
    for path, label in _AI_PATH_HINTS.items():
        try:
            r = await client.head(base + path, timeout=8.0, follow_redirects=False)
        except httpx.HTTPError:
            continue
        if r.status_code in (200, 204, 401, 403, 405, 415, 422):
            surface = label
            conf = max(conf, 0.85)
            evidence.append(("ai_path", path))
            break

    return Fingerprint(
        host=host,
        surface=surface,
        confidence=round(conf, 3),
        framework=framework,
        evidence=tuple(evidence),
        score=_attackability(surface, framework),
    )


async def classify_active(
    hosts: list[str],
    *,
    concurrency: int = 8,
    client: httpx.AsyncClient | None = None,
) -> list[Fingerprint]:
    """Send one HEAD + one path-probe per host. Requires --active."""
    own = client is None
    cli = client or httpx.AsyncClient(timeout=10.0, headers=_HEADERS)
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _gated(h: str) -> Fingerprint:
        async with sem:
            return await _probe_one(cli, h)

    try:
        results = await asyncio.gather(*(_gated(h) for h in hosts))
    finally:
        if own:
            await cli.aclose()
    return list(results)
