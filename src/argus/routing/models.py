"""
argus/routing/models.py — per-job model assignment + failover orchestration.

The router maps a JOB to an ordered list of (provider, model_id) pairs.
At dispatch time it tries each in order until one:
  - has its provider API key set,
  - isn't on the cooldown list (rate-limited within the last N seconds),
  - and completes the call without a retryable error.

Defaults are tuned for a deployment with Anthropic + Gemini + OpenAI
keys (what ``argus --models`` shows). They're cost-reasonable and
capability-appropriate for each job. Override via policy.json.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Defaults ──────────────────────────────────────────────────────────────────

# A "chain" is an ordered list of (provider, model_id) pairs. The first
# one with a live key + no active cooldown wins.

_DEFAULT_CHAINS: dict[str, list[tuple[str, str]]] = {
    # ── Fast, cheap analysis (per-file, per-finding) ────────────────────
    "L1_ANALYZE": [
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("google",    "gemini-2.5-flash"),
        ("openai",    "gpt-4o-mini"),
    ],
    "AGENT_HAIKU": [
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("google",    "gemini-2.5-flash"),
        ("openai",    "gpt-4o-mini"),
    ],
    "L4_DEVIATION": [
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("google",    "gemini-2.5-flash"),
        ("openai",    "gpt-4o-mini"),
    ],
    "CORRELATOR_JUDGE": [
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("google",    "gemini-2.5-flash"),
        ("openai",    "gpt-4o-mini"),
    ],

    # ── Deep synthesis (expensive but high-signal) ──────────────────────
    "L5_SYNTH": [
        ("anthropic", "claude-opus-4-7"),
        ("google",    "gemini-3-pro-preview"),
        ("openai",    "o3-mini"),
    ],
    "CORRELATOR_OPUS": [
        ("anthropic", "claude-opus-4-7"),
        ("google",    "gemini-3-pro-preview"),
        ("openai",    "o3-mini"),
    ],
    "CHAIN_POC": [
        ("anthropic", "claude-opus-4-7"),
        ("google",    "gemini-3.1-pro-preview"),
        ("openai",    "o3-mini"),
    ],

    # ── Code-reading / long context ─────────────────────────────────────
    "L1_POC": [
        ("anthropic", "claude-opus-4-7"),
        ("google",    "gemini-3-pro-preview"),
        ("openai",    "gpt-4o"),
    ],
    "LONG_CONTEXT_REVIEW": [
        ("google",    "gemini-3-pro-preview"),        # 1M ctx primary
        ("anthropic", "claude-opus-4-7"),
        ("openai",    "gpt-4o"),
    ],

    # ── Independent verification (DeepMind-style second opinion) ────────
    "REASONING_AUDIT": [
        ("openai",    "o3-mini"),                      # different family
        ("google",    "gemini-3-pro-preview"),
        ("anthropic", "claude-sonnet-4-6"),
    ],
    "MULTIMODAL_PROBE": [
        ("google",    "gemini-3-pro-image-preview"),
        ("openai",    "gpt-4o"),
    ],

    # ── MCP live attacker phases ────────────────────────────────────────
    "MCP_SYNTH": [
        ("anthropic", "claude-opus-4-7"),
        ("google",    "gemini-3-pro-preview"),
        ("openai",    "o3-mini"),
    ],
    "MCP_SCHEMA_JUDGE": [
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("google",    "gemini-2.5-flash"),
        ("openai",    "gpt-4o-mini"),
    ],

    # ── PRO consensus-gate judges (three independent votes) ─────────────
    # Each judge starts with a DIFFERENT provider so the three votes
    # are genuinely independent — not three calls to the same model.
    # Failover chain kicks in only when the preferred provider is
    # unavailable. This is how the PRO consensus gate achieves
    # "multiple independent judges agreed" rather than "the same judge
    # voted three times."
    "CONSENSUS_JUDGE_A": [
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("google",    "gemini-2.5-flash"),
        ("openai",    "gpt-4o-mini"),
    ],
    "CONSENSUS_JUDGE_B": [
        ("openai",    "gpt-4o-mini"),
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("google",    "gemini-2.5-flash"),
    ],
    "CONSENSUS_JUDGE_C": [
        ("google",    "gemini-2.5-flash"),
        ("openai",    "gpt-4o-mini"),
        ("anthropic", "claude-haiku-4-5-20251001"),
    ],
}


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class JobSpec:
    job:   str
    chain: list[tuple[str, str]] = field(default_factory=list)


JOBS = list(_DEFAULT_CHAINS.keys())


# ── Router ────────────────────────────────────────────────────────────────────

_PROVIDER_KEY_ENV = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai":    ("OPENAI_API_KEY",),
    "google":    ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}

_COOLDOWN_SECS_DEFAULT = 60.0


class ModelRouter:
    """
    Resolves (provider, model) at call time from a job name. Keeps a
    per-provider cooldown map so a rate-limit error on provider A sends
    the next request straight to provider B without retrying A.
    """

    def __init__(
        self,
        chains:   Optional[dict[str, list[tuple[str, str]]]] = None,
        cooldown_secs: float = _COOLDOWN_SECS_DEFAULT,
    ) -> None:
        self._chains = dict(chains or _DEFAULT_CHAINS)
        self._cooldown_secs = cooldown_secs
        self._cooldowns: dict[str, float] = {}   # provider -> expiry monotonic
        self._lock = threading.Lock()

        # Optional override from policy.json / env var.
        policy_path = os.environ.get("ARGUS_ROUTING_POLICY")
        if policy_path and Path(policy_path).exists():
            try:
                override = json.loads(Path(policy_path).read_text(encoding="utf-8"))
                for job, chain in override.items():
                    self._chains[job] = [
                        (p.get("provider", ""), p.get("model", ""))
                        for p in chain
                    ]
            except (json.JSONDecodeError, OSError, KeyError, AttributeError):
                pass   # bad policy file is non-fatal, we fall back to defaults

    # ── Key / cooldown helpers ─────────────────────────────────────────────

    def _key_for(self, provider: str) -> Optional[str]:
        envs = _PROVIDER_KEY_ENV.get(provider, ())
        for e in envs:
            v = os.environ.get(e)
            if v:
                return v
        return None

    def _is_cooled(self, provider: str) -> bool:
        with self._lock:
            expiry = self._cooldowns.get(provider, 0.0)
        return time.monotonic() < expiry

    def cooldown(self, provider: str, secs: Optional[float] = None) -> None:
        """Mark provider as rate-limited for ``secs`` seconds."""
        with self._lock:
            self._cooldowns[provider] = time.monotonic() + (secs or self._cooldown_secs)

    # ── Resolution ─────────────────────────────────────────────────────────

    def resolve(self, job: str) -> tuple[str, str]:
        """
        Return the (provider, model) to use for ``job``. Raises
        ``LookupError`` if no configured model is usable (no keys /
        all on cooldown).
        """
        chain = self._chains.get(job)
        if not chain:
            raise LookupError(f"no chain for job {job!r}")

        first_available: Optional[tuple[str, str]] = None
        # Pass 1: prefer a provider that has a key AND isn't cooled.
        for provider, model in chain:
            if self._key_for(provider) and not self._is_cooled(provider):
                return provider, model
            # Track the first key-available-but-cooled provider as a
            # fallback in case every other option is totally unavailable.
            if self._key_for(provider) and first_available is None:
                first_available = (provider, model)

        if first_available is not None:
            # Every key-available provider is cooled. Return the first
            # one anyway — caller will either succeed (cooldown stale)
            # or get a real error that refreshes the cooldown.
            return first_available

        raise LookupError(
            f"no provider for job {job!r} has a configured API key. "
            f"Chain: {chain}"
        )

    def chain_for(self, job: str) -> list[tuple[str, str]]:
        return list(self._chains.get(job, []))

    def all_chains(self) -> dict[str, list[tuple[str, str]]]:
        return {k: list(v) for k, v in self._chains.items()}


# ── Singleton + convenience ───────────────────────────────────────────────────

_SINGLETON: Optional[ModelRouter] = None
_SINGLETON_LOCK = threading.Lock()


def default_router() -> ModelRouter:
    global _SINGLETON
    if _SINGLETON is None:
        with _SINGLETON_LOCK:
            if _SINGLETON is None:
                _SINGLETON = ModelRouter()
    return _SINGLETON


def route_model(job: str) -> tuple[str, str]:
    """Shortcut: resolve (provider, model) via the default router."""
    return default_router().resolve(job)


def route_call(
    job:         str,
    *,
    messages:    list[dict],
    max_tokens:  int = 1024,
    max_retries: int = 3,
    system:      Optional[str] = None,
):
    """
    One-shot: pick a model for ``job``, make the call, retry down the
    chain on rate-limit / auth / capability errors. Returns the raw
    provider response (SDK object) or raises the last exception.

    Uses ``ArgusClient`` for dispatch so we don't duplicate the
    provider-switching logic.
    """
    from argus.shared.client import ArgusClient
    client = ArgusClient()
    router = default_router()

    last_err: Optional[Exception] = None
    chain = router.chain_for(job) or []
    attempts = 0
    for provider, model in chain:
        if attempts >= max_retries:
            break
        if not router._key_for(provider):
            continue
        attempts += 1
        try:
            kwargs = {
                "model":      model,
                "max_tokens": max_tokens,
                "messages":   messages,
            }
            if system:
                kwargs["system"] = system
            return client.messages.create(**kwargs)
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            # Rate limit / over-quota → cool the provider off.
            if any(k in msg for k in ("rate", "429", "quota", "overloaded",
                                      "capacity")):
                router.cooldown(provider)
            # Otherwise fall through to the next provider.
            continue

    if last_err is not None:
        raise last_err
    raise LookupError(f"no provider available for job {job!r}")
