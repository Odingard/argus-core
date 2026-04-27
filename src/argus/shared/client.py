"""argus.shared.client — universal LLM dispatch with provider failover.

Every LLM call in ARGUS routes through ``ArgusClient.messages.create``.
This module owns:

  - Provider selection (model-name prefix → openai | anthropic | gemini)
  - Per-provider call dispatch with hard timeouts
  - Response normalisation to Anthropic-shaped objects (``MockMessageResponse``)
  - 2026 model aliasing for unknown variants
  - Failover chain walking + process-wide dead-provider blacklist
  - litellm-kwargs export for frameworks (crewAI, etc.) that use litellm
    internally and need to inherit ARGUS's resilience

Failover semantics
──────────────────

The default behaviour is single-attempt: ``client.messages.create(model="X", ...)``
calls model X exactly once. If X raises, the exception propagates. This
preserves backwards compatibility with the seven existing call sites in the
codebase that have never had failover.

Failover is opted into by setting ``ARGUS_LLM_CHAIN`` in the environment:

    export ARGUS_LLM_CHAIN="claude-sonnet-4-5-20250929,gpt-4o,gemini-2.5-pro"

When set, ``messages.create`` walks the chain on every call, blacklisting any
model that returns a recognised quota / credit / auth error and falling over
to the next. The blacklist is process-wide (class-level) so the judge
poisoning a provider stops every other consumer from retrying it. Operators
can clear the blacklist between phases via ``ArgusClient.reset_blacklist()``.

A per-call ``failover=False`` kwarg disables walking for that one call, useful
for harness/test paths and any code that explicitly wants single-attempt
semantics regardless of env config.

Per-purpose overrides
─────────────────────

The judge has historically supported its own chain via ``ARGUS_JUDGE_MODELS``
(plural) / ``ARGUS_JUDGE_MODEL`` (singular). Those env vars are still honoured
by ``LLMJudge`` itself — they layer on top of the global ``ARGUS_LLM_CHAIN``
default. The chain resolution precedence is:

    1. Explicit ``models=[...]`` kwarg passed to the consumer
    2. Per-purpose env var (e.g. ``ARGUS_JUDGE_MODELS`` for the judge)
    3. Global ``ARGUS_LLM_CHAIN``
    4. Single-element list ``[caller's model arg]`` — no failover

Error taxonomy
──────────────

Provider errors split into three classes:

  - **EXHAUSTED**  Quota / credit balance / auth / 401-403 / rate-limit. The
                   model is dead for the rest of this engagement. Blacklist
                   it and try the next in chain.
  - **TRANSIENT**  5xx, network blip, timeout. Re-raise so the caller's
                   existing retry/UNAVAILABLE path handles it. Do NOT
                   blacklist — the model is probably fine.
  - **OTHER**      Malformed request, invalid model ID, etc. Re-raise. Not a
                   provider-availability problem.

We classify by error-message substring rather than exception class because
provider SDKs (OpenAI vs Anthropic vs Gemini) format errors differently and
litellm wraps them into yet a fourth shape. Substring matching is robust
across all four.
"""
from __future__ import annotations

import logging
import os
import threading
import warnings

import anthropic
import openai

with warnings.catch_warnings():
    warnings.simplefilter("ignore", FutureWarning)
    import google.generativeai as genai

from dotenv import load_dotenv

load_dotenv(override=True)

_LOGGER = logging.getLogger("argus.shared.client")

# Default timeout for all LLM calls — prevents infinite hangs on slow /
# dropped provider connections. Override with ``ARGUS_JUDGE_TIMEOUT_S``
# (env var name kept for back-compat; applies to all LLM calls, not just
# the judge).
_LLM_TIMEOUT_S = float(os.environ.get("ARGUS_JUDGE_TIMEOUT_S", "45"))


# ── Provider error classification ────────────────────────────────────

# Substrings that indicate the provider is dead for the rest of this
# engagement. Matching is lowercase, substring-based, and intentionally
# generous: false negatives degrade to the existing single-attempt error
# path (one extra failed call, no harm); false positives blacklist a
# model slightly too aggressively, but recover on the next process start.
_PROVIDER_EXHAUSTED_PATTERNS: tuple[str, ...] = (
    "insufficient_quota",
    "credit balance is too low",
    "credit_balance",
    "exceeded your current quota",
    "you exceeded",
    "rate_limit_exceeded",
    "rate limit exceeded",
    "invalid_api_key",
    "authentication_error",
    "unauthenticated",
    "unauthorized",
    "permission_denied",
    "billing",
    " 429",
    " 401",
    " 402",
    " 403",
)


def _is_provider_exhausted(exc: BaseException) -> bool:
    """True iff the exception text matches a known quota/credit/auth
    failure pattern. Returning True means: blacklist this model, walk
    the chain. Returning False means: re-raise — the model is probably
    fine and the caller should handle this as a transient error."""
    msg = str(exc).lower()
    return any(pat in msg for pat in _PROVIDER_EXHAUSTED_PATTERNS)


class AllProvidersExhausted(Exception):
    """Raised by ``ArgusMessagesAPI.create`` when every model in the
    failover chain has been blacklisted. Consumers handle this by
    degrading gracefully (e.g. the judge emits an UNAVAILABLE verdict)
    so the engagement completes instead of crashing."""


# ── Chain resolution ─────────────────────────────────────────────────

def _global_chain_from_env() -> list[str]:
    """Parse ``ARGUS_LLM_CHAIN`` (comma-separated). Empty / unset means
    no global default — single-attempt semantics for any caller that
    doesn't supply its own chain."""
    raw = os.environ.get("ARGUS_LLM_CHAIN", "").strip()
    if not raw:
        return []
    return [m.strip() for m in raw.split(",") if m.strip()]


def _resolve_chain(model: str | None, chain: list[str] | None) -> list[str]:
    """Final chain for one ``create`` call.

      1. Explicit ``chain`` kwarg wins.
      2. Else if global ``ARGUS_LLM_CHAIN`` is set: use it, prepending
         ``model`` if it's not already in the chain (so the caller's
         requested model is always tried first).
      3. Else: single-element ``[model]`` — preserves legacy behaviour.

    Empty result is impossible: at least one model is always returned,
    or ``ValueError`` is raised (which would only happen if the caller
    passed neither model nor chain).
    """
    if chain:
        return [m for m in chain if m and m.strip()]
    global_chain = _global_chain_from_env()
    if global_chain:
        if model and model not in global_chain:
            return [model] + global_chain
        return global_chain
    if model:
        return [model]
    raise ValueError(
        "ArgusClient.messages.create requires either model= or chain="
    )


# ── Response normalisation ───────────────────────────────────────────

class MockMessageContent:
    """Anthropic-shaped content block. Every consumer reads
    ``.content[0].text`` regardless of which provider answered."""
    def __init__(self, text: str) -> None:
        self.text = text


class MockMessageResponse:
    """Anthropic-shaped response wrapper. Returned for OpenAI and Gemini
    calls so consumers don't need provider-aware response handling.
    Anthropic responses are returned directly (already this shape)."""
    def __init__(self, text: str, stop_reason: str = "end_turn") -> None:
        self.content = [MockMessageContent(text)]
        self.stop_reason = stop_reason


# ── Messages API ─────────────────────────────────────────────────────

class ArgusMessagesAPI:
    """Anthropic-shaped ``messages.create(...)`` surface that dispatches
    to whichever provider matches the model name, with optional chain
    walking + dead-provider blacklist for resilience."""

    # Process-wide blacklist. All ``ArgusClient`` instances share this
    # set so that one consumer poisoning a provider (judge hits Claude
    # quota, gets exhausted) stops every other consumer from retrying
    # it (cve_pipeline, mcp_live_attacker, etc. instantly skip Claude
    # for the rest of the run). Cleared via ``ArgusClient.reset_blacklist()``.
    _dead_models: set[str] = set()
    _blacklist_lock = threading.Lock()

    def __init__(self) -> None:
        self.anthropic_client = None
        self.openai_client = None

        if os.environ.get("ANTHROPIC_API_KEY"):
            self.anthropic_client = anthropic.Anthropic(timeout=_LLM_TIMEOUT_S)
        if os.environ.get("OPENAI_API_KEY"):
            self.openai_client = openai.OpenAI(timeout=_LLM_TIMEOUT_S)
        if os.environ.get("GEMINI_API_KEY"):
            genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

    # ── public API ──────────────────────────────────────────────────

    def create(
        self,
        model: str | None = None,
        messages: list[dict] | None = None,
        max_tokens: int = 4000,
        *,
        chain: list[str] | None = None,
        failover: bool = True,
        **kwargs,
    ):
        """Send messages to an LLM. Returns an Anthropic-shaped response
        regardless of which provider answered.

        Args:
          model:       Single model name. Required if ``chain`` is not set.
          messages:    Anthropic-shaped messages list.
          max_tokens:  Output cap.
          chain:       Explicit failover chain. Overrides env-derived chain.
          failover:    When False, single-attempt semantics — the chain is
                       walked but exhausted-provider errors propagate
                       instead of blacklisting and continuing. Use for
                       test harnesses or any caller that explicitly does
                       not want resilience.
          **kwargs:    Forwarded to the provider SDK.

        Raises:
          AllProvidersExhausted: every model in the chain hit a quota /
                                 credit / auth failure.
          Other exceptions:      transient errors (5xx, network, malformed
                                 request) — propagate so callers can retry
                                 or degrade.
        """
        if messages is None:
            raise ValueError("messages= is required")

        full_chain = _resolve_chain(model, chain)

        # Single-attempt opt-out: walk the chain but don't blacklist.
        # Pre-blacklisted models are still skipped (it would be wasteful
        # to retry them in the same process).
        if not failover:
            for m in full_chain:
                if m in ArgusMessagesAPI._dead_models:
                    continue
                return self._dispatch(m, messages, max_tokens, **kwargs)
            # All models pre-blacklisted, no attempt made.
            raise AllProvidersExhausted(
                f"all {len(full_chain)} providers in chain pre-blacklisted: "
                f"{sorted(ArgusMessagesAPI._dead_models & set(full_chain))}"
            )

        # Full failover: blacklist exhausted models as we hit them.
        last_exc: BaseException | None = None
        attempted = False
        for m in full_chain:
            if m in ArgusMessagesAPI._dead_models:
                continue
            attempted = True
            try:
                return self._dispatch(m, messages, max_tokens, **kwargs)
            except Exception as e:
                if _is_provider_exhausted(e):
                    self._blacklist(m, e, full_chain)
                    last_exc = e
                    continue
                raise  # transient / other → propagate
        if not attempted:
            raise AllProvidersExhausted(
                f"all {len(full_chain)} providers pre-blacklisted: "
                f"{sorted(ArgusMessagesAPI._dead_models & set(full_chain))}"
            )
        raise AllProvidersExhausted(
            f"all {len(full_chain)} providers exhausted this run: "
            f"{sorted(ArgusMessagesAPI._dead_models & set(full_chain))}"
        ) from last_exc

    # ── internals ───────────────────────────────────────────────────

    @classmethod
    def _blacklist(cls, model: str, exc: BaseException, chain: list[str]) -> None:
        """Add model to the process-wide blacklist (idempotent, locked)."""
        with cls._blacklist_lock:
            if model in cls._dead_models:
                return
            cls._dead_models.add(model)
            live = [m for m in chain if m not in cls._dead_models]
        _LOGGER.warning(
            "[argus-failover] %s exhausted (%s: %s) — blacklisted for this "
            "run; remaining chain: %s",
            model, type(exc).__name__, str(exc)[:120], live,
        )

    def _dispatch(
        self,
        model: str,
        messages: list[dict],
        max_tokens: int,
        **kwargs,
    ):
        """Pick provider by model name and call it with a hard timeout."""
        provider = _provider_for_model(model)
        model = _alias_model(provider, model)

        if provider == "openai":
            return self._call_openai(model, messages, max_tokens, **kwargs)
        if provider == "gemini":
            return self._call_gemini(model, messages, max_tokens, **kwargs)
        return self._call_anthropic(model, messages, max_tokens, **kwargs)

    def _call_openai(self, model, messages, max_tokens, **kwargs):
        if not self.openai_client:
            raise ValueError("OPENAI_API_KEY not configured")
        kw = {}
        ml = model.lower()
        if "o1" in ml or "o3" in ml:
            kw = {"max_completion_tokens": max_tokens}
        else:
            kw = {"max_tokens": max_tokens}

        result = [None]
        exc = [None]

        def _go():
            try:
                result[0] = self.openai_client.chat.completions.create(
                    model=model, messages=messages, **kw,
                )
            except Exception as e:
                exc[0] = e

        t = threading.Thread(target=_go, daemon=True)
        t.start()
        t.join(timeout=_LLM_TIMEOUT_S)
        if t.is_alive():
            raise TimeoutError(
                f"LLM call to {model} exceeded {_LLM_TIMEOUT_S}s — skipping"
            )
        if exc[0] is not None:
            raise exc[0]
        resp = result[0]
        return MockMessageResponse(
            resp.choices[0].message.content,
            resp.choices[0].finish_reason,
        )

    def _call_gemini(self, model, messages, max_tokens, **kwargs):
        if not os.environ.get("GEMINI_API_KEY"):
            raise ValueError("GEMINI_API_KEY not configured")
        prompt = "\n\n".join(
            m["content"] for m in messages if "content" in m
        )
        gemini_model = genai.GenerativeModel(model)
        response = gemini_model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
            ),
        )
        return MockMessageResponse(response.text)

    def _call_anthropic(self, model, messages, max_tokens, **kwargs):
        if not self.anthropic_client:
            raise ValueError(
                f"ANTHROPIC_API_KEY not configured for model {model}"
            )

        result = [None]
        exc = [None]

        def _go():
            try:
                result[0] = self.anthropic_client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=messages,
                    **kwargs,
                )
            except Exception as e:
                exc[0] = e

        t = threading.Thread(target=_go, daemon=True)
        t.start()
        t.join(timeout=_LLM_TIMEOUT_S)
        if t.is_alive():
            raise TimeoutError(
                f"LLM call to {model} exceeded {_LLM_TIMEOUT_S}s — skipping"
            )
        if exc[0] is not None:
            raise exc[0]
        return result[0]


# ── Provider routing helpers ─────────────────────────────────────────

def _provider_for_model(model: str) -> str:
    """Map a model name to its provider via prefix matching. Returns
    one of {"openai", "anthropic", "gemini"}."""
    ml = model.lower()
    if "gpt-" in ml or "o1" in ml or "o3" in ml:
        return "openai"
    if "gemini" in ml:
        return "gemini"
    return "anthropic"


# 2026 model aliasing — known-good models the providers actually serve.
# Anything outside these lists gets remapped to a sane default. Update
# when a provider releases new model names.
_KNOWN_ANTHROPIC_MODELS = {
    "claude-opus-4-5",
    "claude-sonnet-4-5",
    "claude-sonnet-4-5-20250929",
    "claude-opus-4-20250514",
    "claude-sonnet-4-20250514",
    "claude-haiku-4-5-20251001",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
}


def _alias_model(provider: str, model: str) -> str:
    """Map unknown / future model names onto known-good ones the
    provider actually serves today. Prevents a typo or a roadmap-only
    model name from blowing up an engagement."""
    ml = model.lower()
    if provider == "openai":
        if "gpt-5.4-pro" in ml:
            return "gpt-4o"
        return model
    if provider == "anthropic":
        if model not in _KNOWN_ANTHROPIC_MODELS:
            return "claude-sonnet-4-20250514"
        return model
    if provider == "gemini":
        if "gemini-3.1-pro" in ml:
            return "gemini-1.5-pro"
        return model
    return model


# ── Public client surface ────────────────────────────────────────────

class ArgusClient:
    """Seamless multi-provider interface mimicking ``anthropic.Anthropic()``.

    Construction is cheap (no API call). Every consumer of LLMs in ARGUS
    instantiates one of these and calls ``client.messages.create(...)``.
    Failover, blacklisting, and litellm-kwargs export are all driven
    through the messages API.
    """

    def __init__(self) -> None:
        self.messages = ArgusMessagesAPI()

    # ── operator escape hatch ───────────────────────────────────────

    @classmethod
    def reset_blacklist(cls) -> set[str]:
        """Clear the process-wide dead-provider blacklist. Returns the
        set of models that were previously blacklisted (informational —
        useful for ''wait, why is the judge silent?'' debugging at the
        REPL or between phases of a multi-stage operator run).

        Typical use: an operator notices ARGUS skipped Claude all
        engagement because of a transient quota issue earlier, tops up
        the account, and calls this between phases:

            ArgusClient.reset_blacklist()  # Claude eligible again next probe
        """
        with ArgusMessagesAPI._blacklist_lock:
            previously_dead = set(ArgusMessagesAPI._dead_models)
            ArgusMessagesAPI._dead_models.clear()
        if previously_dead:
            _LOGGER.info(
                "[argus-failover] blacklist cleared; %d providers eligible "
                "again: %s",
                len(previously_dead), sorted(previously_dead),
            )
        return previously_dead

    @classmethod
    def blacklist_snapshot(cls) -> set[str]:
        """Return a copy of the current blacklist (for observability /
        tests). Modifying the returned set has no effect on the real
        blacklist."""
        with ArgusMessagesAPI._blacklist_lock:
            return set(ArgusMessagesAPI._dead_models)

    # ── litellm bridge ──────────────────────────────────────────────

    @staticmethod
    def build_litellm_kwargs(
        provider: str,
        model: str,
        *,
        chain: list[str] | None = None,
    ) -> dict:
        """Produce a kwargs dict for litellm-based frameworks (crewAI,
        Langchain, etc.) that includes provider failover at the litellm
        layer.

        litellm honours ``fallbacks=["model_a", "model_b"]`` natively,
        so this method maps an ARGUS chain onto litellm's vocabulary.
        Frameworks that consume the result get failover propagated into
        their internal calls without ARGUS having to fork the framework.

        Args:
          provider: ARGUS provider label ("openai" | "anthropic" | "gemini").
          model:    Primary model.
          chain:    Optional explicit failover chain. If unset, falls back
                    to the global ``ARGUS_LLM_CHAIN`` env var.

        Returns:
          dict suitable for splat-passing into litellm.completion(...)
          or for use as a litellm-config-style object the framework
          consumes during LLM construction.
        """
        full_chain = _resolve_chain(model, chain)
        # litellm uses provider-prefixed model names. Map ARGUS's bare
        # model strings to litellm form.
        litellm_model = _to_litellm_model(provider, full_chain[0])
        fallbacks = [
            _to_litellm_model(_provider_for_model(m), m)
            for m in full_chain[1:]
        ]
        kwargs: dict = {
            "model": litellm_model,
            "timeout": _LLM_TIMEOUT_S,
        }
        if fallbacks:
            kwargs["fallbacks"] = fallbacks
        return kwargs


def _to_litellm_model(provider: str, model: str) -> str:
    """Convert ARGUS bare model name into litellm's provider-prefixed
    form (e.g. ``claude-sonnet-4-5`` → ``anthropic/claude-sonnet-4-5``).
    OpenAI is the special case — litellm accepts bare ``gpt-*`` names."""
    if provider == "anthropic":
        return f"anthropic/{model}" if not model.startswith("anthropic/") else model
    if provider == "gemini":
        return f"gemini/{model}" if not model.startswith("gemini/") else model
    return model  # openai: bare name is accepted
