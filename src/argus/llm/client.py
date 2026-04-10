"""LLM Client wrapper.

Auto-detects Anthropic vs OpenAI keys from environment or CLI flag.
Returns a unified client interface. When no key is configured, the
client reports `available = False` and `generate()` returns None,
so agents can cleanly skip LLM-augmented phases.
"""

from __future__ import annotations

import logging
import os
import re
from enum import Enum

logger = logging.getLogger(__name__)


# Regex patterns that scrub API key fragments from exception strings
_KEY_PATTERNS = [
    re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}"),     # Anthropic
    re.compile(r"sk-proj-[a-zA-Z0-9_-]{20,}"),    # OpenAI project keys
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),           # OpenAI legacy
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{10,}", re.IGNORECASE),
    re.compile(r"x-api-key\s*[:=]\s*\S+", re.IGNORECASE),
]


def _sanitize_exception_message(msg: str, max_length: int = 200) -> str:
    """Strip API key fragments from an exception message and cap length."""
    if not msg:
        return ""
    sanitized = msg
    for pattern in _KEY_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
    return sanitized


class LLMMode(str, Enum):
    """Which mode ARGUS is running in."""

    DETERMINISTIC = "deterministic"  # no LLM key, corpus + scanners only
    AUGMENTED_ANTHROPIC = "augmented:anthropic"
    AUGMENTED_OPENAI = "augmented:openai"


class LLMClient:
    """Unified LLM client supporting Anthropic and OpenAI.

    Reads keys from env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY) or
    via explicit configuration. When no key is available, the client
    is `available=False` and all calls become no-ops.
    """

    def __init__(
        self,
        anthropic_key: str | None = None,
        openai_key: str | None = None,
        prefer: str = "anthropic",
    ) -> None:
        self._anthropic_key = anthropic_key or os.environ.get("ANTHROPIC_API_KEY")
        self._openai_key = openai_key or os.environ.get("OPENAI_API_KEY")
        self._prefer = prefer
        self._anthropic_client = None
        self._openai_client = None
        self._tokens_used = 0
        self._calls_made = 0

        if self._anthropic_key and prefer == "anthropic":
            self._mode = LLMMode.AUGMENTED_ANTHROPIC
            self._provider = "anthropic"
        elif self._openai_key:
            self._mode = LLMMode.AUGMENTED_OPENAI
            self._provider = "openai"
        elif self._anthropic_key:
            self._mode = LLMMode.AUGMENTED_ANTHROPIC
            self._provider = "anthropic"
        else:
            self._mode = LLMMode.DETERMINISTIC
            self._provider = None

    @property
    def available(self) -> bool:
        """True if an LLM key is configured."""
        return self._mode != LLMMode.DETERMINISTIC

    @property
    def mode(self) -> LLMMode:
        return self._mode

    @property
    def provider(self) -> str | None:
        return self._provider

    @property
    def stats(self) -> dict:
        return {
            "mode": self._mode.value,
            "provider": self._provider,
            "calls": self._calls_made,
            "tokens_used": self._tokens_used,
        }

    def _init_anthropic(self):
        if self._anthropic_client is None:
            from anthropic import AsyncAnthropic

            self._anthropic_client = AsyncAnthropic(api_key=self._anthropic_key)
        return self._anthropic_client

    def _init_openai(self):
        if self._openai_client is None:
            from openai import AsyncOpenAI

            self._openai_client = AsyncOpenAI(api_key=self._openai_key)
        return self._openai_client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        model: str | None = None,
    ) -> str | None:
        """Generate a completion. Returns None when no LLM is configured.

        Agents should check `client.available` before calling this if
        they need to take a deterministic fallback path.
        """
        if not self.available:
            return None

        try:
            if self._provider == "anthropic":
                client = self._init_anthropic()
                model_name = model or "claude-sonnet-4-20250514"
                response = await client.messages.create(
                    model=model_name,
                    max_tokens=max_tokens,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_prompt}],
                    temperature=temperature,
                )
                self._calls_made += 1
                if hasattr(response, "usage"):
                    self._tokens_used += getattr(response.usage, "input_tokens", 0)
                    self._tokens_used += getattr(response.usage, "output_tokens", 0)
                return response.content[0].text

            elif self._provider == "openai":
                client = self._init_openai()
                model_name = model or "gpt-4o-mini"
                response = await client.chat.completions.create(
                    model=model_name,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temperature,
                )
                self._calls_made += 1
                if hasattr(response, "usage"):
                    self._tokens_used += getattr(response.usage, "total_tokens", 0)
                return response.choices[0].message.content or ""

        except Exception as exc:
            # Log only the exception type by default. Sanitize and DEBUG-log
            # the message if a developer needs more detail.
            logger.warning(
                "LLM generation failed (%s): %s — agent will fall back to deterministic path",
                self._provider,
                type(exc).__name__,
            )
            sanitized = _sanitize_exception_message(str(exc))
            if sanitized:
                logger.debug("LLM error detail (sanitized): %s", sanitized)
            return None

        return None

    def banner_lines(self) -> list[str]:
        """Lines to print at startup describing the current LLM mode."""
        if self._mode == LLMMode.DETERMINISTIC:
            return [
                "[bold]Mode:[/] [yellow]DETERMINISTIC[/] (no LLM key configured)",
                "[dim]ARGUS will use the corpus and scanners only.[/]",
                "[dim]Set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable LLM-augmented mode.[/]",
            ]
        elif self._mode == LLMMode.AUGMENTED_ANTHROPIC:
            return [
                "[bold]Mode:[/] [green]AUGMENTED[/] (Anthropic Claude)",
                "[dim]LLM augmentation enabled \u2014 novel variants, semantic judgment, compound chain reasoning.[/]",
            ]
        elif self._mode == LLMMode.AUGMENTED_OPENAI:
            return [
                "[bold]Mode:[/] [green]AUGMENTED[/] (OpenAI)",
                "[dim]LLM augmentation enabled \u2014 novel variants, semantic judgment, compound chain reasoning.[/]",
            ]
        return []


_global_client: LLMClient | None = None


def get_llm_client(
    anthropic_key: str | None = None,
    openai_key: str | None = None,
    prefer: str = "anthropic",
) -> LLMClient:
    """Get the process-wide LLM client.

    Initializes from env vars on first call. Subsequent calls return
    the same instance unless explicit keys are passed (which creates
    a new client).
    """
    global _global_client

    if anthropic_key or openai_key:
        return LLMClient(
            anthropic_key=anthropic_key,
            openai_key=openai_key,
            prefer=prefer,
        )

    if _global_client is None:
        _global_client = LLMClient(prefer=prefer)

    return _global_client


def reset_llm_client() -> None:
    """Reset the global client (mainly for tests)."""
    global _global_client
    _global_client = None
