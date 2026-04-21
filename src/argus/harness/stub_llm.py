"""
argus/harness/stub_llm.py — deterministic LLM stub.

We replace the real LLM with a table-driven stub so harness runs are
bit-reproducible. That's what lets us:

  - Replay the same scenario across model versions (context-drift
    detection — sinkhole S1).
  - Use transcripts as a fine-tune corpus for Pillar 1 without worrying
    that "the model" was the source of randomness.
  - Run tests without any API key.

A ``StubLLM`` is seeded with either:

    a) a list of ``StubResponse`` rules, each with a regex over the
       prompt and a canned output (first match wins), OR
    b) a default response used when no rule matches (useful for
       "fuzz the rest of the conversation"), OR
    c) a callable ``responder(prompt_text, turn_idx) -> str`` for tests
       that need state machines beyond simple regex.

The stub exposes the same ``messages.create(...)`` surface as
``argus.shared.client.ArgusClient`` so swapping it in is zero-code on
the target side.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


# ── Minimal client-compatible message wrappers ────────────────────────────────

@dataclass
class _StubContent:
    text: str
    type: str = "text"


@dataclass
class _StubResp:
    content: list[_StubContent]
    stop_reason: str = "end_turn"


# ── Response rule ─────────────────────────────────────────────────────────────

@dataclass
class StubResponse:
    """
    One canned LLM response. ``match_regex`` is tested against the *last*
    user/system content in the prompt sequence. First match wins.
    """
    match_regex: str
    output:      str
    stop_reason: str = "end_turn"
    # Optional structural output for tool-calling models (not used here
    # yet — kept in the dataclass so scenarios can evolve).
    tool_calls:  list[dict] = field(default_factory=list)


# ── StubLLM ───────────────────────────────────────────────────────────────────

class StubLLM:
    """
    Drop-in replacement for ArgusClient.messages.create(...).

    Usage:

        stub = StubLLM([
            StubResponse(r"ignore previous", "I won't."),
            StubResponse(r"DROP TABLE",      "Refusing destructive SQL."),
        ], default="Sure.")

        # anywhere that would call client.messages.create(...)
        resp = stub.messages.create(model="...", messages=[{"role":"user","content":"..."}])
        resp.content[0].text   # -> "..."
    """

    def __init__(
        self,
        rules:     Optional[list[StubResponse]] = None,
        default:   str = "[stub-llm]",
        responder: Optional[Callable[[str, int], str]] = None,
    ) -> None:
        self.rules     = list(rules or [])
        self.default   = default
        self.responder = responder
        self._turn     = 0
        self._history: list[tuple[str, str]] = []  # (prompt_tail, output)
        self.messages  = _MessagesAPI(self)        # mirror SDK surface

    # ── Internals used by the _MessagesAPI shim ────────────────────────────

    def _answer(self, prompt_tail: str) -> tuple[str, str]:
        """Return (output, stop_reason). Advances turn counter."""
        turn = self._turn
        self._turn += 1

        if self.responder is not None:
            out = self.responder(prompt_tail, turn)
            self._history.append((prompt_tail, out))
            return out, "end_turn"

        for rule in self.rules:
            try:
                if re.search(rule.match_regex, prompt_tail,
                             re.IGNORECASE | re.DOTALL):
                    self._history.append((prompt_tail, rule.output))
                    return rule.output, rule.stop_reason
            except re.error:
                continue

        self._history.append((prompt_tail, self.default))
        return self.default, "end_turn"

    @property
    def history(self) -> list[tuple[str, str]]:
        return list(self._history)

    @property
    def turns(self) -> int:
        return self._turn


class _MessagesAPI:
    """Mirror of ``ArgusClient.messages.create`` with the stub behind it."""
    def __init__(self, owner: "StubLLM") -> None:
        self._owner = owner

    def create(self, *, model: str, max_tokens: int = 1024,
               messages: list[dict], **_kw) -> _StubResp:
        # Use the last user-role content as the match target. Fall back
        # to the last message regardless of role.
        tail = ""
        for m in reversed(messages):
            if m.get("role") in ("user", None):
                content = m.get("content", "")
                tail = content if isinstance(content, str) else str(content)
                break
        if not tail and messages:
            tail = str(messages[-1].get("content", ""))
        out, stop_reason = self._owner._answer(tail)
        return _StubResp(content=[_StubContent(text=out)],
                         stop_reason=stop_reason)
