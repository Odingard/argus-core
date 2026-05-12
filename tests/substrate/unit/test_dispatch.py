"""Tests for the Phase M ``--transport auto`` dispatcher.

The dispatcher is a pure function (no I/O, no network, no clock), so
every routing rule can be pinned with cheap, deterministic asserts.
"""

from __future__ import annotations

import pytest

from argus.engine.runtime.dispatch import (
    VALID_TRANSPORTS,
    DispatchDecision,
    auto_dispatch,
)

# ---------------------------------------------------------------------------
# Provider model ids -> chat-completion transports
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_id",
    [
        "gpt-4o",
        "gpt-4o-mini",
        "o1-preview",
        "o3-mini",
        "text-davinci-003",
    ],
)
def test_openai_default_for_openai_style_model_ids(model_id: str) -> None:
    decision = auto_dispatch(model_id)
    assert decision.transport == "openai"
    assert decision.target_kind == "model_id"
    assert decision.mcp_capable is False


@pytest.mark.parametrize(
    "model_id",
    [
        "claude-3-5-sonnet-20241022",
        "claude-3-opus-20240229",
        "claude-3-haiku-20240307",
        "claude_2_1",
        "anthropic/claude-3-5-sonnet",
        "anthropic.claude-3-5-sonnet-v2:0",
        "anthropic:claude-3-haiku",
    ],
)
def test_anthropic_for_claude_pattern(model_id: str) -> None:
    decision = auto_dispatch(model_id)
    assert decision.transport == "anthropic"


@pytest.mark.parametrize(
    "model_id",
    [
        "llama3:latest",
        "llama-3.1-8b-instruct",
        "mistral-7b-instruct",
        "qwen2.5-coder",
        "phi-3-mini",
        "gemma-2-9b",
        "codellama-13b",
    ],
)
def test_ollama_for_open_weights_pattern(model_id: str) -> None:
    decision = auto_dispatch(model_id)
    assert decision.transport == "ollama"


# ---------------------------------------------------------------------------
# URL targets -> argt + MCP-aware recon flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://target.example/mcp",
        "https://target.example/api/mcp/server",
        "http://localhost:8000/jsonrpc",
        "https://t.example/v1/rpc",
        "https://t.example/messages",
    ],
)
def test_url_with_mcp_path_hint_flags_mcp_capable(url: str) -> None:
    decision = auto_dispatch(url)
    assert decision.transport == "argt"
    assert decision.target_kind == "url"
    assert decision.mcp_capable is True


@pytest.mark.parametrize(
    "url",
    [
        "https://target.example/api/chat",
        "https://api.target.example/v1/responses",
        "http://localhost:8000/predict",
    ],
)
def test_url_without_mcp_hint_falls_back_to_plain_argt(url: str) -> None:
    decision = auto_dispatch(url)
    assert decision.transport == "argt"
    assert decision.mcp_capable is False


# ---------------------------------------------------------------------------
# Edge cases / invariants
# ---------------------------------------------------------------------------


def test_empty_target_falls_back_to_openai_default() -> None:
    decision = auto_dispatch("")
    assert decision.transport == "openai"
    assert decision.target_kind == "model_id"


def test_whitespace_target_trimmed_and_routed() -> None:
    assert auto_dispatch("  gpt-4o  ").transport == "openai"
    assert auto_dispatch("  claude-3-haiku ").transport == "anthropic"


def test_decision_is_deterministic_for_same_input() -> None:
    """Rule #7 — pure function, identical inputs produce identical outputs."""
    a = auto_dispatch("https://target.example/mcp")
    b = auto_dispatch("https://target.example/mcp")
    assert a == b


def test_returned_transport_is_always_in_valid_set() -> None:
    for target in [
        "gpt-4o",
        "claude-3-5-sonnet",
        "llama3",
        "https://target/mcp",
        "https://target/anything",
        "",
        "unknown-model-xyz",
    ]:
        decision = auto_dispatch(target)
        assert isinstance(decision, DispatchDecision)
        assert decision.transport in VALID_TRANSPORTS


def test_reason_is_non_empty_for_audit_trail() -> None:
    """Rule #9 — every dispatch must explain itself."""
    for target in ["gpt-4o", "claude-3-haiku", "llama3", "https://t/mcp", "https://t/api"]:
        decision = auto_dispatch(target)
        assert decision.reason.strip()
