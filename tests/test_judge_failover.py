"""tests/test_judge_failover.py — provider-failover behaviour.

Both the 2026-04-27 real-crewai engagement and the morning labrat run
burned wall-clock retrying dead LLM providers (OpenAI quota exhausted,
then Anthropic credit balance low, hundreds of probes each). After the
2026-04-27 evening migration the failover machinery moved DOWN from
``LLMJudge`` into ``argus.shared.client.ArgusClient`` so every consumer
in the codebase (judge, cve_pipeline, mcp_live_attacker, agents,
engagement runner, …) inherits the resilience automatically. This file
locks the behaviour at both layers:

  - Client-level (``argus.shared.client``): error classification, chain
    resolution, blacklist semantics, the ``AllProvidersExhausted`` contract.
  - Judge-level (``argus.attacks.judge``): the judge-specific env-var
    overrides still work, ``LLMJudge.evaluate()`` translates an exhausted
    chain into an UNAVAILABLE verdict instead of crashing the engagement.

Each test isolates state by clearing the process-wide blacklist with
``ArgusClient.reset_blacklist()`` in a fixture so order-of-execution
doesn't matter.
"""
from __future__ import annotations

import os
from unittest.mock import patch, MagicMock

import pytest

from argus.attacks.judge import (
    LLMJudge,
    JudgeInput,
    _judge_models_from_env,
)
from argus.shared.client import (
    ArgusClient,
    ArgusMessagesAPI,
    AllProvidersExhausted,
    _is_provider_exhausted,
    _resolve_chain,
)
from argus.policy.base import Policy, VerdictKind


# ── fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_blacklist_between_tests():
    """The blacklist is process-wide; tests must start clean."""
    ArgusClient.reset_blacklist()
    yield
    ArgusClient.reset_blacklist()


# ── _is_provider_exhausted (client-level) ─────────────────────────────

@pytest.mark.parametrize("msg", [
    "Error code: 429 - insufficient_quota",
    "You exceeded your current quota, please check your plan",
    "{'message': 'Your credit balance is too low to access the API'}",
    "openai.RateLimitError: rate_limit_exceeded",
    "anthropic.AuthenticationError: invalid_api_key",
    "google.api_core.exceptions.PermissionDenied: 403 PERMISSION_DENIED",
    "401 Unauthorized",
    "402 Payment Required — billing required",
    " 429 too many requests",
])
def test_is_provider_exhausted_matches_known_patterns(msg):
    assert _is_provider_exhausted(Exception(msg)) is True


@pytest.mark.parametrize("msg", [
    "Connection reset by peer",
    "Read timed out",
    "json.decoder.JSONDecodeError: Expecting value",
    "TypeError: cannot serialize 'foo'",
    "Internal Server Error",
    "503 Service Unavailable",        # NOT marked dead — could be transient
])
def test_is_provider_exhausted_passes_transient_errors(msg):
    assert _is_provider_exhausted(Exception(msg)) is False


# ── chain resolution (client-level) ───────────────────────────────────

def test_explicit_chain_kwarg_wins(monkeypatch):
    monkeypatch.setenv("ARGUS_LLM_CHAIN", "env-a,env-b")
    assert _resolve_chain("model-x", ["explicit-1", "explicit-2"]) == [
        "explicit-1", "explicit-2",
    ]


def test_env_chain_used_when_no_explicit(monkeypatch):
    monkeypatch.setenv("ARGUS_LLM_CHAIN", "claude-haiku-4-5,gpt-4o,gemini-2.5-pro")
    chain = _resolve_chain("claude-haiku-4-5", None)
    # caller's model already in env chain → no prepend
    assert chain == ["claude-haiku-4-5", "gpt-4o", "gemini-2.5-pro"]


def test_env_chain_prepends_caller_model_if_absent(monkeypatch):
    monkeypatch.setenv("ARGUS_LLM_CHAIN", "gpt-4o,gemini-2.5-pro")
    chain = _resolve_chain("claude-sonnet-4-5", None)
    assert chain == ["claude-sonnet-4-5", "gpt-4o", "gemini-2.5-pro"]


def test_no_chain_means_single_model(monkeypatch):
    monkeypatch.delenv("ARGUS_LLM_CHAIN", raising=False)
    assert _resolve_chain("only-one", None) == ["only-one"]


def test_chain_drops_empty_tokens(monkeypatch):
    monkeypatch.setenv("ARGUS_LLM_CHAIN", " a , , b ,")
    assert _resolve_chain("a", None) == ["a", "b"]


# ── judge-specific env overrides ──────────────────────────────────────

def test_judge_models_chain_takes_precedence_over_single(monkeypatch):
    monkeypatch.setenv(
        "ARGUS_JUDGE_MODELS",
        "claude-haiku, gpt-4o, gemini-2.5-pro",
    )
    monkeypatch.setenv("ARGUS_JUDGE_MODEL", "should-be-ignored")
    assert _judge_models_from_env() == [
        "claude-haiku", "gpt-4o", "gemini-2.5-pro",
    ]


def test_legacy_single_model_env_still_works(monkeypatch):
    monkeypatch.delenv("ARGUS_JUDGE_MODELS", raising=False)
    monkeypatch.setenv("ARGUS_JUDGE_MODEL", "claude-sonnet-4-5")
    assert _judge_models_from_env() == ["claude-sonnet-4-5"]


def test_neither_judge_env_var_set_returns_legacy_default(monkeypatch):
    monkeypatch.delenv("ARGUS_JUDGE_MODELS", raising=False)
    monkeypatch.delenv("ARGUS_JUDGE_MODEL", raising=False)
    assert _judge_models_from_env() == ["gpt-4o"]


# ── client-level failover via messages.create ─────────────────────────

def _make_client_with_mock_dispatch():
    """Construct an ArgusClient and replace its provider-dispatch
    surface with a MagicMock the test can drive via side_effect /
    return_value."""
    c = ArgusClient()
    # _dispatch is what actually calls a real provider SDK; replacing
    # it lets us simulate per-model success/failure without network I/O.
    c.messages._dispatch = MagicMock()
    return c


def test_failover_first_model_succeeds_no_blacklist():
    c = _make_client_with_mock_dispatch()
    c.messages._dispatch.return_value = "OK"
    result = c.messages.create(
        model="model-a",
        chain=["model-a", "model-b"],
        messages=[{"role": "user", "content": "x"}],
    )
    assert result == "OK"
    assert ArgusClient.blacklist_snapshot() == set()
    assert c.messages._dispatch.call_count == 1
    # First positional arg to _dispatch is the model name
    assert c.messages._dispatch.call_args.args[0] == "model-a"


def test_failover_first_model_exhausted_falls_over_to_second():
    c = _make_client_with_mock_dispatch()
    c.messages._dispatch.side_effect = [
        Exception("Error code: 429 - insufficient_quota"),
        "OK-from-b",
    ]
    result = c.messages.create(
        model="model-a",
        chain=["model-a", "model-b"],
        messages=[{"role": "user", "content": "x"}],
    )
    assert result == "OK-from-b"
    assert ArgusClient.blacklist_snapshot() == {"model-a"}
    assert c.messages._dispatch.call_count == 2


def test_failover_blacklist_persists_across_calls():
    """Once a model is dead, subsequent probes skip it without even
    attempting — that's the whole point: stop burning wall-clock."""
    c = _make_client_with_mock_dispatch()
    c.messages._dispatch.side_effect = [
        Exception("insufficient_quota"),     # call 1: a fails
        "OK-from-b",                         # call 1: b succeeds
        "OK-from-b-again",                   # call 2: should skip a, hit b
    ]
    chain = ["model-a", "model-b"]
    msgs = [{"role": "user", "content": "x"}]
    c.messages.create(model="model-a", chain=chain, messages=msgs)
    c.messages.create(model="model-a", chain=chain, messages=msgs)
    # 3 dispatches total — a once (then dead), b twice
    assert c.messages._dispatch.call_count == 3
    used = [call.args[0] for call in c.messages._dispatch.call_args_list]
    assert used == ["model-a", "model-b", "model-b"]


def test_failover_blacklist_is_process_wide_across_clients():
    """Two ArgusClient instances share the same blacklist (the whole
    point of the migration: judge poisoning Claude stops cve_pipeline
    from retrying it)."""
    c1 = _make_client_with_mock_dispatch()
    c2 = _make_client_with_mock_dispatch()
    c1.messages._dispatch.side_effect = [
        Exception("insufficient_quota"),
        "ok",
    ]
    c2.messages._dispatch.return_value = "ok"
    c1.messages.create(
        model="model-a",
        chain=["model-a", "model-b"],
        messages=[{"role": "user", "content": "x"}],
    )
    # c2 starts a fresh call — model-a should be skipped without
    # even attempting, because c1 already poisoned it.
    c2.messages.create(
        model="model-a",
        chain=["model-a", "model-b"],
        messages=[{"role": "user", "content": "x"}],
    )
    used = [call.args[0] for call in c2.messages._dispatch.call_args_list]
    assert used == ["model-b"]   # NOT ["model-a", "model-b"]


def test_failover_all_models_exhausted_raises_typed_exception():
    c = _make_client_with_mock_dispatch()
    c.messages._dispatch.side_effect = [
        Exception("insufficient_quota"),
        Exception("credit balance is too low"),
    ]
    with pytest.raises(AllProvidersExhausted) as excinfo:
        c.messages.create(
            model="model-a",
            chain=["model-a", "model-b"],
            messages=[{"role": "user", "content": "x"}],
        )
    assert "exhausted" in str(excinfo.value).lower()
    assert ArgusClient.blacklist_snapshot() == {"model-a", "model-b"}


def test_failover_chain_already_fully_dead_raises_without_dispatching():
    """If every model is already in the blacklist (a previous probe
    killed them all), don't even try the SDK — just raise."""
    ArgusMessagesAPI._dead_models.add("model-a")
    c = _make_client_with_mock_dispatch()
    with pytest.raises(AllProvidersExhausted):
        c.messages.create(
            model="model-a",
            chain=["model-a"],
            messages=[{"role": "user", "content": "x"}],
        )
    assert c.messages._dispatch.call_count == 0


def test_failover_non_exhaustion_error_propagates_without_blacklist():
    """A generic transient error (network blip, 503) should NOT
    blacklist the model — those usually recover on the next probe."""
    c = _make_client_with_mock_dispatch()
    c.messages._dispatch.side_effect = ConnectionError(
        "Connection reset by peer"
    )
    with pytest.raises(ConnectionError):
        c.messages.create(
            model="model-a",
            chain=["model-a", "model-b"],
            messages=[{"role": "user", "content": "x"}],
        )
    assert ArgusClient.blacklist_snapshot() == set()


def test_failover_disabled_via_kwarg_raises_on_first_exhaustion():
    """failover=False is the opt-out for harness/test paths that
    explicitly want single-attempt semantics."""
    c = _make_client_with_mock_dispatch()
    c.messages._dispatch.side_effect = Exception("insufficient_quota")
    with pytest.raises(Exception, match="insufficient_quota"):
        c.messages.create(
            model="model-a",
            chain=["model-a", "model-b"],
            messages=[{"role": "user", "content": "x"}],
            failover=False,
        )
    # No blacklist entry created either — pure single-attempt mode
    assert ArgusClient.blacklist_snapshot() == set()


def test_reset_blacklist_clears_state():
    ArgusMessagesAPI._dead_models.add("dead-1")
    ArgusMessagesAPI._dead_models.add("dead-2")
    snapshot = ArgusClient.blacklist_snapshot()
    assert snapshot == {"dead-1", "dead-2"}
    cleared = ArgusClient.reset_blacklist()
    assert cleared == {"dead-1", "dead-2"}
    assert ArgusClient.blacklist_snapshot() == set()


# ── litellm bridge ────────────────────────────────────────────────────

def test_build_litellm_kwargs_anthropic_with_chain(monkeypatch):
    monkeypatch.delenv("ARGUS_LLM_CHAIN", raising=False)
    kw = ArgusClient.build_litellm_kwargs(
        "anthropic",
        "claude-sonnet-4-5",
        chain=["claude-sonnet-4-5", "gpt-4o", "gemini-2.5-pro"],
    )
    assert kw["model"] == "anthropic/claude-sonnet-4-5"
    assert kw["fallbacks"] == ["gpt-4o", "gemini/gemini-2.5-pro"]
    assert "timeout" in kw


def test_build_litellm_kwargs_no_fallbacks_for_single_model(monkeypatch):
    monkeypatch.delenv("ARGUS_LLM_CHAIN", raising=False)
    kw = ArgusClient.build_litellm_kwargs("openai", "gpt-4o")
    assert kw["model"] == "gpt-4o"   # litellm accepts bare openai names
    assert "fallbacks" not in kw


def test_build_litellm_kwargs_inherits_env_chain(monkeypatch):
    monkeypatch.setenv(
        "ARGUS_LLM_CHAIN",
        "claude-sonnet-4-5,gpt-4o",
    )
    kw = ArgusClient.build_litellm_kwargs("anthropic", "claude-sonnet-4-5")
    assert kw["model"] == "anthropic/claude-sonnet-4-5"
    assert kw["fallbacks"] == ["gpt-4o"]


# ── LLMJudge ctor wiring ──────────────────────────────────────────────

def test_judge_ctor_explicit_models_kwarg_wins(monkeypatch):
    monkeypatch.setenv("ARGUS_JUDGE_MODELS", "env-a,env-b")
    j = LLMJudge(models=["explicit-1", "explicit-2"])
    assert j.models == ["explicit-1", "explicit-2"]
    assert j.model == "explicit-1"


def test_judge_ctor_legacy_model_kwarg_wraps_to_chain(monkeypatch):
    monkeypatch.delenv("ARGUS_JUDGE_MODELS", raising=False)
    j = LLMJudge(model="single-legacy")
    assert j.models == ["single-legacy"]
    assert j.model == "single-legacy"


def test_judge_ctor_no_args_uses_env(monkeypatch):
    monkeypatch.setenv("ARGUS_JUDGE_MODELS", "x,y,z")
    j = LLMJudge()
    assert j.models == ["x", "y", "z"]


# ── LLMJudge.evaluate() integration with client failover ──────────────

def _stub_policy() -> Policy:
    return Policy(
        id="ARGUS-POL-TEST",
        name="test",
        description="test policy for failover suite",
        rule="The target must not leak credentials.",
    )


def _judge_input() -> JudgeInput:
    return JudgeInput(
        policy=_stub_policy(),
        probe="test probe",
        response="test response",
        baseline="",
        technique_id="EP-T1-test",
        surface="chat:test",
    )


@patch.dict(os.environ, {"ARGUS_JUDGE": "1", "OPENAI_API_KEY": "fake"})
def test_evaluate_returns_unavailable_when_all_exhausted():
    """End-to-end: every model in chain dies → ``evaluate`` MUST
    return UNAVAILABLE rather than crashing the engagement."""
    j = LLMJudge(models=["model-a", "model-b"])
    j._client.messages._dispatch = MagicMock(side_effect=[
        Exception("Error code: 429 - insufficient_quota"),
        Exception("Your credit balance is too low"),
    ])
    verdict = j.evaluate(_judge_input())
    assert verdict.kind is VerdictKind.UNAVAILABLE
    assert "exhausted" in verdict.reasoning.lower()


@patch.dict(os.environ, {"ARGUS_JUDGE": "1", "OPENAI_API_KEY": "fake"})
def test_evaluate_recovers_via_failover_to_healthy_provider():
    """End-to-end: model-a is dead, model-b returns a parseable
    verdict → ``evaluate`` MUST return that verdict (not UNAVAILABLE)."""
    fake_response = MagicMock()
    fake_response.content = [MagicMock(text=(
        '{"verdict": "COMPLIANT", "confidence": 0.8, '
        '"evidence": "model behaved correctly", '
        '"reasoning": "no policy violation found"}'
    ))]
    j = LLMJudge(models=["model-a", "model-b"])
    j._client.messages._dispatch = MagicMock(side_effect=[
        Exception("insufficient_quota"),
        fake_response,
    ])
    verdict = j.evaluate(_judge_input())
    # Failover succeeded → real verdict, not UNAVAILABLE
    assert verdict.kind is VerdictKind.COMPLIANT
    assert ArgusClient.blacklist_snapshot() == {"model-a"}
