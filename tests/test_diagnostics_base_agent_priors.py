"""
tests/test_diagnostics_base_agent_priors.py — Day 4.

Covers BaseAgent._load_diagnostic_priors + _haiku prepend. The LLM
call is mocked via a stub ArgusClient so no network traffic.

The contract this locks in:

  - Agent with no prior file → self.diagnostic_prior stays None,
    _haiku prompt unchanged.
  - Agent run AFTER a prior run's diagnostic → loads the per-agent
    entry from the sibling run-dir, injects a remediation-hint
    prefix into every _haiku prompt.
  - Malformed / missing priors file → silent no-op, agent still
    functional.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from argus.agents.base import BaseAgent


class _StubAgent(BaseAgent):
    """Minimal concrete agent so we can instantiate BaseAgent in tests."""
    AGENT_ID = "TEST-01"
    AGENT_NAME = "Test Stub"

    def run(self, target, repo_path, output_dir):
        return []

    @property
    def technique_library(self):
        return {}


class _StubResp:
    def __init__(self, text):
        class _Block:
            def __init__(self, t): self.text = t
        self.content = [_Block(text)]


@pytest.fixture
def stub_agent():
    with patch("argus.agents.base.ArgusClient") as mock_cls:
        mock = mock_cls.return_value
        # Track the last-seen prompt so tests can assert on it.
        mock.messages.create.return_value = _StubResp(
            '{"result": "ok"}'
        )
        mock.last_prompt = None

        def _capture(model, max_tokens, messages):
            mock.last_prompt = messages[0]["content"]
            return _StubResp('{"result": "ok"}')

        mock.messages.create.side_effect = _capture
        agent = _StubAgent(verbose=False)
        agent.client = mock
        yield agent, mock


# ── Prior loading ────────────────────────────────────────────────────────────

def test_no_prior_file_leaves_attribute_none(stub_agent, tmp_path):
    agent, _ = stub_agent
    run_dir = tmp_path / "run_2"
    run_dir.mkdir()
    agent._load_diagnostic_priors(str(run_dir))
    assert agent.diagnostic_prior is None


def test_prior_loaded_from_explicit_dir(stub_agent, tmp_path):
    """Caller passes the PRIOR run's directory directly — no
    sibling-walking magic, no heuristic guessing."""
    agent, _ = stub_agent
    prior_run = tmp_path / "prior"
    prior_run.mkdir()
    (prior_run / "diagnostic_priors.json").write_text(json.dumps({
        "schema_version": 1,
        "per_agent": {
            "TEST-01": {
                "cause": "model_refused",
                "confidence": 0.85,
                "evidence": "I can't help with that",
                "remediation_hint":
                    "reframe as audit request",
            },
        },
    }))
    agent._load_diagnostic_priors(str(prior_run))
    assert agent.diagnostic_prior is not None
    assert agent.diagnostic_prior["cause"] == "model_refused"


def test_prior_for_other_agent_id_ignored(stub_agent, tmp_path):
    agent, _ = stub_agent
    (tmp_path / "diagnostic_priors.json").write_text(json.dumps({
        "per_agent": {
            "OTHER-42": {
                "cause": "no_signal",
                "remediation_hint": "hint for someone else",
            },
        },
    }))
    agent._load_diagnostic_priors(str(tmp_path))
    assert agent.diagnostic_prior is None


def test_malformed_priors_file_silent_noop(stub_agent, tmp_path):
    agent, _ = stub_agent
    (tmp_path / "diagnostic_priors.json").write_text("not json")
    # Should not raise
    agent._load_diagnostic_priors(str(tmp_path))
    assert agent.diagnostic_prior is None


# ── _haiku prompt prepend ────────────────────────────────────────────────────

def test_haiku_prompt_unchanged_when_no_prior(stub_agent):
    agent, mock = stub_agent
    agent._haiku("find vulnerabilities in this tool")
    assert "prior-run diagnostic hint" not in mock.last_prompt


def test_haiku_prompt_gets_hint_when_prior_set(stub_agent):
    agent, mock = stub_agent
    agent.diagnostic_prior = {
        "cause": "target_hardened",
        "remediation_hint":
            "shift focus to cross-tool chains on this run",
    }
    agent._haiku("find vulnerabilities in this tool")
    assert "prior-run diagnostic hint for TEST-01" in mock.last_prompt
    assert "cross-tool chains" in mock.last_prompt


def test_haiku_prompt_skips_hint_when_hint_empty(stub_agent):
    agent, mock = stub_agent
    agent.diagnostic_prior = {
        "cause": "no_signal",
        "remediation_hint": "",  # empty hint → skip
    }
    agent._haiku("original prompt content")
    assert "prior-run diagnostic hint" not in mock.last_prompt


def test_haiku_hint_appears_before_original_prompt(stub_agent):
    agent, mock = stub_agent
    agent.diagnostic_prior = {"remediation_hint": "try option A first"}
    agent._haiku("CONTENT_MARKER")
    idx_hint = mock.last_prompt.find("try option A first")
    idx_body = mock.last_prompt.find("CONTENT_MARKER")
    assert 0 <= idx_hint < idx_body  # hint precedes body


# ── End-to-end integration shape ─────────────────────────────────────────────

def test_end_to_end_run_to_run_feedback(stub_agent, tmp_path):
    """The loop: Run-1 produced a diagnostic file; Run-2 agent picks
    it up; Run-2's _haiku prompt carries the prior hint. This is the
    contract Day-4 exists to prove."""
    agent, mock = stub_agent

    # Simulate Run-1 feedback landing in its own dir.
    run1 = tmp_path / "run_20260424_050000"
    run1.mkdir()
    (run1 / "diagnostic_priors.json").write_text(json.dumps({
        "per_agent": {
            "TEST-01": {
                "cause": "target_hardened",
                "remediation_hint":
                    "target enforced scope on every probe; "
                    "pivot to timing side-channels",
            },
        },
    }))

    # Run-2: operator points the agent at Run-1's directory.
    agent._load_diagnostic_priors(str(run1))

    # First Haiku call from Run-2 carries the hint.
    agent._haiku("probe surface X")
    assert "pivot to timing side-channels" in mock.last_prompt
