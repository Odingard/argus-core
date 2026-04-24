"""
tests/test_mcp_attacker_consensus.py — PRO consensus-gate wiring.

Exercises:
  1. The severity extractor handles JSON + regex fallback + edge cases.
  2. The response-text extractor handles anthropic / openai / google
     response shapes.
  3. The full _apply_consensus_gate flow — with the three judges mocked
     out — downgrades disagreed findings and preserves agreed ones.
  4. License-off path: when argus.pro.consensus.require raises, the
     gate is a silent no-op.

Deterministic end-to-end. No network.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from argus.mcp_attacker.mcp_live_attacker import (
    MCPFinding,
    _apply_consensus_gate,
    _extract_response_text,
    _parse_consensus_severity,
)


def _mk(**kw) -> MCPFinding:
    base = dict(
        id="f00", phase="SCHEMA", severity="HIGH",
        vuln_class="TRACE_LATERAL",
        title="t", tool_name="x", payload_used="p",
        observed_behavior="", expected_behavior="",
        poc=None, cvss_estimate=None, remediation=None,
        raw_response="r",
    )
    base.update(kw)
    return MCPFinding(**base)


# ── Severity parsing ─────────────────────────────────────────────────────────

def test_parse_severity_clean_json():
    assert _parse_consensus_severity(
        '{"severity": "HIGH", "reasoning": "solid PoC"}'
    ) == "HIGH"


def test_parse_severity_handles_markdown_fence():
    assert _parse_consensus_severity(
        '```json\n{"severity": "MEDIUM", "reasoning": "x"}\n```'
    ) == "MEDIUM"


def test_parse_severity_regex_fallback_when_json_broken():
    assert _parse_consensus_severity(
        "After reviewing, I'd grade this as LOW — unexploitable."
    ) == "LOW"


def test_parse_severity_rejects_unknown_labels():
    assert _parse_consensus_severity(
        '{"severity": "WEAPONS-GRADE"}'
    ) is None


def test_parse_severity_empty_returns_none():
    assert _parse_consensus_severity("") is None
    assert _parse_consensus_severity(None) is None


# ── Response text extraction ─────────────────────────────────────────────────

class _AnthropicBlock:
    def __init__(self, text): self.text = text

class _AnthropicResp:
    def __init__(self, text):
        self.content = [_AnthropicBlock(text)]

class _OpenAIMessage:
    def __init__(self, content): self.content = content

class _OpenAIChoice:
    def __init__(self, content):
        self.message = _OpenAIMessage(content)

class _OpenAIResp:
    def __init__(self, content):
        self.choices = [_OpenAIChoice(content)]

class _GoogleResp:
    def __init__(self, text): self.text = text


def test_extract_text_anthropic_shape():
    r = _AnthropicResp('{"severity": "HIGH"}')
    assert _extract_response_text(r) == '{"severity": "HIGH"}'


def test_extract_text_openai_shape():
    r = _OpenAIResp('{"severity": "MEDIUM"}')
    assert _extract_response_text(r) == '{"severity": "MEDIUM"}'


def test_extract_text_google_shape():
    r = _GoogleResp('{"severity": "LOW"}')
    assert _extract_response_text(r) == '{"severity": "LOW"}'


def test_extract_text_none_safe():
    assert _extract_response_text(None) == ""


# ── Full gate flow ───────────────────────────────────────────────────────────

def _fake_votes(vote_tuples):
    """Factory: given a sequence of severities, return an async
    coroutine that yields them in order (simulating 3 judges)."""
    async def _fake_poll(finding, verbose):
        return list(vote_tuples)
    return _fake_poll


@pytest.mark.asyncio
async def test_gate_noop_when_no_high_findings():
    findings = [_mk(severity="MEDIUM"), _mk(severity="LOW")]
    with patch(
        "argus.mcp_attacker.mcp_live_attacker._poll_consensus_judges",
        side_effect=AssertionError("should not be polled"),
    ):
        out = await _apply_consensus_gate(findings)
    assert [f.severity for f in out] == ["MEDIUM", "LOW"]


@pytest.mark.asyncio
async def test_gate_unanimous_high_preserves_severity():
    f = _mk(severity="HIGH")
    with patch(
        "argus.mcp_attacker.mcp_live_attacker._poll_consensus_judges",
        new=_fake_votes(["HIGH", "HIGH", "HIGH"]),
    ):
        out = await _apply_consensus_gate([f])
    assert out[0].severity == "HIGH"
    assert "[consensus:" not in (out[0].observed_behavior or "")


@pytest.mark.asyncio
async def test_gate_2_of_3_high_preserves_severity():
    """Agreement threshold is 2-of-M; 2 HIGH votes is enough."""
    f = _mk(severity="HIGH")
    with patch(
        "argus.mcp_attacker.mcp_live_attacker._poll_consensus_judges",
        new=_fake_votes(["HIGH", "MEDIUM", "HIGH"]),
    ):
        out = await _apply_consensus_gate([f])
    assert out[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_gate_1_of_3_high_downgrades():
    """Only 1 judge agreed HIGH — downgrade to MEDIUM with annotation."""
    f = _mk(severity="HIGH")
    with patch(
        "argus.mcp_attacker.mcp_live_attacker._poll_consensus_judges",
        new=_fake_votes(["HIGH", "LOW", "MEDIUM"]),
    ):
        out = await _apply_consensus_gate([f])
    assert out[0].severity == "MEDIUM"
    assert "[consensus:" in out[0].observed_behavior
    assert "1/3" in out[0].observed_behavior


@pytest.mark.asyncio
async def test_gate_critical_downgrades_to_high_when_disagreed():
    f = _mk(severity="CRITICAL")
    with patch(
        "argus.mcp_attacker.mcp_live_attacker._poll_consensus_judges",
        new=_fake_votes(["CRITICAL", "HIGH", "HIGH"]),
    ):
        out = await _apply_consensus_gate([f])
    assert out[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_gate_skips_when_too_few_judges_voted():
    """If only 1 of 3 judges returned a vote (rate-limits etc.), the
    gate must NOT apply — we'd rather keep the original than make a
    decision on sparse signal."""
    f = _mk(severity="HIGH")
    with patch(
        "argus.mcp_attacker.mcp_live_attacker._poll_consensus_judges",
        new=_fake_votes(["LOW"]),   # only 1 judge responded
    ):
        out = await _apply_consensus_gate([f])
    assert out[0].severity == "HIGH"                # untouched
    assert "[consensus:" not in (out[0].observed_behavior or "")


@pytest.mark.asyncio
async def test_gate_noop_when_pro_license_missing():
    """If argus.pro.consensus.require_agreement can't be imported
    (license enforcement), the gate is a silent no-op. Mocked by
    monkey-patching the consensus import path."""
    f = _mk(severity="HIGH")
    import sys
    import argus.pro.consensus  # noqa: F401 — import triggers registration
    saved = sys.modules.get("argus.pro.consensus")
    try:
        sys.modules["argus.pro.consensus"] = None   # trigger ImportError
        # The gate's `from argus.pro.consensus import require_agreement`
        # should catch and return findings unchanged.
        out = await _apply_consensus_gate([f])
    finally:
        sys.modules["argus.pro.consensus"] = saved
    assert out[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_gate_only_touches_high_critical():
    """MEDIUM/LOW findings are not polled and pass through."""
    findings = [
        _mk(id="m", severity="MEDIUM"),
        _mk(id="h", severity="HIGH"),
        _mk(id="l", severity="LOW"),
    ]
    with patch(
        "argus.mcp_attacker.mcp_live_attacker._poll_consensus_judges",
        new=_fake_votes(["MEDIUM", "MEDIUM", "MEDIUM"]),  # disagree
    ):
        out = await _apply_consensus_gate(findings)
    by_id = {f.id: f for f in out}
    assert by_id["m"].severity == "MEDIUM"           # untouched
    assert by_id["l"].severity == "LOW"              # untouched
    assert by_id["h"].severity == "MEDIUM"           # downgraded
