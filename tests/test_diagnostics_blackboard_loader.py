"""
tests/test_diagnostics_blackboard_loader.py — Day 3 wiring support.

Covers the blackboard-backed LogLoader:

  - Missing file → returns loader that yields empty string for every id
  - Indexing events by agent_id / posted_by / trigger_agents / source
  - Event-to-text flattening captures the fields the classifier
    pattern-matches against (title, raw_response, observed_behavior)
  - Per-agent cap honoured so runaway logs can't explode the
    pattern matchers
"""
from __future__ import annotations

import json

from argus.diagnostics.blackboard_loader import (
    build_blackboard_log_loader,
)


def _write_blackboard(tmp_path, events):
    """Write a sequence of event dicts to the expected jsonl path."""
    path = tmp_path / "swarm_blackboard.jsonl"
    lines = [json.dumps(e) for e in events]
    path.write_text("\n".join(lines) + "\n")
    return path


# ── Missing-file safety ───────────────────────────────────────────────────────

def test_missing_file_returns_empty_loader(tmp_path):
    loader = build_blackboard_log_loader(str(tmp_path))
    assert loader("PI-02") == ""
    assert loader("anything") == ""


def test_malformed_jsonl_skips_bad_lines(tmp_path):
    path = tmp_path / "swarm_blackboard.jsonl"
    path.write_text(
        'not json at all\n'
        + json.dumps({"kind": "finding", "data": {
            "agent_id": "PI-02", "title": "valid"}}) + '\n'
        + '{"broken json\n'
    )
    loader = build_blackboard_log_loader(str(tmp_path))
    text = loader("PI-02")
    assert "valid" in text


# ── Indexing ──────────────────────────────────────────────────────────────────

def test_finding_indexed_by_agent_id(tmp_path):
    _write_blackboard(tmp_path, [
        {"kind": "finding", "data": {
            "agent_id": "PI-02", "title": "T1",
            "observed_behavior": "echoed payload",
            "raw_response": "response bytes",
        }},
        {"kind": "finding", "data": {
            "agent_id": "TP-02", "title": "T2",
        }},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    pi = loader("PI-02")
    tp = loader("TP-02")
    assert "T1" in pi and "echoed payload" in pi and "response bytes" in pi
    assert "T2" in tp
    assert "T1" not in tp


def test_hot_file_indexed_by_posted_by(tmp_path):
    _write_blackboard(tmp_path, [
        {"kind": "hot_file", "data": {
            "posted_by": "SC-09", "path": "/etc", "reason": "target rich",
        }},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    assert "target rich" in loader("SC-09")


def test_hypothesis_indexed_by_trigger_agents(tmp_path):
    _write_blackboard(tmp_path, [
        {"kind": "hypothesis", "data": {
            "trigger_agents": ["MP-03", "IS-04"],
            "title": "chained memory poison → identity spoof",
        }},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    assert "chained memory poison" in loader("MP-03")
    assert "chained memory poison" in loader("IS-04")


def test_annotation_indexed_by_source(tmp_path):
    _write_blackboard(tmp_path, [
        {"kind": "annotation", "data": {
            "finding_id": "f1",
            "key": "opus_chain",
            "value": {
                "source": "ME-10",
                "chain_title": "model-extraction chain",
            },
        }},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    me = loader("ME-10")
    assert "opus_chain" in me
    assert "model-extraction chain" in me


def test_unknown_agent_id_returns_empty(tmp_path):
    _write_blackboard(tmp_path, [
        {"kind": "finding", "data": {"agent_id": "PI-02", "title": "x"}},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    assert loader("UNKNOWN-99") == ""


# ── Event-to-text flattening ─────────────────────────────────────────────────

def test_event_text_captures_validation_error_shape(tmp_path):
    """A finding whose raw_response would trip the validation-error
    guard must have that text in the agent's log blob so the
    classifier can match on it."""
    _write_blackboard(tmp_path, [
        {"kind": "finding", "data": {
            "agent_id": "PI-02",
            "title": "reflected payload",
            "raw_response": "Error executing tool: Note 'x' not found",
        }},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    text = loader("PI-02")
    assert "error executing tool" in text.lower()
    assert "not found" in text.lower()


def test_event_text_captures_timeout_shape(tmp_path):
    """Timeout shape comes through an annotation or observed_behavior."""
    _write_blackboard(tmp_path, [
        {"kind": "finding", "data": {
            "agent_id": "TP-02",
            "title": "probe timeout",
            "observed_behavior": "asyncio.TimeoutError after 30s",
        }},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    assert "asyncio.timeouterror" in loader("TP-02").lower()


# ── Per-agent cap ────────────────────────────────────────────────────────────

def test_per_agent_cap_honoured(tmp_path):
    huge_resp = "x" * 5000
    _write_blackboard(tmp_path, [
        {"kind": "finding", "data": {
            "agent_id": "PI-02",
            "title": "one",
            "raw_response": huge_resp,
        }},
        {"kind": "finding", "data": {
            "agent_id": "PI-02",
            "title": "two",
            "raw_response": huge_resp,
        }},
        {"kind": "finding", "data": {
            "agent_id": "PI-02",
            "title": "three",
            "raw_response": huge_resp,
        }},
    ])
    loader = build_blackboard_log_loader(
        str(tmp_path), max_chars_per_agent=1000,
    )
    text = loader("PI-02")
    # Cap applied; the cap is nominal (~1000 chars) — the loader
    # concatenates chunks and trims the one that would overflow.
    assert len(text) < 2000


# ── Multi-field agent attribution ────────────────────────────────────────────

def test_event_with_multiple_agent_fields_indexed_once(tmp_path):
    """A finding that lists the same agent in both agent_id and
    posted_by should not duplicate into the same bucket."""
    _write_blackboard(tmp_path, [
        {"kind": "finding", "data": {
            "agent_id": "PI-02",
            "posted_by": "PI-02",
            "title": "dedup me",
        }},
    ])
    loader = build_blackboard_log_loader(str(tmp_path))
    text = loader("PI-02")
    assert text.count("dedup me") == 1
