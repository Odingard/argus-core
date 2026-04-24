"""
tests/test_diagnostics_feedback.py — Part A Day 2.

Covers write_diagnostic_feedback + load_prior_for_agent:

  - priors file shape / schema_version
  - per-agent entries for silent agents only
  - EvolveCorpus call count + content (via injected fake)
  - max_corpus_seeds cap
  - idempotency (second write overwrites, entries dedup via
    EvolveCorpus's content-hash id)
  - load_prior_for_agent roundtrip + missing-file safety

Uses a FakeEvolver so no disk writes for the corpus artifacts during
the test; the priors-file write path uses tmp_path.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from argus.diagnostics import (
    DiagnosticReport, SilenceCause, SilentAgentReport,
    load_prior_for_agent, write_diagnostic_feedback,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@dataclass
class _FakeEvolverCall:
    text:       str
    category:   str
    tags:       list
    surfaces:   list
    severity:   str
    target_id:  str
    finding_id: str


class _FakeEvolver:
    """Stand-in for EvolveCorpus — records calls so tests can
    assert on them. Returns a deterministic dict with id=disc_<hash>."""

    def __init__(self, fail_on: Optional[str] = None):
        self.calls:  list[_FakeEvolverCall] = []
        self.fail_on = fail_on

    def add_template(
        self, *, text, category, tags, surfaces,
        severity, target_id, finding_id,
    ):
        if self.fail_on and self.fail_on in text:
            raise RuntimeError(f"corpus write refused: {self.fail_on!r}")
        self.calls.append(_FakeEvolverCall(
            text=text, category=category, tags=list(tags),
            surfaces=list(surfaces), severity=severity,
            target_id=target_id, finding_id=finding_id,
        ))
        return {
            "id":   f"disc_{abs(hash(text)) % 10**10:010d}",
            "text": text, "category": category,
        }


def _silent(agent_id: str,
            cause: SilenceCause,
            *,
            seed: Optional[str] = None) -> SilentAgentReport:
    return SilentAgentReport(
        agent_id=agent_id,
        cause=cause,
        confidence=0.85,
        evidence=f"evidence for {agent_id}",
        remediation_hint=f"hint for {agent_id}",
        corpus_seed_text=seed,
    )


def _mk_report(silent, productive=()) -> DiagnosticReport:
    agg: dict[str, int] = {}
    for r in silent:
        agg[r.cause.value] = agg.get(r.cause.value, 0) + 1
    return DiagnosticReport(
        run_id="run_test", target="mcp://t",
        total_agents=len(silent) + len(productive),
        silent_agents=tuple(silent),
        productive_agents=tuple(productive),
        aggregate_causes=agg,
    )


# ── Priors-file shape ────────────────────────────────────────────────────────

def test_priors_file_schema_and_top_level(tmp_path):
    rep = _mk_report(
        silent=[_silent("PI-02", SilenceCause.TARGET_HARDENED)],
        productive=("SC-09", "TP-02"),
    )
    write_diagnostic_feedback(rep, str(tmp_path))
    doc = json.loads((tmp_path / "diagnostic_priors.json").read_text())
    assert doc["schema_version"] == 1
    assert doc["run_id"] == "run_test"
    assert doc["target"] == "mcp://t"
    assert doc["total_agents"] == 3
    assert doc["silent_count"] == 1
    assert doc["productive_count"] == 2
    assert doc["aggregate_causes"] == {"target_hardened": 1}
    assert set(doc["productive_agents"]) == {"SC-09", "TP-02"}
    assert "generated_at" in doc


def test_per_agent_entries_only_for_silent(tmp_path):
    rep = _mk_report(
        silent=[
            _silent("PI-02", SilenceCause.MODEL_REFUSED),
            _silent("TP-02", SilenceCause.TIMEOUT),
        ],
        productive=("SC-09",),
    )
    write_diagnostic_feedback(rep, str(tmp_path))
    doc = json.loads((tmp_path / "diagnostic_priors.json").read_text())
    assert set(doc["per_agent"].keys()) == {"PI-02", "TP-02"}
    assert "SC-09" not in doc["per_agent"]
    pi = doc["per_agent"]["PI-02"]
    assert pi["cause"] == "model_refused"
    assert pi["confidence"] == 0.85
    assert pi["remediation_hint"].startswith("hint")


def test_priors_file_idempotent(tmp_path):
    """Second write with same report produces same content."""
    rep = _mk_report(silent=[_silent("X", SilenceCause.NO_SIGNAL)])
    write_diagnostic_feedback(rep, str(tmp_path))
    first = (tmp_path / "diagnostic_priors.json").read_text()
    write_diagnostic_feedback(rep, str(tmp_path))
    second = (tmp_path / "diagnostic_priors.json").read_text()
    # generated_at differs between writes; structural content equal.
    d1, d2 = json.loads(first), json.loads(second)
    d1.pop("generated_at"); d2.pop("generated_at")
    assert d1 == d2


def test_empty_report_still_writes_priors_file(tmp_path):
    rep = _mk_report(silent=[], productive=("A", "B", "C"))
    result = write_diagnostic_feedback(rep, str(tmp_path))
    assert (tmp_path / "diagnostic_priors.json").is_file()
    assert result["silent_count"] == 0
    assert result["productive_count"] == 3


# ── EvolveCorpus glue ────────────────────────────────────────────────────────

def test_evolver_receives_one_call_per_seed(tmp_path):
    ev = _FakeEvolver()
    rep = _mk_report(silent=[
        _silent("A", SilenceCause.MODEL_REFUSED,
                seed="refusal-hardened variant A"),
        _silent("B", SilenceCause.MODEL_REFUSED,
                seed="refusal-hardened variant B"),
        _silent("C", SilenceCause.TARGET_HARDENED),   # no seed
    ])
    result = write_diagnostic_feedback(rep, str(tmp_path), evolver=ev)
    assert len(ev.calls) == 2
    assert result["corpus_seeds_written"] == 2
    assert {c.target_id for c in ev.calls} == {"mcp://t"}
    # Tags include from_diagnostic + cause + agent_id
    tags_sets = [set(c.tags) for c in ev.calls]
    assert any("from_diagnostic" in s for s in tags_sets)
    assert any("A" in s or "B" in s for s in tags_sets)


def test_evolver_not_called_when_none(tmp_path):
    """Passing evolver=None must skip the corpus step silently."""
    rep = _mk_report(silent=[
        _silent("A", SilenceCause.MODEL_REFUSED,
                seed="seed text"),
    ])
    result = write_diagnostic_feedback(rep, str(tmp_path), evolver=None)
    assert result["corpus_seeds_written"] == 0


def test_max_corpus_seeds_cap_honoured(tmp_path):
    ev = _FakeEvolver()
    rep = _mk_report(silent=[
        _silent(f"A{i}", SilenceCause.MODEL_REFUSED,
                seed=f"seed {i}")
        for i in range(12)
    ])
    write_diagnostic_feedback(
        rep, str(tmp_path), evolver=ev, max_corpus_seeds=3,
    )
    assert len(ev.calls) == 3


def test_evolver_error_does_not_break_priors_file(tmp_path):
    ev = _FakeEvolver(fail_on="broken")
    rep = _mk_report(silent=[
        _silent("A", SilenceCause.MODEL_REFUSED, seed="broken variant"),
        _silent("B", SilenceCause.MODEL_REFUSED, seed="working variant"),
    ])
    result = write_diagnostic_feedback(rep, str(tmp_path), evolver=ev)
    # Priors file still written
    assert (tmp_path / "diagnostic_priors.json").is_file()
    # One success, one captured error
    assert result["corpus_seeds_written"] == 1
    assert result["corpus_seed_errors"]   == 1


# ── load_prior_for_agent ─────────────────────────────────────────────────────

def test_load_prior_roundtrip(tmp_path):
    rep = _mk_report(silent=[
        _silent("PI-02", SilenceCause.TIMEOUT),
    ])
    write_diagnostic_feedback(rep, str(tmp_path))
    entry = load_prior_for_agent(str(tmp_path), "PI-02")
    assert entry is not None
    assert entry["cause"] == "timeout"
    assert "hint" in entry["remediation_hint"]


def test_load_prior_missing_agent_returns_none(tmp_path):
    rep = _mk_report(silent=[_silent("A", SilenceCause.NO_SIGNAL)])
    write_diagnostic_feedback(rep, str(tmp_path))
    assert load_prior_for_agent(str(tmp_path), "Z") is None


def test_load_prior_missing_file_returns_none(tmp_path):
    assert load_prior_for_agent(str(tmp_path), "PI-02") is None


def test_load_prior_malformed_json_returns_none(tmp_path):
    (tmp_path / "diagnostic_priors.json").write_text("not json")
    assert load_prior_for_agent(str(tmp_path), "PI-02") is None


# ── Public API ───────────────────────────────────────────────────────────────

def test_public_api():
    import argus.diagnostics as d
    assert d.write_diagnostic_feedback is write_diagnostic_feedback
    assert d.load_prior_for_agent is load_prior_for_agent
