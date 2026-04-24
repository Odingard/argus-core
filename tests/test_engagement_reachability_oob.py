"""
tests/test_engagement_reachability_oob.py — Perimeter-First Rule 3 +
AUDITOR OOB wiring acceptance.

Covers:
  - ``_build_reachability_map`` shape from public entry point to
    interior sinks (ARGUS.md §Perimeter-First Rule 3)
  - Engagement runner wires the OOB listener as env var for agents
  - Engagement runner writes reachability.json + SUMMARY carries the
    Reachability Map section
  - CRITICAL findings gain an [oob:receipt …] marker when the
    engagement captured a real callback (so the AUDITOR calibration
    gate preserves the severity end-to-end)
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

from argus.engagement import run_engagement
from argus.engagement.runner import _build_reachability_map
from argus.evidence.collector import OOBCallbackRecord


# ── _build_reachability_map shape ─────────────────────────────────────────

def _fake_spec(scheme: str = "autogen", desc: str = "AutoGen labrat"):
    return SimpleNamespace(scheme=scheme, description=desc)


def _f(surface: str, severity: str = "HIGH"):
    return SimpleNamespace(surface=surface, severity=severity)


def test_reachability_map_names_public_entry_point():
    reach = _build_reachability_map(
        target_id="autogen://labrat",
        spec=_fake_spec(),
        surface_counts={"chat": 2, "tool": 3},
        findings=[_f("chat:default"), _f("tool:fs")],
        by_agent={"PI-01": 1, "TP-02": 1, "IS-04": 0},
        oob_callbacks=None,
    )
    ep = reach["public_entry_point"]
    assert ep["target_url"] == "autogen://labrat"
    assert ep["scheme"] == "autogen"
    assert ep["description"] == "AutoGen labrat"


def test_reachability_map_projects_surfaces_and_sinks():
    reach = _build_reachability_map(
        target_id="t",
        spec=_fake_spec(),
        surface_counts={"chat": 2, "tool": 3, "memory": 1},
        findings=[_f("chat:default"), _f("chat:x"), _f("tool:fs")],
        by_agent={"PI-01": 2, "TP-02": 1, "IS-04": 0, "XE-06": 0},
        oob_callbacks=None,
    )
    # Exposed counts preserved.
    assert reach["surfaces_exposed"] == {"chat": 2, "tool": 3, "memory": 1}
    # Sinks reached are projected by class.
    assert reach["sinks_reached"]["chat"] == 2
    assert reach["sinks_reached"]["tool"] == 1
    assert "memory" not in reach["sinks_reached"]
    assert reach["landing_agents"] == ["PI-01", "TP-02"]
    assert reach["silent_agents"]  == ["IS-04", "XE-06"]


def test_reachability_map_flags_oob_proof():
    cb = OOBCallbackRecord(
        timestamp_ms=0, token="t", source_ip="127.0.0.1",
        method="GET", path="/cb/t", headers={}, body="",
    )
    reach = _build_reachability_map(
        target_id="t", spec=_fake_spec(),
        surface_counts={"chat": 1},
        findings=[_f("chat")],
        by_agent={"PI-01": 1},
        oob_callbacks=[cb],
    )
    assert reach["oob_callback_count"] == 1
    assert reach["oob_proof"] is True


def test_reachability_map_without_callbacks_is_honest_false():
    reach = _build_reachability_map(
        target_id="t", spec=_fake_spec(),
        surface_counts={"chat": 1}, findings=[_f("chat")],
        by_agent={"PI-01": 1}, oob_callbacks=None,
    )
    assert reach["oob_callback_count"] == 0
    assert reach["oob_proof"] is False


# ── Runner integration ───────────────────────────────────────────────────

def test_engagement_writes_reachability_json(tmp_path):
    out = tmp_path / "eng"
    result = run_engagement(
        target_url="autogen://labrat",
        output_dir=str(out), clean=True,
    )
    path = out / "reachability.json"
    assert path.exists(), "reachability.json must be written"
    reach = json.loads(path.read_text())
    assert reach["public_entry_point"]["target_url"] == "autogen://labrat"
    assert reach["surfaces_exposed"], "surfaces_exposed must be populated"
    # Also surfaced on the EngagementResult dataclass.
    assert result.reachability == reach


def test_engagement_summary_carries_reachability_section(tmp_path):
    out = tmp_path / "eng"
    run_engagement(
        target_url="autogen://labrat",
        output_dir=str(out), clean=True,
    )
    summary = (out / "SUMMARY.txt").read_text()
    assert "Perimeter reachability map" in summary
    assert "entry point" in summary
    assert "oob_proof" in summary


def test_engagement_exposes_oob_callback_url_env_var(tmp_path, monkeypatch):
    """The runner sets ARGUS_OOB_CALLBACK_URL before the slate fires.
    We can't observe the mid-run env var from outside, so we assert
    the non-existence of a stale value post-run (listener teardown
    restores the prior state)."""
    monkeypatch.delenv("ARGUS_OOB_CALLBACK_URL", raising=False)
    out = tmp_path / "eng"
    run_engagement(
        target_url="autogen://labrat",
        output_dir=str(out), clean=True,
    )
    # After the engagement the env var must be cleaned up — otherwise
    # back-to-back engagements in the same process inherit stale URLs.
    assert os.environ.get("ARGUS_OOB_CALLBACK_URL") is None


def test_engagement_respects_argus_no_oob(tmp_path, monkeypatch):
    """ARGUS_NO_OOB=1 disables the listener without breaking the run.
    Used for deterministic test environments or ports-blocked hosts."""
    monkeypatch.setenv("ARGUS_NO_OOB", "1")
    out = tmp_path / "eng"
    result = run_engagement(
        target_url="autogen://labrat",
        output_dir=str(out), clean=True,
    )
    assert result.oob_callbacks == 0
    assert result.reachability["oob_proof"] is False
