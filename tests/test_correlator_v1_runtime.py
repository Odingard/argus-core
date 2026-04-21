"""
tests/test_correlator_v1_runtime.py — Phase 2 Correlation Agent v1 retarget.

Verifies the correlator now clusters runtime (behavior-delta) findings
by target and surface, not just by file path. No LLM calls — we test
the cluster-selection layer directly.
"""
from __future__ import annotations

import threading

from argus.agents.base import AgentFinding
from argus.swarm.blackboard import Blackboard
from argus.swarm.correlator import (
    LiveCorrelator, _finding_summary, _runtime_target,
)


# ── _runtime_target ──────────────────────────────────────────────────────────

def test_runtime_target_extracts_from_scoped_baseline_ref():
    f = AgentFinding(
        id="f1", agent_id="PI-01", vuln_class="PROMPT_INJECTION",
        severity="HIGH", title="t", description="d",
        evidence_kind="behavior_delta",
        baseline_ref="mcp://customer.example::session42",
    )
    assert _runtime_target(f) == "mcp://customer.example"


def test_runtime_target_returns_empty_for_static_finding():
    f = AgentFinding(
        id="f2", agent_id="X", vuln_class="Y",
        severity="LOW", title="t", description="d",
        file="src/foo.py",           # static path
    )
    assert _runtime_target(f) == ""


def test_runtime_target_falls_back_to_raw_ref_for_runtime_without_scope():
    f = AgentFinding(
        id="f3", agent_id="MP-03", vuln_class="MEMORY_POISONING",
        severity="HIGH", title="t", description="d",
        evidence_kind="behavior_delta",
        baseline_ref="a2a://customer.fabric",
    )
    assert _runtime_target(f) == "a2a://customer.fabric"


# ── _finding_summary ─────────────────────────────────────────────────────────

def test_finding_summary_includes_runtime_provenance():
    f = AgentFinding(
        id="abc", agent_id="CW-05", vuln_class="CONTEXT_WINDOW",
        severity="HIGH", title="t", description="a thing happened",
        evidence_kind="behavior_delta",
        attack_variant_id="CW-T1-gradual-escalation",
        surface="chat",
        session_id="CW-05_longcon_xyz",
        verdict_kind="CONTENT_LEAK",
    )
    s = _finding_summary(f)
    assert "CW-05" in s
    assert "CONTEXT_WINDOW" in s
    assert "CW-T1-gradual-escalation" in s
    assert "surface=chat" in s
    assert "session=" in s
    assert "verdict=CONTENT_LEAK" in s


def test_finding_summary_falls_back_for_static_finding():
    f = AgentFinding(
        id="abc", agent_id="L1", vuln_class="RCE",
        severity="HIGH", title="t", description="static vuln",
        file="src/foo.py", technique="legacy-T1",
    )
    s = _finding_summary(f)
    assert "file=src/foo.py" in s
    assert "session=" not in s
    assert "verdict=" not in s


# ── _candidate_clusters on a real LiveCorrelator ─────────────────────────────

def _make_correlator(tmp_path) -> LiveCorrelator:
    bb = Blackboard(run_dir=str(tmp_path))
    return LiveCorrelator(
        blackboard=bb,
        agent_registry={},
        stop_event=threading.Event(),
        verbose=False,
    )


def _runtime_finding(
    *,
    id: str, agent_id: str, target: str, surface: str = "chat",
) -> AgentFinding:
    return AgentFinding(
        id=id, agent_id=agent_id, vuln_class="X",
        severity="HIGH", title="t", description="d",
        evidence_kind="behavior_delta",
        baseline_ref=f"{target}::baseline",
        surface=surface,
        attack_variant_id=f"{agent_id}-v1",
    )


def test_candidate_clusters_runtime_same_target(tmp_path):
    cor = _make_correlator(tmp_path)
    f1 = _runtime_finding(id="1", agent_id="PI-01",
                          target="mcp://x", surface="chat")
    f2 = _runtime_finding(id="2", agent_id="TP-02",
                          target="mcp://x", surface="tool:foo")

    # Seed the correlator with f1, then evaluate clusters for f2.
    cor._seen.append(type("S", (), {"finding": f1, "ts_mono": 0.0})())
    clusters = cor._candidate_clusters(f2)

    # Expect ≥1 cluster that pairs f1 with f2.
    assert any(set(f.id for f in c) == {"1", "2"} for c in clusters), (
        f"runtime-same-target rule did not fire; clusters={[[f.id for f in c] for c in clusters]}"
    )


def test_candidate_clusters_runtime_same_surface(tmp_path):
    cor = _make_correlator(tmp_path)
    f1 = _runtime_finding(id="a", agent_id="PI-01",
                          target="mcp://a", surface="tool:delete_user")
    f2 = _runtime_finding(id="b", agent_id="TP-02",
                          target="mcp://b",                 # different target
                          surface="tool:delete_user")       # SAME surface
    cor._seen.append(type("S", (), {"finding": f1, "ts_mono": 0.0})())
    clusters = cor._candidate_clusters(f2)
    assert any(set(f.id for f in c) == {"a", "b"} for c in clusters)


def test_candidate_clusters_ignores_static_file_when_empty(tmp_path):
    """Runtime findings have f.file == '' — the legacy same-file rule
    must not cross-cluster them just because both are empty strings."""
    cor = _make_correlator(tmp_path)
    f1 = AgentFinding(
        id="x1", agent_id="PI-01", vuln_class="X",
        severity="HIGH", title="t", description="d",
        evidence_kind="behavior_delta",
        baseline_ref="mcp://a::baseline",
        surface="",               # explicitly no surface
        file="",
    )
    f2 = AgentFinding(
        id="x2", agent_id="TP-02", vuln_class="X",
        severity="HIGH", title="t", description="d",
        evidence_kind="behavior_delta",
        baseline_ref="mcp://b::baseline",
        surface="",
        file="",
    )
    cor._seen.append(type("S", (), {"finding": f1, "ts_mono": 0.0})())
    clusters = cor._candidate_clusters(f2)

    # No same-file, no same-target, no same-surface — should not pair these.
    # (The rolling-window rule needs ≥3 findings; we only have 2.)
    # MAAC pair rule requires agent registry, which we didn't supply.
    assert not any(set(f.id for f in c) == {"x1", "x2"} for c in clusters), (
        "empty-string file/surface/target incorrectly clustered"
    )


def test_candidate_clusters_still_catches_static_same_file(tmp_path):
    """Legacy static-file rule must still fire for historical findings."""
    cor = _make_correlator(tmp_path)
    f1 = AgentFinding(
        id="s1", agent_id="L1", vuln_class="X", severity="HIGH",
        title="t", description="d", file="src/foo.py",
    )
    f2 = AgentFinding(
        id="s2", agent_id="L2", vuln_class="X", severity="HIGH",
        title="t", description="d", file="src/foo.py",
    )
    cor._seen.append(type("S", (), {"finding": f1, "ts_mono": 0.0})())
    clusters = cor._candidate_clusters(f2)
    assert any(set(f.id for f in c) == {"s1", "s2"} for c in clusters)
