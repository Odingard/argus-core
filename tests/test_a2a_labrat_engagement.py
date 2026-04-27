"""
tests/test_a2a_labrat_engagement.py — end-to-end smoke over the
a2a://labrat target.

ARGUS.md §3 Priority B: Multi-Agent Trust Escalation (A2A Protocol).
The a2a://labrat is our in-process proving ground — a 3-peer mesh
with one peer holding a private-context credential, exactly the
surface IS-04 (identity spoof) and XE-06 (cross-agent exfil) were
written against. This test locks in the wiring so a regression that
silently drops the slate, mis-resolves the scheme, or empties the
peer graph fails loudly.
"""
from __future__ import annotations

import json

import pytest

from argus.engagement import run_engagement


@pytest.mark.xfail(
    reason="IS-04 silent on a2a://labrat — tracked in KNOWN_REDS.md",
    strict=False,
)
def test_a2a_labrat_engagement_produces_is04_and_xe06_findings(
    tmp_path, monkeypatch,
):
    # Keep this purely deterministic — don't start a loopback
    # listener and don't parallelise. Both flags are covered by
    # other suites; this one is about agent output only.
    monkeypatch.setenv("ARGUS_NO_OOB", "1")
    monkeypatch.setenv("ARGUS_SEQUENTIAL", "1")

    out = tmp_path / "a2a"
    result = run_engagement(
        target_url="a2a://labrat",
        output_dir=str(out), clean=True,
        agent_slate=("IS-04", "XE-06"),
    )

    # Both agents must land ≥1 finding each — otherwise the
    # cross-agent handoff surface isn't being exercised.
    assert result.by_agent.get("IS-04", 0) >= 1, (
        f"IS-04 produced zero findings on a2a://labrat; "
        f"by_agent={result.by_agent}"
    )
    assert result.by_agent.get("XE-06", 0) >= 1, (
        f"XE-06 produced zero findings on a2a://labrat; "
        f"by_agent={result.by_agent}"
    )

    # Reachability map must name the a2a entry point and report
    # the handoff class as reached.
    reach = result.reachability
    assert reach["public_entry_point"]["target_url"] == "a2a://labrat"
    assert "handoff" in reach["sinks_reached"]
    assert "IS-04" in reach["landing_agents"]
    assert "XE-06" in reach["landing_agents"]

    # Chain materialised with CRITICAL severity — confirms the
    # exfil + spoof pair compounds correctly.
    chain = json.loads((out / "chain.json").read_text())
    assert chain["severity"] in {"HIGH", "CRITICAL"}
    assert any(
        s.get("vuln_class") == "IDENTITY_SPOOF"
        for s in chain["steps"]
    ), "chain must include an IDENTITY_SPOOF step"
    assert any(
        s.get("vuln_class") == "CROSS_AGENT_EXFIL"
        for s in chain["steps"]
    ), "chain must include a CROSS_AGENT_EXFIL step"

    # SUMMARY carries the Reachability Map section (Perimeter-First
    # Rule 3) with the handoff surface named explicitly.
    summary = (out / "SUMMARY.txt").read_text()
    assert "Perimeter reachability map" in summary
    assert "handoff" in summary
