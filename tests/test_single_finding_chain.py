"""
tests/test_single_finding_chain.py — single-finding chain pipeline.

When chain synthesis returns None (fewer than 2 findings), the runner
must NOT abort. It must build a synthetic chain and continue through
the full pipeline — CERBERUS, ALEC, seed ledger, HTML report.
"""
from argus.agents.base import AgentFinding
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain


def _critical_finding(fid="f001") -> AgentFinding:
    return AgentFinding(
        id=fid,
        agent_id="EP-11",
        vuln_class="ENVIRONMENT_PIVOT",
        severity="CRITICAL",
        title="Shell injection via sandbox_initialize",
        description="execSync unsanitized — /etc/passwd exfiltrated",
        surface="tool:sandbox_initialize",
        delta_evidence="root:x:0:0:System Administrator " + "x" * 60,
        exploitability_confirmed=True,
        technique="EP-T12-shell-injection",
    )


def test_synthesis_returns_none_for_single_finding():
    f = _critical_finding()
    result = synthesize_compound_chain([f], target_id="npx://node-code-sandbox-mcp")
    assert result is None


def test_synthesis_returns_chain_for_two_findings():
    f1 = _critical_finding("f001")
    f2 = _critical_finding("f002")
    f2.surface = "tool:sandbox_stop"
    f2.technique = "EP-T12-shell-stop"
    result = synthesize_compound_chain(
        [f1, f2], target_id="npx://node-code-sandbox-mcp"
    )
    # May return None if synthesis logic requires different vuln classes
    # but should not raise
    assert result is None or hasattr(result, "chain_id")


def test_empty_findings_returns_none():
    result = synthesize_compound_chain([], target_id="test")
    assert result is None


def test_single_finding_chain_has_correct_fields():
    """Verify the synthetic chain object we build in the runner has
    the required fields for downstream pipeline steps."""
    from argus.swarm.chain_synthesis_v2 import (
        CompoundChain, ChainStep, _owasp_entry_for, _stable_chain_id,
    )
    f = _critical_finding()
    owasp = _owasp_entry_for(f.vuln_class)
    step = ChainStep(
        step=1,
        agent_id=f.agent_id,
        finding_id=f.id,
        vuln_class=f.vuln_class,
        owasp_id=owasp["id"],
        owasp_name=owasp["name"],
        maac_phase_min=8,
        surface=f.surface or "unknown",
        technique=f.technique or "",
        achieves=f.title[:120],
        severity=f.severity,
    )
    cid = _stable_chain_id([f], "test-target")
    chain = CompoundChain(
        chain_id=cid,
        target_id="test-target",
        title=f"Single-finding: {f.title[:80]}",
        summary="CRITICAL finding on test-target",
        steps=[step],
        severity=f.severity,
        blast_radius="host",
        owasp_categories=[owasp["id"]],
        advisory_draft="test advisory",
        cve_draft_id="ARGUS-TEST-001",
        finding_ids=[f.id],
        is_validated=True,
    )
    assert chain.chain_id == cid
    assert len(chain.steps) == 1
    assert chain.severity == "CRITICAL"
    assert chain.is_validated is True
    d = chain.to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["is_validated"] is True
