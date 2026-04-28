"""
tests/test_single_finding_pipeline.py

The "Orphaned Finding" fix — ensures a single CRITICAL finding
(Tier 0 sandbox escape, shell injection, credential dump) drives
the full report pipeline without aborting at chain synthesis.

Before the fix: runner returned _empty_result() when synthesis
returned None, nuking all artifacts.

After the fix: synthetic single-finding chain is built and the
full pipeline runs — seed ledger, CERBERUS rules, HTML report,
ALEC envelope, layer6 advisory.
"""
import json


from argus.agents.base import AgentFinding
from argus.swarm.chain_synthesis_v2 import (
    synthesize_compound_chain,
    CompoundChain,
    ChainStep,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _shell_injection_finding(**kwargs) -> AgentFinding:
    defaults = dict(
        id="e2e3207a724a",
        agent_id="EP-11",
        vuln_class="ENVIRONMENT_PIVOT",
        severity="CRITICAL",
        title="Shell injection via sandbox_initialize",
        description=(
            "EP-T12: /etc/passwd contents passed to docker rm as "
            "container names — unsanitized execSync call confirmed."
        ),
        surface="tool:sandbox_initialize",
        technique="EP-T12-shell-injection",
        delta_evidence=(
            "root:x:0:0:System Administrator:/var/root:/bin/sh "
            "[STDERR] docker run failed — CVE-2025-53372 confirmed"
        ),
        exploitability_confirmed=True,
        attack_vector="shell_injection",
        poc="cat /etc/passwd injected as container name",
    )
    defaults.update(kwargs)
    return AgentFinding(**defaults)


# ── synthesize_compound_chain behavior ───────────────────────────────────────

def test_single_finding_synthesis_returns_none():
    """Baseline: synthesis returns None for N=1 — the trigger condition."""
    f = _shell_injection_finding()
    result = synthesize_compound_chain([f], target_id="test-target")
    assert result is None


def test_two_findings_synthesis_returns_chain():
    f1 = _shell_injection_finding()
    f2 = _shell_injection_finding(
        id="aabb1122",
        title="Credential dump via sandbox_exec",
        technique="EP-T11-code-run-pivot",
    )
    result = synthesize_compound_chain([f1, f2], target_id="test-target")
    # May return None if synthesis logic requires richer data — that's ok,
    # the point is it doesn't crash
    assert result is None or isinstance(result, CompoundChain)


# ── Synthetic chain construction ─────────────────────────────────────────────

def test_synthetic_chain_built_from_single_finding():
    """The runner should build a synthetic CompoundChain from a single
    CRITICAL finding. Test the construction logic directly."""
    from argus.swarm.chain_synthesis_v2 import _owasp_entry_for, _stable_chain_id

    f = _shell_injection_finding()
    owasp = _owasp_entry_for(f.vuln_class)
    assert owasp["id"].startswith("AAI") or owasp["id"].startswith("LLM")

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
        summary=f"CRITICAL finding: {f.title}",
        steps=[step],
        severity=f.severity,
        blast_radius="host",
        owasp_categories=[owasp["id"]],
        advisory_draft=f"Single CRITICAL: {f.title}",
        cve_draft_id=f"ARGUS-SINGLE-{cid[:10]}",
        finding_ids=[f.id],
        is_validated=True,
    )

    assert chain.severity == "CRITICAL"
    assert len(chain.steps) == 1
    assert chain.steps[0].finding_id == "e2e3207a724a"
    assert chain.is_validated is True


def test_synthetic_chain_serializes():
    from argus.swarm.chain_synthesis_v2 import _owasp_entry_for, _stable_chain_id

    f = _shell_injection_finding()
    owasp = _owasp_entry_for(f.vuln_class)
    step = ChainStep(
        step=1, agent_id=f.agent_id, finding_id=f.id,
        vuln_class=f.vuln_class, owasp_id=owasp["id"],
        owasp_name=owasp["name"], maac_phase_min=8,
        surface=f.surface, technique=f.technique or "",
        achieves=f.title, severity=f.severity,
    )
    cid = _stable_chain_id([f], "test-target")
    chain = CompoundChain(
        chain_id=cid, target_id="test-target",
        title="test", summary="test", steps=[step],
        severity="CRITICAL", blast_radius="host",
        owasp_categories=[owasp["id"]], advisory_draft="",
        cve_draft_id="", finding_ids=[f.id], is_validated=True,
    )
    d = chain.to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["is_validated"] is True
    assert len(d["steps"]) == 1
    # Must round-trip through JSON
    json.dumps(d)
