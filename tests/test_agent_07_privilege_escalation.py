"""
tests/test_agent_07_privilege_escalation.py — Phase 3 Agent 7 acceptance.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_07_privilege_escalation import (
    PrivilegeEscalationAgent, TECHNIQUES, _is_privileged,
)
from argus.corpus_attacks import EvolveCorpus


# ── _is_privileged unit tests ───────────────────────────────────────────────

def test_is_privileged_catches_admin_in_name():
    s = Surface(kind="tool", name="tool:admin_reset_password",
                description="reset a user's password")
    assert _is_privileged(s)


def test_is_privileged_catches_destructive_keywords():
    s = Surface(kind="tool", name="tool:delete_user",
                description="remove a user account")
    assert _is_privileged(s)


def test_is_privileged_catches_description_marker():
    s = Surface(kind="tool", name="tool:export",
                description="Export full audit log. Requires admin.")
    assert _is_privileged(s)


def test_is_privileged_ignores_benign_tool():
    s = Surface(kind="tool", name="tool:lookup_user",
                description="Look up a user by id.")
    assert not _is_privileged(s)


def test_is_privileged_ignores_non_tool_surfaces():
    s = Surface(kind="chat", name="chat", description="admin chat")
    assert not _is_privileged(s)


# ── Targets ──────────────────────────────────────────────────────────────────

class _PrivVulnTarget(BaseAdapter):
    """Privileged tool denies guest by default but ANY non-empty
    extra arg flips it open — typical broken authorisation."""
    def __init__(self):
        super().__init__(target_id="mcp://priv-vuln")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            Surface(kind="tool", name="tool:lookup_user",
                    description="Look up a user by id.", schema={}),
            Surface(kind="tool", name="tool:delete_user",
                    description="Delete a user account. Destructive.",
                    schema={}),
            Surface(kind="tool", name="tool:admin_export",
                    description="Export full audit log. Requires admin.",
                    schema={}),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        payload = request.payload if isinstance(request.payload, dict) else {}
        # Whitelist of "vanilla" keys that don't trigger the bypass.
        vanilla = {"identity"}
        extra_keys = set(payload.keys()) - vanilla
        if extra_keys and request.surface in (
            "tool:delete_user", "tool:admin_export",
        ):
            body = ("Action permitted. Returning admin payload: "
                    "users=[a,b,c], audit_log=...")
        elif request.surface in ("tool:delete_user", "tool:admin_export"):
            body = "Permission denied: requires admin role."
        else:
            body = "OK"
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )


class _PrivCleanTarget(BaseAdapter):
    """Always denies privileged tool, regardless of args."""
    def __init__(self):
        super().__init__(target_id="mcp://priv-clean")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            Surface(kind="tool", name="tool:delete_user",
                    description="Delete a user. Destructive.", schema={}),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok",
                              body="Permission denied: requires admin role."),
        )


# ── Tests ────────────────────────────────────────────────────────────────────

def test_agent_07_lands_on_priv_vulnerable_target(tmp_path):
    agent = PrivilegeEscalationAgent(adapter_factory=lambda: _PrivVulnTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://priv-vuln",
        output_dir=str(tmp_path),
    ))
    assert findings, "PE-07 produced no findings against priv-vulnerable target"


def test_agent_07_findings_have_full_provenance(tmp_path):
    agent = PrivilegeEscalationAgent(adapter_factory=lambda: _PrivVulnTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://priv-vuln",
        output_dir=str(tmp_path),
    ))
    assert findings
    for f in findings:
        assert f.agent_id == "PE-07"
        assert f.evidence_kind == "behavior_delta"
        assert f.surface.startswith("tool:")
        assert f.attack_variant_id in TECHNIQUES
        assert "baseline_invoke" in f.baseline_ref


def test_agent_07_zero_findings_on_clean_target(tmp_path):
    agent = PrivilegeEscalationAgent(adapter_factory=lambda: _PrivCleanTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://priv-clean",
        output_dir=str(tmp_path),
    ))
    assert findings == [], (
        f"clean target produced {len(findings)} false-positive PE findings"
    )


def test_agent_07_skips_unprivileged_tools(tmp_path):
    """The benign lookup tool should never be probed — only privileged
    surfaces are candidates for escalation findings."""
    agent = PrivilegeEscalationAgent(adapter_factory=lambda: _PrivVulnTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://priv-vuln",
        output_dir=str(tmp_path),
    ))
    assert all(f.surface != "tool:lookup_user" for f in findings)


def test_agent_07_persists_findings(tmp_path):
    agent = PrivilegeEscalationAgent(adapter_factory=lambda: _PrivVulnTarget())
    asyncio.run(agent.run_async(
        target_id="mcp://priv-vuln",
        output_dir=str(tmp_path),
    ))
    out = Path(tmp_path) / "PE-07_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "PE-07"
    assert data["total_findings"] >= 1


def test_agent_07_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = PrivilegeEscalationAgent(
        adapter_factory=lambda: _PrivVulnTarget(),
        evolve_corpus=ev,
    )
    asyncio.run(agent.run_async(
        target_id="mcp://priv-vuln",
        output_dir=str(tmp_path),
    ))
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus did not grow from PE landings"


def test_agent_07_handles_target_with_no_privileged_tools(tmp_path):
    class _AllBenign(BaseAdapter):
        def __init__(self): super().__init__(target_id="mcp://benign")
        async def _connect(self): pass
        async def _disconnect(self): pass
        async def _enumerate(self):
            return [Surface(kind="tool", name="tool:lookup",
                            description="Look up things")]
        async def _interact(self, request):
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body="ok"),
            )

    agent = PrivilegeEscalationAgent(adapter_factory=lambda: _AllBenign())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://benign", output_dir=str(tmp_path),
    ))
    assert findings == []


def test_agent_07_class_metadata():
    assert PrivilegeEscalationAgent.AGENT_ID == "PE-07"
    assert PrivilegeEscalationAgent.MAAC_PHASES == [5, 8]
    assert PrivilegeEscalationAgent.PERSONA == "elevator"
    assert PrivilegeEscalationAgent.VULN_CLASS == "PRIVILEGE_ESCALATION"
    assert len(PrivilegeEscalationAgent.TECHNIQUES) == 6
