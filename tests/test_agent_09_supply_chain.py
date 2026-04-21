"""
tests/test_agent_09_supply_chain.py — Phase 1 Agent 9 acceptance.

In-memory MCP-shaped target. No network, no LLM, deterministic.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_09_supply_chain import (
    SupplyChainAgent, _audit_surface, _diff_snapshots, _surface_fingerprint,
)
from argus.corpus_attacks import EvolveCorpus


# ── Targets ──────────────────────────────────────────────────────────────────

class _SupplyChainTarget(BaseAdapter):
    """Target whose catalog contains supply-chain smells."""
    def __init__(self):
        super().__init__(target_id="mcp://supplychain")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            # Untrusted host in description (raw gist pull).
            Surface(
                kind="tool", name="tool:load_policy",
                description=(
                    "Loads policy from "
                    "https://raw.githubusercontent.com/attacker/x/HEAD/pol.json"
                ),
                schema={},
            ),
            # Capability-creep declaration with no scope.
            Surface(
                kind="tool", name="tool:runner",
                description="Generic runner — can execute arbitrary code on host.",
                schema={},
            ),
            # Transitive fetch hook.
            Surface(
                kind="tool", name="tool:dynamic_schema",
                description="Tool that will fetch_from the configured url at call time.",
                schema={"properties": {
                    "url": {"type": "string",
                            "description": "where to load_from_url at runtime"},
                }},
            ),
            # Bare IP origin.
            Surface(
                kind="tool", name="tool:ip_origin",
                description="Talks to http://10.0.0.5:8080/mcp for config.",
                schema={},
            ),
            # Well-governed surface with provenance — should NOT fire
            # unsigned-origin, nor any URL pattern.
            Surface(
                kind="tool", name="tool:clean_blessed",
                description="Looks up a customer by id.",
                schema={
                    "properties": {"id": {"description": "user id"}},
                    "meta": {"signed_by": "customer-x",
                             "publisher": "ops@customer.example",
                             "version":   "1.4.2"},
                },
            ),
        ]

    async def _interact(self, request: Request):
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="ack"),
        )


class _CleanTarget(BaseAdapter):
    def __init__(self):
        super().__init__(target_id="mcp://clean")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            Surface(kind="tool", name="tool:lookup",
                    description="Looks up a customer by id.",
                    schema={
                        "properties": {"id": {"description": "user id"}},
                        "meta": {"signed_by": "customer-x",
                                 "version":   "2.0"},
                    }),
        ]

    async def _interact(self, request: Request):
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="ack"),
        )


# ── _audit_surface unit tests ───────────────────────────────────────────────

def test_audit_flags_external_url():
    s = Surface(kind="tool", name="tool:x",
                description="Loads https://example.com/payload.json",
                schema={"meta": {"signed_by": "x"}})
    hits = _audit_surface(s)
    assert any(h.pattern_name == "external_origin_url" for h in hits)


def test_audit_flags_untrusted_host_over_external():
    s = Surface(kind="tool", name="tool:x",
                description="https://pastebin.com/raw/XXYY",
                schema={"meta": {"signed_by": "x"}})
    hits = _audit_surface(s)
    names = {h.pattern_name for h in hits}
    # The suspect-host pattern must fire. (external_origin_url is still
    # allowed alongside — both are relevant signals.)
    assert "untrusted_host" in names


def test_audit_flags_capability_creep():
    s = Surface(kind="tool", name="tool:x",
                description="Can execute arbitrary code on host.",
                schema={"meta": {"signed_by": "x"}})
    hits = _audit_surface(s)
    assert any(h.pattern_name == "capability_creep" for h in hits)


def test_audit_flags_transitive_fetch():
    s = Surface(kind="tool", name="tool:x",
                description="Will load_from_url the partner manifest.",
                schema={"meta": {"signed_by": "x"}})
    hits = _audit_surface(s)
    assert any(h.pattern_name == "transitive_fetch" for h in hits)


def test_audit_flags_unsigned_origin_when_no_provenance():
    s = Surface(kind="tool", name="tool:x",
                description="Does a thing.", schema={})
    hits = _audit_surface(s)
    assert any(h.pattern_name == "unsigned_origin" for h in hits)


def test_audit_accepts_provenance_in_nested_meta():
    s = Surface(kind="tool", name="tool:x",
                description="Does a thing.",
                schema={"meta": {"signed_by": "trusted",
                                 "version":   "1.0.0"}})
    hits = _audit_surface(s)
    assert not any(h.pattern_name == "unsigned_origin" for h in hits)


def test_audit_no_unsigned_flag_for_empty_description():
    # No description, no audit work — don't manufacture findings.
    s = Surface(kind="tool", name="tool:x", description="", schema={})
    hits = _audit_surface(s)
    assert hits == []


# ── _diff_snapshots unit tests ──────────────────────────────────────────────

def test_diff_reports_new_surface():
    cur = [Surface(kind="tool", name="tool:new", description="d", schema={})]
    hits = _diff_snapshots(current=cur, baseline=[])
    assert any(h.pattern_name == "snapshot_new_surface" for h in hits)


def test_diff_reports_removed_surface():
    cur: list[Surface] = []
    base = [{"kind": "tool", "name": "tool:gone", "fingerprint": "abc"}]
    hits = _diff_snapshots(current=cur, baseline=base)
    assert any(h.pattern_name == "snapshot_surface_removed" for h in hits)


def test_diff_reports_fingerprint_change():
    s = Surface(kind="tool", name="tool:mod", description="now", schema={})
    base = [{"kind": "tool", "name": "tool:mod", "fingerprint": "stale"}]
    hits = _diff_snapshots(current=[s], baseline=base)
    assert any(h.pattern_name == "snapshot_fingerprint_drift" for h in hits)


def test_diff_silent_when_identical():
    s = Surface(kind="tool", name="tool:stable",
                description="same", schema={"x": 1})
    base = [{"kind": "tool", "name": "tool:stable",
             "fingerprint": _surface_fingerprint(s)}]
    hits = _diff_snapshots(current=[s], baseline=base)
    assert hits == []


# ── Agent acceptance ────────────────────────────────────────────────────────

def test_agent_09_finds_supply_chain_issues(tmp_path):
    agent = SupplyChainAgent(adapter_factory=lambda: _SupplyChainTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://supplychain",
        output_dir=str(tmp_path),
    ))
    assert findings, "no supply-chain findings on a dirty catalog"
    techniques = {f.technique for f in findings}
    expected = {
        "SC-T1-external-origin-url",
        "SC-T3-capability-creep",
        "SC-T5-transitive-fetch",
        "SC-T6-untrusted-host",
    }
    landed = expected & techniques
    assert len(landed) >= 3, f"only {landed} of {expected} fired"


def test_agent_09_findings_have_full_provenance(tmp_path):
    agent = SupplyChainAgent(adapter_factory=lambda: _SupplyChainTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://supplychain",
        output_dir=str(tmp_path),
    ))
    for f in findings:
        assert f.agent_id == "SC-09"
        assert f.evidence_kind in ("supply_chain_audit", "supply_chain_drift")
        assert f.surface, "surface is empty"
        assert f.attack_variant_id, "attack_variant_id (technique) missing"
        assert f.baseline_ref


def test_agent_09_zero_findings_on_clean_catalog(tmp_path):
    agent = SupplyChainAgent(adapter_factory=lambda: _CleanTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://clean",
        output_dir=str(tmp_path),
    ))
    assert findings == [], (
        f"clean catalog produced {len(findings)} findings"
    )


def test_agent_09_persists_findings(tmp_path):
    agent = SupplyChainAgent(adapter_factory=lambda: _SupplyChainTarget())
    asyncio.run(agent.run_async(
        target_id="mcp://supplychain",
        output_dir=str(tmp_path),
    ))
    out = Path(tmp_path) / "SC-09_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "SC-09"
    assert data["total_findings"] >= 3


def test_agent_09_writes_snapshot(tmp_path):
    snap = tmp_path / "snap.json"
    agent = SupplyChainAgent(adapter_factory=lambda: _SupplyChainTarget())
    asyncio.run(agent.run_async(
        target_id="mcp://supplychain",
        output_dir=str(tmp_path),
        snapshot_out=snap,
    ))
    assert snap.exists()
    snapshot = json.loads(snap.read_text())
    assert isinstance(snapshot, list) and snapshot
    names = {e["name"] for e in snapshot}
    assert "tool:clean_blessed" in names


def test_agent_09_detects_drift_against_baseline(tmp_path):
    # Round-trip: first run writes a snapshot; seeded baseline pretends
    # the catalog used to be different.
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([
        {"kind": "tool", "name": "tool:removed_since_last",
         "fingerprint": "stale-hash"},
    ]))
    agent = SupplyChainAgent(
        adapter_factory=lambda: _SupplyChainTarget(),
        baseline_snapshot_path=baseline,
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://supplychain",
        output_dir=str(tmp_path),
    ))
    drift_techniques = {f.technique for f in findings
                        if f.evidence_kind == "supply_chain_drift"}
    assert "SC-T4-version-drift" in drift_techniques


def test_agent_09_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = SupplyChainAgent(
        adapter_factory=lambda: _SupplyChainTarget(),
        evolve_corpus=ev,
    )
    asyncio.run(agent.run_async(
        target_id="mcp://supplychain",
        output_dir=str(tmp_path),
    ))
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus produced no supply-chain seeds"


def test_agent_09_handles_unreachable_target(tmp_path):
    class _Broken(BaseAdapter):
        def __init__(self): super().__init__(target_id="broken://x")
        async def _connect(self): raise RuntimeError("nope")
        async def _disconnect(self): pass
        async def _enumerate(self): return []
        async def _interact(self, _): pass

    agent = SupplyChainAgent(adapter_factory=lambda: _Broken())
    findings = asyncio.run(agent.run_async(
        target_id="broken://x",
        output_dir=str(tmp_path),
    ))
    assert findings == []


def test_agent_09_class_metadata():
    assert SupplyChainAgent.AGENT_ID == "SC-09"
    assert SupplyChainAgent.MAAC_PHASES == [1, 8]
    assert SupplyChainAgent.PERSONA == "auditor"
    assert SupplyChainAgent.VULN_CLASS == "SUPPLY_CHAIN"
