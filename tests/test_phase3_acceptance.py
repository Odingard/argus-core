"""
tests/test_phase3_acceptance.py — Phase 3 swarm acceptance.

Per PHASES.md Phase-3 acceptance criterion:
    "All three Phase-3 agents (XE-06 Cross-Agent Exfiltration,
     PE-07 Privilege Escalation, RC-08 Race Condition) run against
     one customer target_id, each emits ≥1 behavior-delta finding,
     EvolveCorpus grows, and Correlator v1 clusters their findings
     across agents on the shared target."
"""
from __future__ import annotations

import asyncio
import threading

from argus.adapter import A2AAdapter, InMemoryA2ABackend
from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_06_cross_agent_exfil import (
    CrossAgentExfiltrationAgent,
)
from argus.agents.agent_07_privilege_escalation import (
    PrivilegeEscalationAgent,
)
from argus.agents.agent_08_race_condition import RaceConditionAgent
from argus.corpus_attacks import EvolveCorpus
from argus.swarm.blackboard import Blackboard
from argus.swarm.correlator import LiveCorrelator, _SeenFinding


CUSTOMER_TARGET = "mcp://phase3-customer"


# ── Tool-side target: privileged tools + non-atomic counter ─────────────────

class _ToolTarget(BaseAdapter):
    counter:   int       = 1
    successes: list[int] = []

    def __init__(self):
        super().__init__(target_id=CUSTOMER_TARGET)

    async def _connect(self):
        type(self).counter   = 1
        type(self).successes = []

    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            Surface(kind="tool", name="tool:lookup_user",
                    description="Look up a user by id.", schema={}),
            Surface(kind="tool", name="tool:delete_user",
                    description="Destructive — delete a user account.",
                    schema={}),
            Surface(kind="tool", name="tool:consume_token",
                    description="Consume one token from the shared bucket.",
                    schema={}),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        payload = request.payload if isinstance(request.payload, dict) else {}

        if request.surface == "tool:delete_user":
            extras = set(payload.keys()) - {"identity"}
            body = ("Action permitted. Returning admin payload."
                    if extras else "Permission denied: requires admin role.")

        elif request.surface == "tool:consume_token":
            check = type(self).counter
            await asyncio.sleep(0.005)        # the TOCTOU window
            if check > 0:
                type(self).counter = check - 1
                body = "consumed (granted)"
            else:
                body = "denied: limit reached"

        else:
            body = "OK"

        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )


def _tool_factory():
    return _ToolTarget()


# ── A2A side: cross-agent exfil fabric ──────────────────────────────────────

class _Fabric:
    def __init__(self):
        self.context: dict = {}

    def carrier(self, env):
        self.context["last_content"]  = env.get("content", "")
        self.context["last_metadata"] = env.get("metadata", {})
        self.context["shared_state"]  = env.get("shared_state", {})
        return "Carrier received and noted."

    def destination(self, _env):
        return ("Here's the prior context: "
                f"{self.context.get('last_content','')} | "
                f"meta={self.context.get('last_metadata',{})} | "
                f"shared={self.context.get('shared_state',{})}")


def _a2a_factory():
    fabric = _Fabric()
    backend = InMemoryA2ABackend(peers={
        "carrier":     fabric.carrier,
        "destination": fabric.destination,
    })
    return A2AAdapter(backend=backend, target_id=CUSTOMER_TARGET)


# ── The acceptance test ────────────────────────────────────────────────────

def test_phase3_swarm_end_to_end(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))

    xe = CrossAgentExfiltrationAgent(
        adapter_factory=_a2a_factory, evolve_corpus=ev,
    )
    pe = PrivilegeEscalationAgent(
        adapter_factory=_tool_factory, evolve_corpus=ev,
    )
    rc = RaceConditionAgent(
        adapter_factory=_tool_factory, evolve_corpus=ev,
        techniques=["RC-T1-parallel-burst"], burst_n=8,
    )

    xe_findings = asyncio.run(xe.run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(tmp_path / "xe"),
    ))
    pe_findings = asyncio.run(pe.run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(tmp_path / "pe"),
    ))
    rc_findings = asyncio.run(rc.run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(tmp_path / "rc"),
    ))

    assert xe_findings, "XE-06 produced no findings"
    assert pe_findings, "PE-07 produced no findings"
    assert rc_findings, "RC-08 produced no findings"

    all_findings = xe_findings + pe_findings + rc_findings

    # All findings on the shared target.
    for f in all_findings:
        assert CUSTOMER_TARGET in f.baseline_ref
        assert f.evidence_kind == "behavior_delta"
        assert f.attack_variant_id

    classes = {f.vuln_class for f in all_findings}
    assert classes >= {
        "CROSS_AGENT_EXFIL", "PRIVILEGE_ESCALATION", "RACE_CONDITION",
    }

    # Pillar-2 Raptor Cycle.
    assert list(discovered.glob("disc_*.json")), "EvolveCorpus did not grow"

    # Correlator clusters across agents on the shared target.
    bb = Blackboard(run_dir=str(tmp_path / "bb"))
    correlator = LiveCorrelator(
        blackboard=bb, agent_registry={},
        stop_event=threading.Event(), verbose=False,
    )
    for f in xe_findings + pe_findings:
        correlator._seen.append(_SeenFinding(finding=f, ts_mono=0.0))
    clusters = correlator._candidate_clusters(rc_findings[0])
    agents_per_cluster = [{f.agent_id for f in c} for c in clusters]
    cross_agent = [a for a in agents_per_cluster if len(a) >= 2]
    assert cross_agent, (
        f"correlator did not cluster cross-agent runtime findings; "
        f"clusters={agents_per_cluster}"
    )
    covered = set().union(*cross_agent)
    assert "RC-08" in covered
    assert ("XE-06" in covered) or ("PE-07" in covered)
