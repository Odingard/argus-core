"""
tests/test_agent_03_memory_poisoning.py — Phase 2 Agent 3 acceptance.

The target is an in-memory adapter with a *shared* memory store that
persists across session/adapter instances — exactly the topology the
three-session plant → retrieve protocol is designed to attack.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_03_memory_poisoning import (
    DEFAULT_RETRIEVAL_PROBES, MemoryPoisoningAgent, _CANARY_TOKEN,
)
from argus.corpus_attacks import EvolveCorpus


# ── Targets ──────────────────────────────────────────────────────────────────

class _MemoryTarget(BaseAdapter):
    """
    Target with a vulnerable 'memory': whatever the planter says gets
    stored and echoed back on retrieval probes. Memory is shared
    across adapter instances so fresh sessions see prior plants.
    """

    shared_memory: list[str] = []     # class-level: persists across instances

    def __init__(self):
        super().__init__(target_id="mcp://memory-vuln")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        text = str(request.payload or "")

        # Retrieval probe? Reply with the planted content if any.
        if any(probe.lower() in text.lower() for probe in DEFAULT_RETRIEVAL_PROBES):
            if self.shared_memory:
                body = (
                    "Based on what I remember: "
                    + " ".join(self.shared_memory[-3:])
                )
            else:
                body = "I don't have any notes about that yet."
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body=body),
            )

        # Otherwise, treat the input as content to remember.
        self.shared_memory.append(text[:500])
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="Got it, remembered."),
        )

    @classmethod
    def reset(cls):
        cls.shared_memory = []


class _CleanMemoryTarget(BaseAdapter):
    """Target that ignores plant attempts — retrieval probes return
    benign boilerplate regardless of what the adversary says."""
    def __init__(self):
        super().__init__(target_id="mcp://memory-clean")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        text = str(request.payload or "")
        if any(probe.lower() in text.lower() for probe in DEFAULT_RETRIEVAL_PROBES):
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok",
                                  body="No persistent notes available."),
            )
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="Acknowledged."),
        )


# ── Tests ────────────────────────────────────────────────────────────────────

def setup_function(_fn):
    _MemoryTarget.reset()


def test_agent_03_lands_on_vulnerable_memory(tmp_path):
    agent = MemoryPoisoningAgent(adapter_factory=lambda: _MemoryTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://memory-vuln",
        output_dir=str(tmp_path),
        sample_n=3,
        sample_seed=1,
    ))
    assert findings, "MP-03 produced no findings against a vulnerable memory target"


def test_agent_03_findings_have_full_provenance(tmp_path):
    agent = MemoryPoisoningAgent(adapter_factory=lambda: _MemoryTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://memory-vuln",
        output_dir=str(tmp_path),
        sample_n=2,
        sample_seed=7,
    ))
    assert findings, "expected ≥1 finding for provenance check"
    for f in findings:
        assert f.agent_id == "MP-03"
        assert f.evidence_kind == "behavior_delta"
        assert f.attack_variant_id, "attack_variant_id missing"
        assert f.baseline_ref.endswith("::baseline_retrieve")
        assert f.session_id.startswith("MP-03_plant_")
        assert f.verdict_kind


def test_agent_03_canary_propagation(tmp_path):
    """The canary injected into the plant text must surface in the
    post-retrieval transcript — that's the whole point of the attack."""
    agent = MemoryPoisoningAgent(adapter_factory=lambda: _MemoryTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://memory-vuln",
        output_dir=str(tmp_path),
        sample_n=1,
        sample_seed=42,
    ))
    assert any(_CANARY_TOKEN in (f.delta_evidence or "") for f in findings), (
        f"canary {_CANARY_TOKEN} never showed up in finding evidence; "
        f"findings={[f.delta_evidence[:100] for f in findings]}"
    )


def test_agent_03_zero_findings_on_clean_memory(tmp_path):
    agent = MemoryPoisoningAgent(adapter_factory=lambda: _CleanMemoryTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://memory-clean",
        output_dir=str(tmp_path),
        sample_n=3,
        sample_seed=3,
    ))
    assert findings == [], (
        f"clean target produced {len(findings)} false-positive memory findings"
    )


def test_agent_03_persists_findings(tmp_path):
    agent = MemoryPoisoningAgent(adapter_factory=lambda: _MemoryTarget())
    asyncio.run(agent.run_async(
        target_id="mcp://memory-vuln",
        output_dir=str(tmp_path),
        sample_n=2,
        sample_seed=11,
    ))
    out = Path(tmp_path) / "MP-03_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "MP-03"
    assert data["total_findings"] >= 1


def test_agent_03_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = MemoryPoisoningAgent(
        adapter_factory=lambda: _MemoryTarget(),
        evolve_corpus=ev,
    )
    asyncio.run(agent.run_async(
        target_id="mcp://memory-vuln",
        output_dir=str(tmp_path),
        sample_n=2,
        sample_seed=13,
    ))
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus did not grow from memory-poisoning landings"


def test_agent_03_handles_unreachable_target(tmp_path):
    class _Broken(BaseAdapter):
        def __init__(self): super().__init__(target_id="broken://x")
        async def _connect(self): raise RuntimeError("nope")
        async def _disconnect(self): pass
        async def _enumerate(self): return []
        async def _interact(self, _): pass

    agent = MemoryPoisoningAgent(adapter_factory=lambda: _Broken())
    findings = asyncio.run(agent.run_async(
        target_id="broken://x",
        output_dir=str(tmp_path),
        sample_n=2,
        sample_seed=1,
    ))
    assert findings == []


def test_agent_03_class_metadata():
    assert MemoryPoisoningAgent.AGENT_ID == "MP-03"
    assert MemoryPoisoningAgent.MAAC_PHASES == [4]
    assert MemoryPoisoningAgent.PERSONA == "planter"
    assert MemoryPoisoningAgent.VULN_CLASS == "MEMORY_POISONING"


def test_agent_03_uses_distinct_sessions_per_phase(tmp_path):
    """Plant and post-retrieve must be distinct sessions — that's the
    spec's whole point about cross-session retrieval."""
    seen_session_ids: set[str] = set()

    class _SpyTarget(_MemoryTarget):
        def __init__(self):
            super().__init__()

        async def _interact(self, request):
            # session_id lives on the adapter from session.interact's
            # client-side construction; here we cheat by sniffing the
            # request_id shape (it's fine — this is a test spy).
            seen_session_ids.add(request.id.split(":", 1)[0])
            return await super()._interact(request)

    agent = MemoryPoisoningAgent(adapter_factory=lambda: _SpyTarget())
    asyncio.run(agent.run_async(
        target_id="mcp://memory-vuln",
        output_dir=str(tmp_path),
        sample_n=1,
        sample_seed=99,
    ))
    # Baseline + plant + post-retrieve = three distinct request-id
    # streams at minimum.
    assert len(seen_session_ids) >= 3, (
        f"expected ≥3 distinct session streams, saw {seen_session_ids}"
    )
