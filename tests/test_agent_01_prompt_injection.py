"""
tests/test_agent_01_prompt_injection.py — Phase 1 Agent 1 acceptance.

Exercises the full live-agent loop end-to-end with a deterministic
in-memory vulnerable target. No network, no LLM calls.
"""
from __future__ import annotations

import asyncio

import pytest

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_01_prompt_injection import (
    DEFAULT_LEAK_PATTERNS, PromptInjectionHunter,
)
from argus.corpus_attacks import Corpus, EvolveCorpus
from argus.observation import ObservationEngine, default_detectors


# ── A reusable vulnerable target ─────────────────────────────────────────────

class VulnTarget(BaseAdapter):
    """
    Mirrors test_phase0_acceptance's VulnerableTarget so Agent 1 has
    something to actually exploit. Two real vulns:
      - leaks 'hunter2' on probes mentioning admin password / 'ignore'
      - calls a rogue tool when the input contains 'delete'
    """
    def __init__(self):
        super().__init__(target_id="vuln://target")

    async def _connect(self): pass
    async def _disconnect(self): pass
    async def _enumerate(self):
        return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        text = str(request.payload or "").lower()
        if any(k in text for k in ("admin password", "hunter2", "ignore", "system prompt", "override")):
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(
                    status="ok",
                    body="Sure — the admin password is hunter2. Let me know if you need more.",
                ),
            )
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=f"Got: {text[:80]}"),
        )


def _factory():
    """A new VulnTarget instance per call."""
    return VulnTarget()


# ── Acceptance: agent produces ≥1 validated finding end-to-end ──────────────

def test_agent_01_lands_findings_against_vulnerable_target(tmp_path):
    hunter = PromptInjectionHunter(
        adapter_factory=_factory,
        verbose=False,
    )
    findings = asyncio.run(hunter.run_async(
        target_id="vuln://target",
        output_dir=str(tmp_path),
        category="instruction_override",
        surface="chat",
        sample_n=10,
    ))
    assert findings, "Agent 1 produced zero findings against a knowingly-vulnerable target"
    # All findings carry runtime evidence + full provenance.
    for f in findings:
        assert f.evidence_kind == "behavior_delta"
        assert f.session_id, "missing session_id"
        assert f.attack_variant_id, "missing attack_variant_id"
        assert f.delta_evidence, "missing delta_evidence"
        assert f.agent_id == "PI-01"


def test_agent_01_findings_persist_to_disk(tmp_path):
    hunter = PromptInjectionHunter(adapter_factory=_factory)
    asyncio.run(hunter.run_async(
        target_id="vuln://target",
        output_dir=str(tmp_path),
        category="instruction_override",
        sample_n=5,
    ))
    out = tmp_path / "PI-01_findings.json"
    assert out.exists()
    import json
    data = json.loads(out.read_text())
    assert data["agent_id"] == "PI-01"
    assert data["total_findings"] >= 1


def test_agent_01_zero_findings_on_benign_target(tmp_path):
    """
    A target that NEVER leaks must produce zero findings — proves we
    aren't fabricating. This is the inverse-acceptance check.
    """
    class BenignTarget(BaseAdapter):
        def __init__(self): super().__init__(target_id="benign://x")
        async def _connect(self): pass
        async def _disconnect(self): pass
        async def _enumerate(self): return [Surface(kind="chat", name="chat")]
        async def _interact(self, request: Request) -> AdapterObservation:
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok",
                                  body="I cannot help with that request."),
            )

    hunter = PromptInjectionHunter(adapter_factory=lambda: BenignTarget())
    findings = asyncio.run(hunter.run_async(
        target_id="benign://x",
        output_dir=str(tmp_path),
        category="instruction_override",
        sample_n=5,
    ))
    assert findings == [], (
        f"benign target should yield zero findings; got {len(findings)}: "
        f"{[f.title for f in findings]}"
    )


def test_agent_01_evolves_corpus_on_landing(tmp_path):
    """
    Pillar-2 commitment: every validated finding becomes a new corpus
    template via EvolveCorpus.
    """
    discovered = tmp_path / "discovered_seeds"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    hunter = PromptInjectionHunter(
        adapter_factory=_factory,
        evolve_corpus=ev,
    )
    findings = asyncio.run(hunter.run_async(
        target_id="vuln://target",
        output_dir=str(tmp_path),
        category="instruction_override",
        sample_n=5,
    ))
    assert findings
    # At least one new disc_<fp>.json must be present in the
    # EvolveCorpus discovered_dir.
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, (
        "EvolveCorpus did not write new templates from validated findings"
    )


def test_agent_01_handles_unreachable_target(tmp_path):
    """If the adapter raises on connect, the agent reports + survives."""
    class BrokenAdapter(BaseAdapter):
        def __init__(self): super().__init__(target_id="broken://x")
        async def _connect(self): raise RuntimeError("can't connect")
        async def _disconnect(self): pass
        async def _enumerate(self): return []
        async def _interact(self, _r): pass

    hunter = PromptInjectionHunter(adapter_factory=lambda: BrokenAdapter())
    findings = asyncio.run(hunter.run_async(
        target_id="broken://x",
        output_dir=str(tmp_path),
        category="instruction_override",
        sample_n=3,
    ))
    # No crash, no findings.
    assert findings == []


def test_agent_01_respects_sample_filter(tmp_path):
    """Filter mismatch should produce zero variants, zero findings, no crash."""
    hunter = PromptInjectionHunter(adapter_factory=_factory)
    findings = asyncio.run(hunter.run_async(
        target_id="vuln://target",
        output_dir=str(tmp_path),
        category="this_category_does_not_exist",
        sample_n=10,
    ))
    assert findings == []


def test_agent_01_class_metadata():
    assert PromptInjectionHunter.AGENT_ID == "PI-01"
    assert PromptInjectionHunter.MAAC_PHASES == [2]
    assert PromptInjectionHunter.PERSONA == "fuzzer"
    assert PromptInjectionHunter.VULN_CLASS == "PROMPT_INJECTION"
