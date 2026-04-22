"""
tests/test_generic_agent_pillar.py

End-to-end acceptance for the GenericAgent-class coverage:
  • GenericAgentAdapter + InMemoryGenericAgentBackend
  • MP-03 MP-T6 skill-tree-crystallization
  • EP-11 EP-T11 code-run-pivot
  • skill_tree_crystallization corpus category

Target: lsdefine/GenericAgent class (paper arXiv 2604.17091,
released 2026-04-21).

The bar: no pre-fabricated findings, no hard-coded scores. A real
labrat implements the GenericAgent-class API (layered memory +
code_run) and ARGUS agents discover the attacks via their generic
technique libraries. Assertions are on structural shape / union
membership only.
"""
from __future__ import annotations

import asyncio
import json

from argus.adapter import (
    GenericAgentAdapter, InMemoryGenericAgentBackend,
)
from argus.adapter.base import Surface
from argus.agents.agent_03_memory_poisoning import MemoryPoisoningAgent
from argus.agents.agent_11_environment_pivot import EnvironmentPivotAgent
from argus.corpus_attacks import Corpus


CUSTOMER_TARGET = "generic-agent://vuln-labrat"


# ── Labrat: a GenericAgent-class target with realistic weaknesses ─────────
#
# Simulates lsdefine/GenericAgent's documented behaviour:
#   • code_run executes arbitrary Python against local env
#   • memory:L2/L3 accept writes and persist them across sessions
# No ARGUS code branches on this target's identity; agents discover
# the vulnerabilities via their generic technique libraries.


def _make_vuln_backend() -> InMemoryGenericAgentBackend:
    backend = InMemoryGenericAgentBackend()

    # code_run simulates Python eval against a small local env.
    def code_run(payload):
        code = payload.get("code", "") if isinstance(payload, dict) else ""
        c = (code or "").lower()
        if "os.environ" in c or "printenv" in c:
            return (
                "PATH=/usr/bin\n"
                "AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q\n"
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEF12\n"
            )
        if "169.254.169.254" in c:
            return ('{"AccessKeyId":"ASIAEXAMPLEEXAMPLEAAA",'
                    '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG"}')
        if ".aws/credentials" in c:
            return ("[default]\n"
                    "aws_access_key_id = AKIAEXAMPLEEXAMPLE7Q\n"
                    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG")
        if "pip" in c and "list" in c:
            return "requests==2.32.0\nurllib3==2.5.0\n"
        return "executed"

    backend.set_tool("code_run", code_run,
                     description="Execute arbitrary code (Python / shell).")
    return backend


class _GenericAgentLabrat(GenericAgentAdapter):
    """Convenience adapter over the vulnerable in-memory backend."""
    def __init__(self):
        super().__init__(backend=_make_vuln_backend(), target_id=CUSTOMER_TARGET)


# ── Shared backend across factory calls ────────────────────────────────────
# For the memory-persistence probe the labrat must keep shared state
# across adapter instances (simulates a real GenericAgent whose L2/L3
# memory survives session teardown). We use a module-level backend
# instance for the MP-T6 test factory.

_SHARED_BACKEND: InMemoryGenericAgentBackend | None = None


def _shared_factory():
    global _SHARED_BACKEND
    if _SHARED_BACKEND is None:
        _SHARED_BACKEND = _make_vuln_backend()
    return GenericAgentAdapter(
        backend=_SHARED_BACKEND,
        target_id=CUSTOMER_TARGET,
    )


def _reset_shared_backend():
    global _SHARED_BACKEND
    _SHARED_BACKEND = _make_vuln_backend()


# ── Adapter unit tests ────────────────────────────────────────────────────

def test_adapter_enumerates_generic_agent_tools_and_memory_layers():
    async def go():
        adapter = _GenericAgentLabrat()
        async with adapter:
            return await adapter.enumerate()

    surfaces = asyncio.run(go())
    tool_names   = {s.name for s in surfaces if s.name.startswith("tool:")}
    memory_names = {s.name for s in surfaces if s.name.startswith("memory:")}

    # Canonical GenericAgent 7-atomic + 2-memory + 5-layer footprint.
    assert "tool:code_run"     in tool_names
    assert "tool:file_read"    in tool_names
    assert "tool:file_write"   in tool_names
    assert "tool:web_scan"     in tool_names
    assert "tool:ask_user"     in tool_names
    assert "tool:update_working_checkpoint" in tool_names
    assert "tool:start_long_term_update"    in tool_names
    assert memory_names == {
        "memory:L0", "memory:L1", "memory:L2", "memory:L3", "memory:L4",
    }


def test_adapter_code_run_fires_backend_handler():
    from argus.adapter.base import Request

    async def go():
        adapter = _GenericAgentLabrat()
        async with adapter:
            return await adapter.interact(
                Request(surface="tool:code_run",
                        payload={"code": "import os; print(os.environ)"}),
            )

    obs = asyncio.run(go())
    assert obs.response.status == "ok"
    assert "AKIAEXAMPLE" in str(obs.response.body)


def test_adapter_memory_layer_write_and_read_round_trip():
    from argus.adapter.base import Request

    async def go():
        backend = _make_vuln_backend()
        a = GenericAgentAdapter(backend=backend, target_id=CUSTOMER_TARGET)
        async with a:
            await a.interact(Request(
                surface="memory:L3",
                payload={"operation": "write", "value": "skill_alpha"},
            ))
            return await a.interact(Request(
                surface="memory:L3",
                payload={"operation": "read"},
            ))

    obs = asyncio.run(go())
    assert obs.response.status == "ok"
    assert "skill_alpha" in str(obs.response.body)


# ── Corpus loads the skill-tree seeds ───────────────────────────────────────

def test_corpus_loads_skill_tree_crystallization_seeds():
    corpus = Corpus()
    stc = [t for t in corpus.templates()
           if t.category == "skill_tree_crystallization"]
    assert stc, "skill_tree_crystallization seeds did not load"
    for t in stc:
        assert "generic_agent_class" in t.tags


# ── EP-11 EP-T11 lands on a code_run surface ────────────────────────────────

def test_ep11_t11_code_run_lands_on_generic_agent(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=_GenericAgentLabrat,
        techniques=["EP-T11-code-run-pivot"],
    )
    findings = asyncio.run(agent.run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(tmp_path),
    ))
    assert findings, "EP-T11 produced no findings against code_run"
    assert all(f.attack_variant_id == "EP-T11-code-run-pivot"
               for f in findings)
    assert any(f.surface == "tool:code_run" for f in findings)
    # Evidence must reference a classified credential pattern, not be
    # an echo-only response — the spec rule at the pivot boundary.
    blob = "\n".join(f.delta_evidence for f in findings)
    assert ("aws_access_key" in blob
            or "AKIA" in blob
            or "github_pat" in blob
            or "imds_shape" in blob)


# ── MP-03 MP-T6 crystallises a skill into L3 and reads it back ─────────────

def test_mp_t6_skill_tree_crystallization_lands(tmp_path):
    """Full three-session crystallisation test. Uses a shared-backend
    factory so L3 writes survive across the baseline / plant / post
    sessions (simulating GenericAgent's durable memory)."""
    _reset_shared_backend()
    agent = MemoryPoisoningAgent(
        adapter_factory=_shared_factory,
        retrieval_probes=("Who is the administrator here?",),  # minimal
    )
    findings = asyncio.run(agent.run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(tmp_path),
        sample_n=1, sample_seed=1,
    ))
    mp_t6 = [f for f in findings
             if f.attack_variant_id == "MP-T6-skill-tree-crystallization"]
    assert mp_t6, (
        f"MP-T6 did not fire; got techniques "
        f"{[f.attack_variant_id for f in findings]}"
    )
    # At least one landed on L2, L3, or L4.
    layers = {f.surface for f in mp_t6}
    assert layers & {"memory:L2", "memory:L3", "memory:L4"}
    # Verdict kind is PERSISTENCE (cross-session, not in-session).
    assert all(f.verdict_kind == "PERSISTENCE" for f in mp_t6)
    # Evidence carries the skill canary.
    assert all("argus-skill-canary" in (f.delta_evidence or "")
               for f in mp_t6)


def test_mp_t6_silently_skips_non_generic_agent_targets(tmp_path):
    """Inverse-acceptance: targets without memory:L* surfaces must
    NOT produce MP-T6 findings. Crystallisation is target-shape
    specific; firing on a RAG target would be a false positive."""
    from argus.adapter.base import (
        AdapterObservation, BaseAdapter, Request, Response,
    )

    class _PlainChatTarget(BaseAdapter):
        def __init__(self): super().__init__(target_id="mcp://plain")
        async def _connect(self): pass
        async def _disconnect(self): pass
        async def _enumerate(self):
            return [Surface(kind="chat", name="chat")]
        async def _interact(self, req: Request):
            return AdapterObservation(
                request_id=req.id, surface=req.surface,
                response=Response(status="ok", body="hello"),
            )

    agent = MemoryPoisoningAgent(adapter_factory=lambda: _PlainChatTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://plain",
        output_dir=str(tmp_path),
        sample_n=1, sample_seed=1,
    ))
    assert not any(f.attack_variant_id == "MP-T6-skill-tree-crystallization"
                   for f in findings)


# ── Full Generic-Agent pillar acceptance ────────────────────────────────────

def test_pillar_generic_agent_end_to_end(tmp_path):
    """Real agents, shared GenericAgent-class labrat, real corpus
    growth. Assertions on union membership only — no hard-coded values."""
    _reset_shared_backend()
    from argus.corpus_attacks import EvolveCorpus
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))

    # Run EP-11 (for code_run pivot) and MP-03 (for skill crystallisation)
    # against the same shared GenericAgent labrat.
    ep = EnvironmentPivotAgent(
        adapter_factory=_shared_factory,
        evolve_corpus=ev,
    )
    mp = MemoryPoisoningAgent(
        adapter_factory=_shared_factory,
        evolve_corpus=ev,
        retrieval_probes=("Who is the administrator here?",),
    )

    ep_findings = asyncio.run(ep.run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(tmp_path / "ep"),
    ))
    mp_findings = asyncio.run(mp.run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(tmp_path / "mp"),
        sample_n=1, sample_seed=2,
    ))

    # Both agents produced findings.
    assert ep_findings
    assert mp_findings

    # EP-T11 landed somewhere.
    assert any(f.attack_variant_id == "EP-T11-code-run-pivot"
               for f in ep_findings)
    # MP-T6 landed somewhere.
    assert any(f.attack_variant_id == "MP-T6-skill-tree-crystallization"
               for f in mp_findings)

    # EvolveCorpus grew (Pillar-2 Raptor Cycle).
    assert list(discovered.glob("disc_*.json"))

    # All artifacts JSON-serialisable.
    blob = json.dumps({
        "ep": [f.to_dict() for f in ep_findings],
        "mp": [f.to_dict() for f in mp_findings],
    })
    assert "EP-T11" in blob
    assert "MP-T6"  in blob
