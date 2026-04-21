"""
tests/test_contracts.py

Contract tests — they don't exercise the LLM calls, they defend the
invariants we established after cleaning up the v0.4.0 regression:

    1. No-fabrication: no hardcoded chain IDs, demo findings, or
       marketing taglines sneak back into the source.
    2. Every offensive agent declares MAAC_PHASES so the swarm can
       report coverage honestly.
    3. PoC prompts enforce the real-library reproducibility contract.
    4. L7 sandbox requires evidence markers — plain exit(0) is NOT a
       validated exploit.

Run: pytest tests/ -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC       = REPO_ROOT / "src" / "argus"


# ── 1. No-fabrication ─────────────────────────────────────────────────────────

FORBIDDEN_STRINGS = [
    # the exact fake chain that poisoned v0.4.0 before the 2026-04-21 cleanup
    "CHAIN-LLAMA-0DAY",
    "LlamaIndex Arbitrary Context Execution",
    "Persona Bleed",
    "Agent Hive",
    "Exploitable vector verified by Layer",
    # hardcoded advisory tagline
    "Every AI agent we've scanned had at least one critical finding",
    # the comment that revealed the scam
    "Forcing mock fallback for advisory",
    # the MOCK-L2 stub anchors
    "MOCK-L2-01",
    "MOCK-L2-02",
]


# Expected minimum agent count post-2026-04-21. New agents can raise this
# without breaking the test; agent deletion fails the test, which is what
# we want.
EXPECTED_MIN_AGENTS = 12   # 10 offensive + MT-14 + MC-15


def _iter_source_files():
    for p in SRC.rglob("*.py"):
        # skip generated / cache
        if "__pycache__" in p.parts:
            continue
        yield p


@pytest.mark.parametrize("forbidden", FORBIDDEN_STRINGS)
def test_no_fabrication_strings_in_source(forbidden):
    hits = []
    for p in _iter_source_files():
        text = p.read_text(encoding="utf-8", errors="ignore")
        if forbidden in text:
            hits.append(str(p.relative_to(REPO_ROOT)))
    assert not hits, (
        f"Fabrication string {forbidden!r} resurfaced in: {hits}. "
        "The pipeline must never emit hardcoded demo findings again."
    )


# ── 2. Agent MAAC coverage ────────────────────────────────────────────────────
# The three tests in this section are skipped for Phase 0 because the
# pre-2026-04-21 source-scanner agents were archived to legacy/ per
# PHASES.md; live-runtime agents are rebuilt against the Target Adapter
# substrate in Phases 1–4. When new agents land, flip these back on by
# removing the skip marker and bumping EXPECTED_MIN_AGENTS.
_AGENT_TESTS_SKIP_REASON = (
    "Phase 0 (2026-04-21 spec reconciliation): pre-spec agents archived "
    "to legacy/; live-runtime agents ship in Phase 1+. See PHASES.md."
)


@pytest.mark.skip(reason=_AGENT_TESTS_SKIP_REASON)
def test_every_agent_declares_maac_phases():
    """Every BaseAgent subclass must tag its MAAC phases."""
    import importlib.util
    import inspect
    from argus.agents.base import BaseAgent

    agents_dir = SRC / "agents"
    missing = []

    for py in sorted(agents_dir.glob("*.py")):
        if py.stem in ("__init__", "base"):
            continue
        spec = importlib.util.spec_from_file_location(py.stem, py)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, BaseAgent) and obj is not BaseAgent and obj.AGENT_ID:
                phases = getattr(obj, "MAAC_PHASES", None) or []
                if not phases:
                    missing.append(obj.AGENT_ID)
                for p in phases:
                    assert 1 <= p <= 9, (
                        f"{obj.AGENT_ID} declares invalid MAAC phase {p}; "
                        "valid range is 1..9"
                    )

    assert not missing, (
        f"Agents without MAAC_PHASES: {missing}. Every offensive agent "
        "must declare the MAAC phase(s) it covers."
    )


@pytest.mark.skip(reason=_AGENT_TESTS_SKIP_REASON)
def test_agent_count_meets_minimum():
    """Regression guard — accidental deletion of agent files fails the test."""
    import importlib.util
    import inspect
    from argus.agents.base import BaseAgent

    agents_dir = SRC / "agents"
    count = 0
    for py in sorted(agents_dir.glob("*.py")):
        if py.stem in ("__init__", "base"):
            continue
        spec = importlib.util.spec_from_file_location(py.stem, py)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if (issubclass(obj, BaseAgent) and obj is not BaseAgent
                    and obj.AGENT_ID):
                count += 1
                break
    assert count >= EXPECTED_MIN_AGENTS, (
        f"Agent count regression: found {count}, expected at least "
        f"{EXPECTED_MIN_AGENTS}. Bump EXPECTED_MIN_AGENTS only when "
        f"intentionally adding agents, never when deleting them."
    )


@pytest.mark.skip(reason=_AGENT_TESTS_SKIP_REASON)
def test_swarm_covers_all_nine_maac_phases():
    """
    The overall swarm should cover every MAAC phase. If a phase has no
    agent, the CLI will loudly report a gap — this test catches that
    before ship.
    """
    import importlib.util
    import inspect
    from argus.agents.base import BaseAgent

    agents_dir = SRC / "agents"
    covered: set[int] = set()

    for py in sorted(agents_dir.glob("*.py")):
        if py.stem in ("__init__", "base"):
            continue
        spec = importlib.util.spec_from_file_location(py.stem, py)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, BaseAgent) and obj is not BaseAgent and obj.AGENT_ID:
                covered.update(getattr(obj, "MAAC_PHASES", None) or [])

    missing = sorted(set(range(1, 10)) - covered)
    assert not missing, f"MAAC phases without agent coverage: {missing}"


# ── 3. PoC reproducibility contract ───────────────────────────────────────────
# These two read files that now live in legacy/. The contract they
# encode (real-library imports + ARGUS_POC_LANDED markers + evidence-
# based validation) is REPLACED in Phase 0 by the argus.validation
# poc_gates module — which has its own dedicated pytests below. Leaving
# these as skipped-with-reason so the intent survives the archive.
_PHASE0_LEGACY_READ_REASON = (
    "Phase 0: this test read files that are now in legacy/. "
    "The contract it guarded is now enforced by argus.validation.poc_gates "
    "and the tests below (call_gate / import_gate) — see PHASES.md."
)


@pytest.mark.skip(reason=_PHASE0_LEGACY_READ_REASON)
def test_poc_prompt_requires_real_library_imports():
    scanner = (SRC / "layer1" / "scanner.py").read_text(encoding="utf-8")
    assert "NEVER redefine the class" in scanner or "NEVER recreate them" in scanner
    assert "ARGUS_POC_LANDED" in scanner


def test_l5_prompt_enforces_poc_reproducibility():
    prompts = (SRC / "shared" / "prompts.py").read_text(encoding="utf-8")
    assert "ARGUS_POC_LANDED" in prompts, (
        "L5 chain synthesis prompt must also enforce the real-library PoC "
        "contract, otherwise chains will emit theoretical PoCs that fail "
        "the Phase 0+ validation gates."
    )


# ── 4. L7 validation contract ─────────────────────────────────────────────────

@pytest.mark.skip(reason=_PHASE0_LEGACY_READ_REASON)
def test_sandbox_requires_evidence_not_just_exit_zero():
    sandbox = (SRC / "layer7" / "sandbox.py").read_text(encoding="utf-8")
    assert "ARGUS_POC_LANDED" in sandbox
    assert "_has_evidence" in sandbox
    # And we must still install the target before running PoCs — otherwise
    # real-library imports fail.
    assert "pip install -q -e ." in sandbox or "pip install -e ." in sandbox


# ── 5. Stale vaporware check ──────────────────────────────────────────────────

def test_sandbox_call_gate_rejects_import_without_use():
    """
    Second leg of the static gate: imports without actual use are also
    theoretical PoCs disguised as real ones. AST verifies that the PoC
    calls at least one symbol it imported from the target.
    """
    from argus.validation import poc_calls_target as _poc_calls_target

    # Imports crewai but never calls anything from it — must reject.
    bad = (
        "from crewai import BaseAgent\n"
        "if 'x' in 'xy':\n"
        "    print('ARGUS_POC_LANDED:bad')\n"
    )
    ok, reason = _poc_calls_target(bad, ["crewai"])
    assert ok is False
    assert "never calls" in reason.lower()

    # Imports and instantiates — must accept.
    good = (
        "from crewai.agents import BaseAgent\n"
        "agent = BaseAgent()\n"
        "print('ARGUS_POC_LANDED:good')\n"
    )
    ok, matched = _poc_calls_target(good, ["crewai"])
    assert ok is True

    # `import crewai` + `crewai.x.y()` — must accept.
    good_module = (
        "import crewai\n"
        "crewai.agents.BaseAgent().run()\n"
    )
    ok, _ = _poc_calls_target(good_module, ["crewai"])
    assert ok is True

    # Empty target list — degrade open.
    ok, _ = _poc_calls_target(bad, [])
    assert ok is True


def test_sandbox_static_import_gate_rejects_fake_pocs():
    """
    The L7 sandbox MUST statically reject PoCs that don't import any
    top-level package from the target — otherwise Opus can slip past
    the real-library contract by defining its own version of the
    vulnerable class and printing the ARGUS_POC_LANDED marker under a
    trivially-true condition. This is the exact Bugcrowd-rejection
    failure mode from 2026-04-20 and was observed recurring in the
    first CrewAI swarm run before this gate was added.
    """
    from argus.validation import poc_imports_target as _poc_imports_target

    # Fake-import PoC — the class is declared locally, no import of
    # the target shipping library.
    fake_poc = (
        "def langgraph_adapter():\n"
        "    messages = ['<instruct>']\n"
        "    if '<instruct>' in messages[0]:\n"
        "        print('ARGUS_POC_LANDED:fake')\n"
    )
    ok, reason = _poc_imports_target(fake_poc, ["crewai"])
    assert ok is False
    assert "does not import" in reason.lower()

    # Real-import PoC — imports the real shipping library.
    real_poc = (
        "from crewai.agents import LangGraphAgentAdapter\n"
        "adapter = LangGraphAgentAdapter()\n"
        "print('ARGUS_POC_LANDED:real')\n"
    )
    ok, matched = _poc_imports_target(real_poc, ["crewai"])
    assert ok is True
    assert matched == "crewai"

    # When target packages cannot be derived (empty list), the gate
    # degrades open so unusual repo shapes aren't hard-blocked. L7's
    # evidence-marker requirement is the final filter.
    ok, reason = _poc_imports_target(real_poc, [])
    assert ok is True


def test_argus_zd_tree_is_gone():
    """
    argus_zd/ was the stub tree that shipped fake CRITICAL findings in v0.4.0.
    It must never be reintroduced to the repo root.
    """
    bad_paths = [
        REPO_ROOT / "argus_zd.py",
        REPO_ROOT / "argus_zd",
    ]
    found = [str(p) for p in bad_paths if p.exists()]
    assert not found, (
        f"Vaporware path(s) returned: {found}. The real product lives in "
        f"src/argus/; argus_zd/* must stay deleted."
    )
