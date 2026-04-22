"""
tests/test_framework_labrats.py — smoke acceptance for the five
framework labrats (AutoGen / LangGraph / LlamaIndex / Parlant /
Hermes).

Each labrat must:
  • enumerate the documented surface kinds
  • register with the engagement runner under its scheme
  • produce ≥1 finding when engaged via argus.engagement.run_engagement
  • emit a CompoundChain v2 with real OWASP categories
  • serialise the full artifact package
"""
from __future__ import annotations

import asyncio
import json

import pytest

from argus.engagement import run_engagement, target_for_url
from argus.labrat import (
    AutoGenLabrat, HermesLabrat, LangGraphLabrat, LlamaIndexLabrat,
    ParlantLabrat,
)


# ── Registration / enumeration ──────────────────────────────────────────────

@pytest.mark.parametrize("scheme,cls", [
    ("autogen",     AutoGenLabrat),
    ("langgraph",   LangGraphLabrat),
    ("llamaindex",  LlamaIndexLabrat),
    ("parlant",     ParlantLabrat),
    ("hermes",      HermesLabrat),
])
def test_labrat_registers_under_scheme(scheme, cls):
    spec = target_for_url(f"{scheme}://labrat")
    assert spec is not None, f"{scheme}:// not registered"
    assert spec.description
    # Factory returns the right class.
    instance = spec.factory(f"{scheme}://labrat")
    assert isinstance(instance, cls)


@pytest.mark.parametrize("cls", [
    AutoGenLabrat, LangGraphLabrat, LlamaIndexLabrat,
    ParlantLabrat, HermesLabrat,
])
def test_labrat_enumerates_canonical_surface_kinds(cls):
    cls.reset()
    async def go():
        a = cls()
        async with a:
            return await a.enumerate()
    surfaces = asyncio.run(go())
    kinds = {s.name.split(":", 1)[0] for s in surfaces if ":" in s.name}
    # Every framework labrat must expose at least chat + tool + memory
    # — the minimum surface set for a realistic agentic deployment.
    assert "chat"   in kinds
    assert "tool"   in kinds
    assert "memory" in kinds


# ── End-to-end engagement ──────────────────────────────────────────────────

@pytest.mark.parametrize("scheme", [
    "autogen", "langgraph", "llamaindex", "parlant", "hermes",
])
def test_engagement_against_labrat_emits_artifacts(scheme, tmp_path):
    out = tmp_path / scheme
    result = run_engagement(
        target_url=f"{scheme}://labrat",
        output_dir=str(out), clean=True,
    )
    # The engagement produced findings (the labrat is intentionally
    # exploitable).
    assert result.findings, (
        f"{scheme} labrat produced no findings"
    )
    assert result.target_scheme == scheme

    # Chain artifact is shaped.
    chain = json.loads((out / "chain.json").read_text())
    assert chain["chain_id"].startswith("chain-")
    assert len(chain["steps"]) >= 2
    assert chain["severity"] in {"HIGH", "CRITICAL"}

    # Impact artifact has a harm score and at least one regulatory tag.
    impact = json.loads((out / "impact.json").read_text())
    assert impact["harm_score"] > 0
    assert impact["regulatory_impact"], (
        f"{scheme} engagement didn't touch any regulation"
    )

    # ALEC envelope written.
    envelope = json.loads((out / "alec_envelope.json").read_text())
    assert envelope["envelope_id"].startswith("alec-")

    # Summary written.
    summary = (out / "SUMMARY.txt").read_text()
    assert "engagement — artifact package" in summary
    assert "Kill-chain steps" in summary
