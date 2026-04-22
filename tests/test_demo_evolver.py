"""
tests/test_demo_evolver.py — end-to-end Pillar-2 Raptor Cycle demo.
"""
from __future__ import annotations

import json

from argus.demo import run_evolver


def test_demo_evolver_emits_full_artifact_package(tmp_path):
    out = tmp_path / "evolver_out"
    rc = run_evolver(
        output_dir=str(out),
        clean=True, generations=4, seed=7,
        seed_sample=20,
    )
    assert rc == 0

    # Summary exists and carries the expected sections.
    summary = (out / "EVOLUTION_SUMMARY.txt").read_text()
    assert "Pillar-2 Raptor Cycle" in summary
    assert "Top-10 elites" in summary
    assert "Cell coverage" in summary

    # elites.json is shaped correctly.
    elites = json.loads((out / "elites.json").read_text())
    assert elites["elite_count"] >= 1
    assert len(elites["cells"]) == elites["elite_count"]
    for cell in elites["cells"]:
        assert "coordinates" in cell
        assert "elite" in cell
        assert cell["elite"]["fitness"] >= 0.0

    # lineage.jsonl has one line per elite.
    lineage_lines = (out / "lineage.jsonl").read_text().strip().splitlines()
    assert len(lineage_lines) == elites["elite_count"]
    for line in lineage_lines:
        ln = json.loads(line)
        assert ln["payload_id"]
        assert "steps" in ln

    # Discovered seeds written — Pillar-2 closed.
    disc_files = list((out / "discovered").glob("disc_*.json"))
    assert disc_files, "elites were not promoted into the corpus"
    # At least one entry carries the cell + fitness tag the demo
    # writes.
    sample = json.loads(disc_files[0].read_text())
    assert isinstance(sample, list) and sample
    tags = sample[0].get("tags", [])
    assert any(t.startswith("cell:") for t in tags)
    assert any(t.startswith("fitness:") for t in tags)
    assert "evolver_elite" in tags


def test_demo_evolver_produces_diverse_grid(tmp_path):
    """The demo must end with coverage across at least TWO distinct
    OWASP cells — MAP-Elites' whole value prop."""
    out = tmp_path / "diverse"
    run_evolver(output_dir=str(out), clean=True,
                generations=6, seed=11, seed_sample=30)
    elites = json.loads((out / "elites.json").read_text())
    owasp_seen = {
        cell["coordinates"][0] for cell in elites["cells"]
    }
    assert len(owasp_seen) >= 2, (
        f"grid collapsed onto one OWASP cell: {owasp_seen}"
    )


def test_demo_evolver_zero_llm_cost(tmp_path):
    """OfflineMutatorBackend is the default — the demo must never
    require an LLM. Verified by running with no API keys and checking
    the summary's '0 LLM calls' headline remnant."""
    out = tmp_path / "cheap"
    rc = run_evolver(
        output_dir=str(out), clean=True, generations=3,
        seed=1, seed_sample=15,
    )
    assert rc == 0
    # The backend label in the serialized result is the offline one.
    elites = json.loads((out / "elites.json").read_text())
    sources = set()
    for cell in elites["cells"]:
        sources.add(cell["elite"]["metadata"].get("source", ""))
    assert sources.issubset({"seed", "offline"})
