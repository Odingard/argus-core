"""
tests/test_demo_generic_agent.py — end-to-end demo runner.

Runs the packaged demo against its in-process labrat and asserts
the full artifact package is emitted correctly. No mocks, no
fabricated findings — this is the same code path operators invoke
from the CLI.
"""
from __future__ import annotations

import json

from argus.demo import run_generic_agent


def test_demo_emits_full_artifact_package(tmp_path):
    out = tmp_path / "demo_out"
    rc = run_generic_agent(output_dir=str(out), clean=True)
    assert rc == 0

    # 1. SUMMARY.txt exists and names every stage.
    summary = (out / "SUMMARY.txt").read_text()
    assert "GenericAgent demo artifact package" in summary
    assert "MP-03" in summary
    assert "EP-11" in summary
    assert "CERBERUS rules emitted" in summary
    assert "severity_label" in summary

    # 2. Findings dir has both agents' JSON.
    assert (out / "findings" / "mp" / "MP-03_findings.json").exists()
    assert (out / "findings" / "ep" / "EP-11_findings.json").exists()

    # 3. Evidence file is sealed and proof-grade.
    ev_files = list((out / "evidence").glob("ev-*.json"))
    assert ev_files, "no evidence file written"
    ev = json.loads(ev_files[0].read_text())
    assert ev["integrity_sha"], "evidence not sealed"
    assert ev["pcap"], "pcap empty"
    assert ev["container_logs"], "container_logs empty"

    # 4. Chain v2 artifact is shaped correctly.
    chain = json.loads((out / "chain.json").read_text())
    assert chain["chain_id"].startswith("chain-")
    assert len(chain["steps"]) >= 2
    assert chain["cve_draft_id"].startswith("ARGUS-DRAFT-CVE-")
    # OWASP AAI03 Memory Poisoning + AAI07 Privilege Escalation (pivot)
    # are the two categories the labrat's two attack classes map to.
    owasp = set(chain["owasp_categories"])
    assert "AAI03" in owasp
    assert "AAI07" in owasp

    # 5. BlastRadiusMap is populated.
    impact = json.loads((out / "impact.json").read_text())
    assert impact["harm_score"] > 0
    assert impact["severity_label"] in {
        "MEDIUM", "HIGH", "CRITICAL", "CATASTROPHIC",
    }
    assert "SECRET" in impact["data_classes_exposed"]
    assert impact["regulatory_impact"]
    assert impact["transitively_reachable"], (
        "no transitive surfaces — trust-transitivity didn't fire"
    )

    # 6. CERBERUS rules were emitted and deduped.
    rules_file = out / "cerberus" / "cerberus_rules.json"
    assert rules_file.exists()
    rules = json.loads(rules_file.read_text())
    assert rules["rule_count"] >= 2
    classes = {r["vuln_class"] for r in rules["rules"]}
    assert classes == {"MEMORY_POISONING", "ENVIRONMENT_PIVOT"}

    # 7. ALEC envelope is built and references the Wilson bundle.
    envelope = json.loads((out / "alec_envelope.json").read_text())
    assert envelope["envelope_id"].startswith("alec-")
    assert envelope["finding_count"] >= 4
    assert envelope["integrity"]
    assert "CRITICAL" in envelope["severity_summary"]

    # 8. Wilson-shaped bundle is present with manifest + evidence.
    bundle = out / "wilson_bundle"
    assert bundle.exists()
    assert (bundle / "manifest.json").exists()
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["target_id"] == "generic-agent://demo-labrat"
    assert manifest["compound_chain"]["chain_id"] == chain["chain_id"]
    assert manifest["impact"]["harm_score"] == impact["harm_score"]

    # 9. Pillar-2 Raptor Cycle: corpus grew from real findings.
    discovered = out / "discovered"
    disc_files = list(discovered.glob("disc_*.json"))
    assert disc_files, "EvolveCorpus did not grow during the demo"


def test_demo_idempotent_under_clean(tmp_path):
    """Re-running with --clean wipes and regenerates — chain and
    envelope ids are deterministic for a given target + finding set
    but integrity hashes match only when inputs are byte-identical."""
    out = tmp_path / "repeat"
    rc1 = run_generic_agent(output_dir=str(out), clean=True)
    chain_a = json.loads((out / "chain.json").read_text())
    rc2 = run_generic_agent(output_dir=str(out), clean=True)
    chain_b = json.loads((out / "chain.json").read_text())
    assert rc1 == 0 and rc2 == 0
    # Same target, same labrat behaviour → same OWASP coverage and
    # same step count. Chain_id is deterministic given the finding ids.
    assert set(chain_a["owasp_categories"]) == set(chain_b["owasp_categories"])
    assert len(chain_a["steps"]) == len(chain_b["steps"])
