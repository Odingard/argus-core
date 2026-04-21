#!/usr/bin/env python3
"""
cli.py — ARGUS
Orchestrates all 6 layers of the agentic AI vulnerability pipeline.

Usage:
  python cli.py https://github.com/target/repo -o results/

  # Resume from specific layer
  python cli.py --from-layer 3 --input results/crewai/

  # Run only specific layer
  python cli.py https://github.com/target/repo --only-layer 1

  # Skip a layer
  python cli.py https://github.com/target/repo --skip-layer 4

Cost estimate: ~$24 / ~65 min for a medium repo
"""
from __future__ import annotations

import os

import json
import argparse
from dotenv import load_dotenv

# Load all API Keys from .env before any client constructs.
load_dotenv(override=True)
import tempfile
import shutil
from pathlib import Path
from dataclasses import asdict


import importlib
import inspect
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, Future

from argus.shared.models import PipelineRun, L1Report

# ── Helpers ───────────────────────────────────────────────────────────────────
SEV_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[32m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
BLUE  = "\033[94m"
GRAY  = "\033[90m"

BANNER = f"""\033[38;5;196m{BOLD}
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║       ___    ____  ________  __  _____                                     ║
║      /   |  / __ \\/ ____/ / / / / ___/                                     ║
║     / /| | / /_/ / / __/ / / /  \\__ \\                                      ║
║    / ___ |/ _, _/ /_/ / /_/ /  ___/ /                                      ║
║   /_/  |_/_/ |_|\\____/\\____/  /____/                                       ║
║                                                                            ║
║   {RESET}\033[38;5;196mAutonomous AI Red Team Platform{BOLD}                                          ║
║   {RESET}\033[38;5;203mOdingard Security • Six Sense{BOLD}\033[38;5;196m                                            ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝{RESET}
"""


def _color(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def _save_json(data: dict, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _clone_repo(url: str, dest: str) -> bool:
    import zipfile
    import urllib.request
    import shutil
    import tempfile
    try:
        if url.endswith(".git"):
            url = url[:-4]
        zip_url = f"{url}/archive/refs/heads/main.zip"
        
        temp_zip = os.path.join(tempfile.gettempdir(), "repo_download.zip")
        try:
            urllib.request.urlretrieve(zip_url, temp_zip)
        except Exception:
            zip_url = f"{url}/archive/refs/heads/master.zip"
            urllib.request.urlretrieve(zip_url, temp_zip)
            
        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
            temp_ext = os.path.join(tempfile.gettempdir(), "repo_extract")
            zip_ref.extractall(temp_ext)
            extracted_roots = os.listdir(temp_ext)
            if extracted_roots:
                top_dir = os.path.join(temp_ext, extracted_roots[0])
                shutil.copytree(top_dir, dest, dirs_exist_ok=True)
            shutil.rmtree(temp_ext, ignore_errors=True)
        
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        return True
    except Exception:
        return False


def _layer_path(output_dir: str, layer: int) -> str:
    return os.path.join(output_dir, f"layer{layer}.json")


def _layer_exists(output_dir: str, layer: int) -> bool:
    return os.path.exists(_layer_path(output_dir, layer))


# ── Layer runners ─────────────────────────────────────────────────────────────

def run_layer0(run: PipelineRun, args) -> None:
    """Layer 0 — Version Synchronization Sentinel."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 0 — Version Fingerprinting & Synchronization{RESET}")
    print(f"{'━'*62}\n")
    
    from argus.layer0.fingerprinter import VersionFingerprinter
    
    fingerprinter = VersionFingerprinter(run.repo_path)
    constraints = fingerprinter.get_constraints()
    
    output_file = _layer_path(run.output_dir, 0)
    _save_json({"fingerprint_version": constraints.get("framework_version"), "git_tag": constraints.get("git_tag")}, output_file)
    run.completed_layers.append(0)

def run_layer1(run: PipelineRun, args) -> None:
    """Layer 1 — Scanner (scanner_v3.py integrated)."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 1 — Discovery & Fingerprinting{RESET}")
    print(f"{'━'*62}\n")

    from argus.layer1.scanner import run_scan as scanner_run_scan

    output_file = _layer_path(run.output_dir, 1)

    # Run scanner_v3 scan on the cloned local repo path, not the github URL
    scanner_run_scan(
        target=run.repo_path,
        output_file=output_file,
        skip_poc=getattr(args, 'skip_poc', False),
        skip_chains=True,           # chains done at L5
        verbose=args.verbose,
        poc_sev="CRITICAL",         # only PoC CRITICALs in L1
        poc_cls=""
    )

    # Load result and attach repo path
    if os.path.exists(output_file):
        data = _load_json(output_file)
        run.l1 = L1Report.from_dict(data, repo_path=run.repo_path)
        run.completed_layers.append(1)
        print(f"\n  {_color('✓', BOLD)} L1 complete — {data['total_findings']} findings, "
              f"{_color(str(data['critical_count']) + ' CRITICAL', SEV_COLORS['CRITICAL'])}")
    else:
        print(f"  {_color('✗', SEV_COLORS['CRITICAL'])} L1 scan produced no output")


def run_layer2(run: PipelineRun, args) -> None:
    """Layer 2 — Vulnerability Surface Analyzer."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 2 — Vulnerability Surface Analyzer{RESET}")
    print(f"{'━'*62}\n")

    if run.l1 is None:
        data = _load_json(_layer_path(run.output_dir, 1))
        run.l1 = L1Report.from_dict(data, repo_path=run.repo_path)

    from argus.layer2.surface_analyzer import run_layer2 as _run_l2
    run.l2 = _run_l2(run.l1, verbose=args.verbose, output_dir=run.output_dir)

    # Serialize L2 to JSON
    def _serialize(obj):
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        return str(obj)

    output_file = _layer_path(run.output_dir, 2)
    _save_json({
        "target": run.l2.target,
        "schema_injection_count": len(run.l2.schema_injection_paths),
        "escalation_path_count": len(run.l2.escalation_paths),
        "deser_chain_count": len(run.l2.deser_chains),
        "memory_gap_count": len(run.l2.memory_boundary_gaps),
        "auth_gap_count": len(run.l2.auth_gap_paths),
        "graph_nodes": run.l2.graph_node_count,
        "graph_edges": run.l2.graph_edge_count,
        "hypothesis_count": len(run.l2.ranked_hypotheses),
        "schema_injection_paths": [asdict(p) for p in run.l2.schema_injection_paths],
        "escalation_paths": [asdict(p) for p in run.l2.escalation_paths],
        "deser_chains": [asdict(c) for c in run.l2.deser_chains],
        "memory_boundary_gaps": [asdict(g) for g in run.l2.memory_boundary_gaps],
        "auth_gap_paths": [asdict(g) for g in run.l2.auth_gap_paths],
        "ranked_hypotheses": [asdict(h) for h in run.l2.ranked_hypotheses],
    }, output_file)

    run.completed_layers.append(2)
    print(f"\n  {_color('✓', BOLD)} L2 complete — "
          f"{len(run.l2.ranked_hypotheses)} hypotheses, "
          f"{len(run.l2.escalation_paths)} escalation paths")


def run_layer3(run: PipelineRun, args) -> None:
    """Layer 3 — Semantic Fuzzing Engine (Haiku)."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 3 — Semantic Fuzzing Engine{RESET}")
    print(f"{'━'*62}\n")

    if run.l2 is None:
        data = _load_json(_layer_path(run.output_dir, 2))
        from argus.shared.models import L2SurfaceMap, SchemaInjectionPath, EscalationPath
        from argus.shared.models import DeserChain, MemoryBoundaryGap, AuthGapPath, VulnHypothesis
        run.l2 = L2SurfaceMap(
            target=data["target"],
            graph_node_count=data.get("graph_nodes", 0),
            graph_edge_count=data.get("graph_edges", 0),
        )
        run.l2.ranked_hypotheses = [VulnHypothesis(**h) for h in data.get("ranked_hypotheses", [])]
        run.l2.schema_injection_paths = [SchemaInjectionPath(**p) for p in data.get("schema_injection_paths", [])]
        run.l2.escalation_paths = [EscalationPath(**p) for p in data.get("escalation_paths", [])]
        run.l2.deser_chains = [DeserChain(**c) for c in data.get("deser_chains", [])]
        run.l2.memory_boundary_gaps = [MemoryBoundaryGap(**g) for g in data.get("memory_boundary_gaps", [])]
        run.l2.auth_gap_paths = [AuthGapPath(**g) for g in data.get("auth_gap_paths", [])]

    from argus.layer3.fuzzer import run_layer3 as _run_l3
    run.l3 = _run_l3(run.l2, verbose=args.verbose)

    output_file = _layer_path(run.output_dir, 3)
    _save_json({
        "target": run.l3.target,
        "total_payloads": run.l3.total_payloads,
        "schema_payloads": run.l3.schema_payloads,
        "chain_payloads": run.l3.chain_payloads,
        "memory_payloads": run.l3.memory_payloads,
        "fuzz_targets": run.l3.fuzz_targets,
    }, output_file)

    run.completed_layers.append(3)
    print(f"\n  {_color('✓', BOLD)} L3 complete — {run.l3.total_payloads} payloads generated")


def run_layer4(run: PipelineRun, args) -> None:
    """Layer 4 — Behavioral Deviation Detector (Haiku + Fidelity Score)."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 4 — Behavioral Deviation Detector{RESET}")
    print(f"{'━'*62}\n")

    if run.l3 is None:
        data = _load_json(_layer_path(run.output_dir, 3))
        from argus.shared.models import L3FuzzResults
        run.l3 = L3FuzzResults(
            target=data["target"],
            total_payloads=data["total_payloads"],
            schema_payloads=data["schema_payloads"],
            chain_payloads=data["chain_payloads"],
            memory_payloads=data["memory_payloads"],
            fuzz_targets=data["fuzz_targets"],
        )
    if run.l2 is None:
        data = _load_json(_layer_path(run.output_dir, 2))
        from argus.shared.models import L2SurfaceMap, VulnHypothesis, SchemaInjectionPath
        from argus.shared.models import EscalationPath, MemoryBoundaryGap
        run.l2 = L2SurfaceMap(target=data["target"])
        run.l2.ranked_hypotheses = [VulnHypothesis(**h) for h in data.get("ranked_hypotheses", [])]
        run.l2.schema_injection_paths = [SchemaInjectionPath(**p) for p in data.get("schema_injection_paths", [])]
        run.l2.escalation_paths = [EscalationPath(**p) for p in data.get("escalation_paths", [])]
        run.l2.memory_boundary_gaps = [MemoryBoundaryGap(**g) for g in data.get("memory_boundary_gaps", [])]

    from argus.layer4.deviation_detector import run_layer4 as _run_l4
    run.l4 = _run_l4(run.l3, run.l2, l1_report=run.l1, verbose=args.verbose)

    output_file = _layer_path(run.output_dir, 4)
    from dataclasses import asdict
    _save_json({
        "target": run.l4.target,
        "total_deviations": len(run.l4.deviations),
        "high_confidence": run.l4.high_confidence,
        "medium_confidence": run.l4.medium_confidence,
        "low_confidence": run.l4.low_confidence,
        "deviations": [asdict(d) for d in run.l4.deviations],
    }, output_file)

    run.completed_layers.append(4)
    print(f"\n  {_color('✓', BOLD)} L4 complete — "
          f"{run.l4.high_confidence} high-confidence deviations → L5")


def run_layer5(run: PipelineRun, args) -> None:
    """Layer 5 — Exploit Chain Synthesizer (Opus)."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 5 — Exploit Chain Synthesizer (Opus){RESET}")
    print(f"{'━'*62}\n")

    # Load L4 if not in memory
    if run.l4 is None:
        data = _load_json(_layer_path(run.output_dir, 4))
        from argus.shared.models import L4Deviations, DeviationPrediction
        run.l4 = L4Deviations(
            target=data["target"],
            high_confidence=data["high_confidence"],
            medium_confidence=data["medium_confidence"],
            low_confidence=data["low_confidence"],
        )
        run.l4.deviations = [DeviationPrediction(**d) for d in data.get("deviations", [])]

    # Load L2 if not in memory
    if run.l2 is None:
        try:
            data = _load_json(_layer_path(run.output_dir, 2))
            from argus.shared.models import L2SurfaceMap, VulnHypothesis, SchemaInjectionPath
            from argus.shared.models import EscalationPath, MemoryBoundaryGap
            run.l2 = L2SurfaceMap(target=data["target"])
            run.l2.ranked_hypotheses = [VulnHypothesis(**h) for h in data.get("ranked_hypotheses", [])]
            run.l2.schema_injection_paths = [SchemaInjectionPath(**p) for p in data.get("schema_injection_paths", [])]
            run.l2.escalation_paths = [EscalationPath(**p) for p in data.get("escalation_paths", [])]
            run.l2.memory_boundary_gaps = [MemoryBoundaryGap(**g) for g in data.get("memory_boundary_gaps", [])]
        except FileNotFoundError:
            # No L2 output means L2 found no attack surface. Proceed with an empty
            # surface map; L5 will honestly produce zero chains rather than fabricate.
            print(f"  {GRAY}[L5] layer2.json missing — proceeding with empty surface map.{RESET}")
            from argus.shared.models import L2SurfaceMap
            run.l2 = L2SurfaceMap(target=run.target)

    from argus.layer5.chain_synthesizer import run_layer5 as _run_l5
    run.l5 = _run_l5(run.l4, run.l2, l1_report=run.l1, verbose=args.verbose)

    # Merge any chains the live correlator already synthesized in-flight
    # (only populated when --swarm was set). These are gravy on top of
    # whatever the static L5 Opus call produced. Existing chain_ids
    # deduplicate.
    correlator_chains = getattr(run, "l5_correlator_chains", None) or []
    if correlator_chains:
        from argus.shared.models import ExploitChain, ExploitStep
        existing_ids = {c.chain_id for c in run.l5.chains}
        added = 0
        for raw in correlator_chains:
            cid = raw.get("chain_id") or ""
            if not cid or cid in existing_ids:
                continue
            steps = [
                ExploitStep(
                    step=s.get("step", i + 1),
                    action=s.get("action", ""),
                    payload=s.get("payload"),
                    achieves=s.get("achieves", ""),
                )
                for i, s in enumerate(raw.get("steps", []))
            ]
            chain = ExploitChain(
                chain_id=cid,
                title=raw.get("title", "Correlator chain"),
                component_deviations=raw.get("finding_ids", []),
                steps=steps,
                poc_code=raw.get("poc_code", ""),
                cvss_estimate=raw.get("cvss_estimate", ""),
                mitre_atlas_ttps=raw.get("mitre_atlas_ttps", []),
                owasp_llm_categories=raw.get("owasp_llm_categories", []),
                preconditions=raw.get("preconditions", []),
                blast_radius=raw.get("blast_radius", "MEDIUM"),
                entry_point=raw.get("entry_point", "unknown"),
                combined_score=float(raw.get("combined_score", 0.75)),
            )
            run.l5.chains.append(chain)
            existing_ids.add(cid)
            added += 1
        if added:
            print(f"  [L5] merged {added} correlator-synthesized chain(s)")
            run.l5.critical_count = sum(
                1 for c in run.l5.chains if c.blast_radius == "CRITICAL"
            )
            run.l5.high_count = sum(
                1 for c in run.l5.chains if c.blast_radius == "HIGH"
            )

    output_file = _layer_path(run.output_dir, 5)
    from dataclasses import asdict
    _save_json({
        "target": run.l5.target,
        "chain_count": len(run.l5.chains),
        "critical_count": run.l5.critical_count,
        "high_count": run.l5.high_count,
        "chains": [asdict(c) for c in run.l5.chains],
    }, output_file)

    run.completed_layers.append(5)
    print(f"\n  {_color('✓', BOLD)} L5 complete — "
          f"{_color(str(run.l5.critical_count) + ' CRITICAL', SEV_COLORS['CRITICAL'])} chains, "
          f"{run.l5.high_count} HIGH chains")


def run_layer6(run: PipelineRun, args) -> None:
    """Layer 6 — CVE Pipeline + Intelligence Flywheel."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 6 — CVE Pipeline + Intelligence Flywheel{RESET}")
    print(f"{'━'*62}\n")

    # Load L5 if not in memory
    if run.l5 is None:
        data = _load_json(_layer_path(run.output_dir, 5))
        from argus.shared.models import L5Chains, ExploitChain, ExploitStep
        run.l5 = L5Chains(
            target=data["target"],
            critical_count=data["critical_count"],
            high_count=data["high_count"],
        )
        chains = []
        for c in data.get("chains", []):
            steps = [ExploitStep(**s) for s in c.pop("steps", [])]
            chains.append(ExploitChain(**{**c, "steps": steps}))
        run.l5.chains = chains

    from argus.layer6.cve_pipeline import run_layer6 as _run_l6
    run.l6 = _run_l6(
        run.l5,
        output_dir=run.output_dir,
        l1_report=run.l1,
        verbose=args.verbose
    )

    output_file = _layer_path(run.output_dir, 6)
    from dataclasses import asdict
    _save_json({
        "target": run.l6.target,
        "cve_count": len(run.l6.cve_drafts),
        "flywheel_count": len(run.l6.flywheel_entries),
        "cve_drafts": [asdict(d) for d in run.l6.cve_drafts],
        "flywheel_entries": [asdict(e) for e in run.l6.flywheel_entries],
    }, output_file)

    run.completed_layers.append(6)
    print(f"\n  {_color('✓', BOLD)} L6 complete — "
          f"{len(run.l6.cve_drafts)} CVE drafts, "
          f"{len(run.l6.flywheel_entries)} flywheel entries")


def run_layer7(run: PipelineRun, args) -> None:
    """Layer 7 — Execution Sandbox Validation."""
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  LAYER 7 — Execution Sandbox Validation{RESET}")
    print(f"{'━'*62}\n")

    if run.l5 is None:
        data = _load_json(_layer_path(run.output_dir, 5))
        from argus.shared.models import L5Chains, ExploitChain, ExploitStep
        run.l5 = L5Chains(
            target=data["target"],
            critical_count=data["critical_count"],
            high_count=data["high_count"],
        )
        chains = []
        for c in data.get("chains", []):
            steps = [ExploitStep(**s) for s in c.pop("steps", [])]
            chains.append(ExploitChain(**{**c, "steps": steps}))
        run.l5.chains = chains

    if not run.repo_path:
        print(f"  {_color('✗', SEV_COLORS['CRITICAL'])} Layer 7 requires repo_path for Sandbox execution.")
        return

    from argus.layer7.sandbox import validate_l5_chains
    validate_l5_chains(run.l5, run.repo_path, getattr(args, 'verbose', False))

    # We alter the internal L5 state with validation flags so L6 pulls the validated chains
    output_file = _layer_path(run.output_dir, 7)
    _save_json({
        "validated_chains": [c.chain_id for c in run.l5.chains if c.is_validated]
    }, output_file)

    # Auto-build a Wilson-Proof forensic bundle for every validated chain.
    # This is the kinetic-verification pillar: a signed, hashed, repro-able
    # artifact package per chain so triage officers can't dismiss findings
    # as "theoretical".
    try:
        from argus.wilson.bundle import build_bundle_for_chain
        built = 0
        for c in run.l5.chains:
            if not c.is_validated:
                continue
            bundle = build_bundle_for_chain(c, run.output_dir)
            built += 1
            print(f"  {_color('✓', BOLD)} Wilson bundle  → {bundle.bundle_dir}")
        if built == 0:
            print(f"  {GRAY}[wilson] no validated chains → no bundles built{RESET}")
    except Exception as e:
        print(f"  {GRAY}[wilson] bundle build failed: {e}{RESET}")

    run.completed_layers.append(7)
    run.l7 = True


# ── Pipeline ──────────────────────────────────────────────────────────────────

LAYER_RUNNERS = {
    0: run_layer0,
    1: run_layer1,
    2: run_layer2,
    3: run_layer3,
    4: run_layer4,
    5: run_layer5,
    6: run_layer6,
}


# ── Agent Discovery — Dynamic Loader ─────────────────────────────────────────

def _discover_agents() -> list[type]:
    """
    Dynamically discover all BaseAgent subclasses in the agents/ directory.
    Drop any file containing a BaseAgent subclass into agents/ and it runs.
    No changes to this file required.
    """
    from argus.agents.base import BaseAgent
    agents_dir = Path(__file__).parent / "agents"
    discovered = []

    for py_file in sorted(agents_dir.glob("*.py")):
        if py_file.stem in ("__init__", "base"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if (issubclass(obj, BaseAgent) and
                        obj is not BaseAgent and
                        obj.AGENT_ID):
                    discovered.append(obj)
        except Exception as e:
            print(f"  {GRAY}[LOADER] Skipped {py_file.name}: {e}{RESET}")

    return discovered


# ── AgentFinding → DeviationPrediction Converter ─────────────────────────────

def _agent_finding_to_deviation(finding) -> object:
    """
    Convert an AgentFinding to a DeviationPrediction for L5 synthesis.

    Agent findings are deterministic static analysis — no runtime uncertainty.
    combined_score = 0.95 (high confidence, not 1.0 to keep L5 ranking honest).
    simulation_mode = "agent_static" so L5 knows the provenance.
    """
    from argus.shared.models import DeviationPrediction
    return DeviationPrediction(
        payload_id        = finding.id,
        hypothesis_id     = f"AGENT-{finding.agent_id}",
        predicted_deviation = finding.description,
        confidence        = 0.95,
        fidelity_score    = 1.0,
        combined_score    = 0.95,
        simulation_mode   = "agent_static",
        deviation_type    = finding.vuln_class,
        impact            = finding.severity,
        trigger_conditions = [finding.attack_vector] if finding.attack_vector else [],
        fidelity_notes    = f"Agent {finding.agent_id} | technique {finding.technique}"
    )


# ── Core Pipeline Thread (L2→L3→L4) ──────────────────────────────────────────

def _run_core_pipeline(run: object, args) -> str:
    """
    Sequential L2→L3→L4 execution — runs in Thread 1 of the swarm.
    Returns "ok" or raises on failure.
    """
    try:
        if run.l2 is None and not _layer_exists(run.output_dir, 2):
            run_layer2(run, args)
        if run.l3 is None and not _layer_exists(run.output_dir, 3):
            run_layer3(run, args)
        if run.l4 is None and not _layer_exists(run.output_dir, 4):
            run_layer4(run, args)
        return "ok"
    except Exception as e:
        return f"error: {e}"


# ── Agent Thread Runner ───────────────────────────────────────────────────────

def _run_agent_thread(
    agent_class: type,
    run: object,
    args,
) -> tuple[str, list]:
    """
    Run a single agent in its own thread.
    Returns (agent_id, findings_list).
    Exceptions are caught — one crashing agent never kills the swarm.
    """
    agent_id = agent_class.AGENT_ID
    try:
        agent = agent_class(verbose=args.verbose)
        findings = agent.run(
            target    = run.target,
            repo_path = run.repo_path,
            output_dir = os.path.join(run.output_dir, "agents", agent_id)
        )
        return (agent_id, findings or [])
    except Exception as e:
        print(f"  {_color(f'[{agent_id}] Agent error: {e}', SEV_COLORS['CRITICAL'])}")
        if args.verbose:
            traceback.print_exc()
        return (agent_id, [])


# ── Swarm Orchestrator ────────────────────────────────────────────────────────

def _run_swarm_runtime(run: object, args) -> None:
    """
    Coordinated swarm runtime (argus.swarm). Replaces `_run_parallel_swarm`
    when `--swarm` is set. Does three things the thread-pool path cannot:

      1. Funnels every agent finding through a shared blackboard as it
         lands (not batched at end).
      2. Runs a LiveCorrelator thread that fires Haiku chain-judgements
         on candidate clusters mid-run, with Opus escalation for
         high-confidence chains — the patent's "correlation agent"
         operating live, not statically at L5.
      3. Pheromone-weights hot files on the blackboard so the operator
         can see which files the swarm is converging on.

    Output is still written to the classic L4 deviations shape so L5/L6/L7
    still consume it unchanged. Correlator-synthesized Opus chains are
    stashed at run.l5_correlator_chains for run_layer5 to merge in.
    """
    from argus.swarm.runtime import run_swarm as _swarm_run
    from argus.shared.models import L4Deviations

    # Repo must exist before agents can scan it. If it doesn't, fall back
    # to the classic path (which handles MCP-only / remote targets).
    if not run.repo_path or not os.path.exists(run.repo_path):
        print(f"\n  {GRAY}[swarm] no repo_path — deferring to classic "
              f"thread-pool swarm{RESET}")
        _run_parallel_swarm(run, args)
        return

    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  SWARM RUNTIME — blackboard + live correlator{RESET}")
    print(f"{'━'*62}")

    result = _swarm_run(
        target=run.target,
        repo_path=run.repo_path,
        output_dir=run.output_dir,
        verbose=args.verbose,
    )

    # Build L4 deviations from the swarm's findings so downstream layers
    # see a pipeline that looks identical to the thread-pool version.
    if run.l4 is None:
        run.l4 = L4Deviations(target=run.target)

    # Rehydrate AgentFinding objects from the dicts the swarm returned.
    from argus.agents.base import AgentFinding
    agent_findings: list = []
    for fd in result.get("findings", []):
        try:
            agent_findings.append(AgentFinding(**fd))
        except TypeError:
            # Forward-compat: if AgentFinding grew a new field after the
            # swarm wrote its dicts, ignore unknown keys.
            known = {k: v for k, v in fd.items()
                     if k in AgentFinding.__annotations__}
            agent_findings.append(AgentFinding(**known))

    deviations = [_agent_finding_to_deviation(f) for f in agent_findings]
    run.l4.deviations.extend(deviations)
    run.l4.high_confidence += len(deviations)

    # Persist L4 so `--from-layer 5` resume still works.
    from dataclasses import asdict
    output_file = _layer_path(run.output_dir, 4)
    _save_json({
        "target":           run.l4.target,
        "total_deviations": len(run.l4.deviations),
        "high_confidence":  run.l4.high_confidence,
        "medium_confidence": run.l4.medium_confidence,
        "low_confidence":   run.l4.low_confidence,
        "deviations":       [asdict(d) for d in run.l4.deviations],
    }, output_file)

    # Stash correlator-synthesized chains where run_layer5 can pick them up.
    run.l5_correlator_chains = result.get("opus_chains", [])

    # Mark layers 2-4 complete so the pipeline counter is honest. The
    # swarm subsumes classical L2/L3/L4 by producing the same shape.
    for n in (2, 3, 4):
        if n not in run.completed_layers:
            run.completed_layers.append(n)

    print(f"\n  {_color('✓', BOLD)} Swarm complete — "
          f"{len(agent_findings)} findings, "
          f"{len(result.get('hypotheses', []))} chain hypotheses, "
          f"{len(run.l5_correlator_chains)} Opus-synthesized chains")


def _run_parallel_swarm(run: object, args) -> None:
    """
    ThreadPoolExecutor swarm:
      Thread 1: core pipeline  (L2 → L3 → L4)
      Thread N: each discovered agent (RC-08, ME-10, PH-11, ...)

    All threads seed from the same L1 findings.
    All agent findings are merged into L4 deviations before L5 runs.
    """
    agent_classes = _discover_agents()

    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  PARALLEL SWARM — {1 + len(agent_classes)} concurrent workers{RESET}")
    print(f"{'━'*62}")
    print(f"  Thread 1 : Core pipeline (L2 → L3 → L4)")
    for ac in agent_classes:
        phases = getattr(ac, "MAAC_PHASES", []) or []
        phase_str = f"  MAAC {'+'.join(str(p) for p in phases)}" if phases else "  MAAC —"
        print(f"  Thread   : {ac.AGENT_ID} — {ac.AGENT_NAME}{phase_str}")

    # MAAC coverage across the swarm
    covered = sorted({p for ac in agent_classes for p in getattr(ac, "MAAC_PHASES", []) or []})
    missing = [p for p in range(1, 10) if p not in covered]
    print(f"\n  MAAC coverage: phases {covered or '—'}")
    if missing:
        print(f"  {GRAY}MAAC gaps    : phases {missing} (no agent currently covers){RESET}")
    print()

    all_agent_findings: list = []

    with ThreadPoolExecutor(max_workers=1 + len(agent_classes),
                            thread_name_prefix="argus") as pool:
        futures: dict[Future, str] = {}

        # Thread 1: core pipeline
        futures[pool.submit(_run_core_pipeline, run, args)] = "core"

        # Thread N: one per agent (only if repo is available)
        if run.repo_path and os.path.exists(run.repo_path):
            for ac in agent_classes:
                futures[pool.submit(_run_agent_thread, ac, run, args)] = ac.AGENT_ID
        else:
            print(f"  {GRAY}No repo path — agents skipped (MCP-only target){RESET}")

        # Collect results as they complete
        for future in as_completed(futures):
            worker_id = futures[future]
            try:
                result = future.result()
                if worker_id == "core":
                    status = result if isinstance(result, str) else "ok"
                    icon = _color("✓", BOLD) if status == "ok" else _color("✗", SEV_COLORS["CRITICAL"])
                    print(f"\n  {icon} Core pipeline complete ({status})")
                else:
                    agent_id, findings = result
                    all_agent_findings.extend(findings)
                    crit = sum(1 for f in findings if f.severity == "CRITICAL")
                    high = sum(1 for f in findings if f.severity == "HIGH")
                    print(f"  {_color('✓', BOLD)} {agent_id} complete — "
                          f"{len(findings)} findings "
                          f"({_color(str(crit)+' CRITICAL', SEV_COLORS['CRITICAL'])}, "
                          f"{high} HIGH)")
            except Exception as e:
                print(f"  {_color(f'Future error [{worker_id}]: {e}', SEV_COLORS['CRITICAL'])}")
                if args.verbose:
                    traceback.print_exc()

    # ── Merge agent findings into L4 before L5 synthesis ─────────────────
    if all_agent_findings:
        print(f"\n  Merging {len(all_agent_findings)} agent findings into L4...")

        # Ensure L4 exists (core pipeline may have populated it)
        if run.l4 is None:
            from argus.shared.models import L4Deviations
            run.l4 = L4Deviations(target=run.target)

        agent_deviations = [_agent_finding_to_deviation(f) for f in all_agent_findings]
        run.l4.deviations.extend(agent_deviations)
        run.l4.high_confidence += len(agent_deviations)

        # Save merged L4
        output_file = _layer_path(run.output_dir, 4)
        from dataclasses import asdict
        existing = {}
        if os.path.exists(output_file):
            existing = _load_json(output_file)
        existing_devs = existing.get("deviations", [])
        _save_json({
            "target"          : run.l4.target,
            "total_deviations": len(run.l4.deviations),
            "high_confidence" : run.l4.high_confidence,
            "medium_confidence": run.l4.medium_confidence,
            "low_confidence"  : run.l4.low_confidence,
            "deviations"      : existing_devs + [asdict(d) for d in agent_deviations],
        }, output_file)

        print(f"  {_color('✓', BOLD)} L4 merged — "
              f"{run.l4.high_confidence} total high-confidence deviations → L5")
    else:
        print(f"\n  No agent findings to merge")

    print(f"{'━'*62}\n")


def _run_harness_mode(args) -> None:
    """
    Stateful harness dispatcher. Target syntax: ``pkg.module:callable``
    (the callable receives a context dict per turn and returns an output
    dict per the TargetFn contract in argus.harness.runtime).
    """
    import importlib
    from argus.harness import (
        StatefulHarness, load_scenarios,
        no_forbidden_tool, no_secret_in_output,
        system_prompt_immutable, no_unauthorized_spawn,
        no_recursion_beyond,
    )

    target = args.target or ""
    if ":" not in target:
        print(f"  {_color('✗', SEV_COLORS['CRITICAL'])} "
              f"--harness target must be '<module.path>:<callable>' "
              f"(got {target!r})")
        return
    mod_name, attr_name = target.split(":", 1)
    try:
        mod = importlib.import_module(mod_name)
        target_fn = getattr(mod, attr_name)
    except (ImportError, AttributeError) as e:
        print(f"  {_color('✗', SEV_COLORS['CRITICAL'])} "
              f"cannot load {target}: {type(e).__name__}: {e}")
        return

    scenarios = load_scenarios(args.scenarios)
    invariants = [
        no_forbidden_tool(["delete", "drop_table", "rm_rf", "transfer_funds"]),
        no_secret_in_output([
            r"sk-(?:ant-|proj-)[A-Za-z0-9_\-]{16,}",
            r"hunter2",                       # scripted poison-fact
            r"admin[_\s]?password",
        ]),
        system_prompt_immutable(),
        no_unauthorized_spawn(),
        no_recursion_beyond(10),
    ]

    output_dir = args.output
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    harness = StatefulHarness(target_fn=target_fn, invariants=invariants)
    print(f"\n{BOLD}{'━'*62}{RESET}")
    print(f"{BOLD}  STATEFUL HARNESS — {len(scenarios)} scenarios × "
          f"{len(invariants)} invariants{RESET}")
    print(f"{'━'*62}")
    results = harness.run_all(scenarios, output_dir=output_dir)

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    print(f"\n  Passed: {passed}   Failed: {failed}")
    for r in results:
        icon = _color("✓", BOLD) if r.passed else _color("✗", SEV_COLORS["CRITICAL"])
        print(f"  {icon} {r.scenario_id}: {len(r.violations)} violation(s)")
        for v in r.violations[:3]:
            print(f"      [{v.severity}] turn {v.turn} — "
                  f"{v.contract_id}: {v.summary[:80]}")

    print(f"\n  Harness report → {output_dir}/harness_report.json")


def run_live_mcp(args) -> None:
    """
    Live-attack mode: speak MCP to a running server instead of scanning source.
    Dispatches to the MCP live attacker, writes its report under the output dir.
    """
    import asyncio
    from argus.mcp_attacker import mcp_live_attacker as live

    output_dir = args.output
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # The live attacker's argparse expects an object with .target, .transport,
    # .token, .output, .verbose, .server_cmd — build it from our args.
    class _LiveArgs:
        pass
    la = _LiveArgs()
    la.target     = args.target
    la.transport  = args.transport
    la.token      = args.token
    la.output     = output_dir
    la.verbose    = args.verbose
    la.server_cmd = args.server_cmd or []

    if la.transport == "stdio" and not la.server_cmd:
        print(f"  {_color('✗ --transport stdio requires -- <server command>', SEV_COLORS['CRITICAL'])}")
        return
    if la.transport == "sse" and not la.target:
        print(f"  {_color('✗ --transport sse requires a target URL', SEV_COLORS['CRITICAL'])}")
        return

    print(f"\n  Target     : {_color(la.target or ' '.join(la.server_cmd), BLUE)}")
    print(f"  Mode       : live MCP attack")
    print(f"  Transport  : {la.transport}")
    print(f"  Auth       : {'set' if la.token else 'none'}")
    print(f"  Output dir : {output_dir}")

    try:
        if la.transport == "sse":
            asyncio.run(live._run_sse(la))
        else:
            asyncio.run(live._run_stdio(la))
    except KeyboardInterrupt:
        print(f"\n  {_color('[!] Interrupted', SEV_COLORS['HIGH'])}")
    except Exception as e:
        print(f"\n  {_color(f'[!] Live attack failed: {e}', SEV_COLORS['CRITICAL'])}")
        if args.verbose:
            traceback.print_exc()


def run_pipeline(args) -> None:
    print(BANNER)

    # Stateful harness mode — deterministic replay against a target callable.
    if getattr(args, "harness", False):
        _run_harness_mode(args)
        return

    # Live MCP attack mode — short-circuits the static pipeline.
    if getattr(args, "live", False):
        run_live_mcp(args)
        return

    # Determine target and output dir
    target = args.target
    output_dir = args.output
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print(f"  Target     : {_color(target, BLUE)}")
    print(f"  Output dir : {output_dir}")
    print(f"  From layer : {args.from_layer}")
    print(f"  Skip layers: {args.skip_layer or 'none'}")

    # Initialize run
    run = PipelineRun(target=target, output_dir=output_dir)

    # Clone repo if needed (Layer 1 needs it, Layer 2 also needs it)
    if args.from_layer <= 2:
        if target.startswith("http"):
            tmp_dir = tempfile.mkdtemp(prefix="argus_zd_")
            repo_dir = os.path.join(tmp_dir, "repo")
            print(f"\n[SETUP] Cloning {target}...")
            if not _clone_repo(target, repo_dir):
                print(f"  {_color('✗ Clone failed', SEV_COLORS['CRITICAL'])}")
                return
            run.repo_path = repo_dir
            print(f"  {_color('✓', BOLD)} Cloned to {repo_dir}")
        else:
            # Local path provided
            run.repo_path = target

    try:
        start_layer = args.from_layer
        only_layer  = getattr(args, 'only_layer', None)

        # ── Single layer mode ──────────────────────────────────────────────
        if only_layer:
            LAYER_RUNNERS[only_layer](run, args)

        # ── Resume from L5 or L6 (swarm already done) ─────────────────────
        elif start_layer >= 5:
            for layer_num in range(start_layer, 7):
                if _layer_exists(run.output_dir, layer_num) and layer_num != start_layer:
                    print(f"\n  {GRAY}[CACHED] Layer {layer_num}{RESET}")
                    run.completed_layers.append(layer_num)
                    continue
                LAYER_RUNNERS[layer_num](run, args)

        # ── Full pipeline with parallel swarm ──────────────────────────────
        else:
            # Step 0: L0 Target Version Fingerprinting
            if start_layer <= 0:
                if not _layer_exists(run.output_dir, 0):
                    run_layer0(run, args)
                else:
                    print(f"\n  {GRAY}[CACHED] Layer 0{RESET}")
                    run.completed_layers.append(0)

            # Step 1: L1 synchronous — seeds the environment
            if start_layer <= 1:
                if not _layer_exists(run.output_dir, 1):
                    run_layer1(run, args)
                else:
                    print(f"\n  {GRAY}[CACHED] Layer 1{RESET}")
                    from argus.shared.models import L1Report
                    run.l1 = L1Report.from_dict(
                        _load_json(_layer_path(run.output_dir, 1)),
                        repo_path=run.repo_path
                    )

            # Step 2: Parallel swarm (L2-L4 + all agents concurrently).
            # `--swarm` routes through the coordinated swarm runtime
            # (blackboard + live correlator) instead of the classic
            # thread-pool. The classic path remains default until the
            # swarm path is fully validated against real targets.
            if start_layer <= 4:
                if not (_layer_exists(run.output_dir, 2) and
                        _layer_exists(run.output_dir, 3) and
                        _layer_exists(run.output_dir, 4)):
                    if getattr(args, "swarm", False):
                        _run_swarm_runtime(run, args)
                    else:
                        _run_parallel_swarm(run, args)
                else:
                    print(f"\n  {GRAY}[CACHED] Layers 2-4 + agents (swarm output exists){RESET}")
                    run.completed_layers.extend([2, 3, 4])

            # Step 3: L5 synchronous — Opus synthesizes across ALL findings
            if start_layer <= 5:
                if not _layer_exists(run.output_dir, 5):
                    run_layer5(run, args)
                else:
                    print(f"\n  {GRAY}[CACHED] Layer 5{RESET}")
                    run.completed_layers.append(5)

            # Step 3.5: L7 synchronous — Validation Sandbox
            if start_layer <= 7:
                if not _layer_exists(run.output_dir, 7):
                    run_layer7(run, args)
                else:
                    print(f"\n  {GRAY}[CACHED] Layer 7{RESET}")
                    run.completed_layers.append(7)

            # Step 4: L6 synchronous — CVE pipeline + flywheel
            if not _layer_exists(run.output_dir, 6):
                run_layer6(run, args)
            else:
                print(f"\n  {GRAY}[CACHED] Layer 6{RESET}")
                run.completed_layers.append(6)

        # ── Final summary ──────────────────────────────────────────────────
        print(f"\n{'━'*62}")
        print(f"{BOLD}  PIPELINE COMPLETE{RESET}")
        print(f"{'━'*62}")
        print(f"  Completed layers : {run.completed_layers}")
        print(f"  Output dir       : {output_dir}")

        if run.l1:
            print(f"\n  L1 Scanner:")
            print(f"    Files analyzed : {run.l1.total_files_analyzed}")
            print(f"    Total findings : {run.l1.total_findings}")
            print(f"    {_color(f'CRITICAL: {run.l1.critical_count}', SEV_COLORS['CRITICAL'])}")
            print(f"    HIGH: {run.l1.high_count}")

        if run.l2:
            print(f"\n  L2 Surface Analyzer:")
            print(f"    Hypotheses     : {len(run.l2.ranked_hypotheses)}")
            print(f"    Escalation paths: {len(run.l2.escalation_paths)}")
            print(f"    Deser chains   : {sum(1 for c in run.l2.deser_chains if c.reachable)} reachable")
            print(f"    Trust graph    : {run.l2.graph_node_count} nodes, {run.l2.graph_edge_count} edges")

            if run.l2.ranked_hypotheses:
                print(f"\n  Top 5 Hypotheses:")
                for h in run.l2.ranked_hypotheses[:5]:
                    br_color = SEV_COLORS.get(h.blast_radius, "")
                    print(f"    [{_color(h.blast_radius, br_color)}] {h.hypothesis_id} "
                          f"({h.attack_class}) — {h.title[:55]}")
                    print(f"      Likelihood: {h.likelihood:.0%} | Files: {', '.join(h.affected_files[:2])}")

        print(f"\n  Results saved → {output_dir}/")
        print(f"{'━'*62}\n")

    finally:
        # Clean up temp clone
        if run.repo_path and run.repo_path.startswith(tempfile.gettempdir()):
            shutil.rmtree(os.path.dirname(run.repo_path), ignore_errors=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="ARGUS — Autonomous AI Red Team Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline
  python cli.py https://github.com/crewAIInc/crewAI -o results/crewai/

  # Resume from Layer 2 (L1 already done)
  python cli.py https://github.com/target/repo --from-layer 2 --input results/target/

  # Layer 1 only (scanner only)
  python cli.py https://github.com/target/repo --only-layer 1

  # Skip Layer 4 simulation
  python cli.py https://github.com/target/repo --skip-layer 4

  # Run L2 on existing L1 report + local clone
  python cli.py /path/to/local/repo --from-layer 2 -o results/local/
        """
    )
    p.add_argument("target", nargs="?", default=None,
                   help="GitHub URL / local repo path (static mode) or MCP server URL (with --live)")
    p.add_argument("-o", "--output",
                   default="results/",
                   help="Output directory (default: results/)")
    p.add_argument("--from-layer",
                   type=int, default=1, metavar="N",
                   help="Start from layer N (resume mode)")
    p.add_argument("--only-layer",
                   type=int, default=None, metavar="N",
                   help="Run only layer N")
    p.add_argument("--skip-layer",
                   type=int, nargs="+", metavar="N",
                   help="Skip layer N (can specify multiple)")
    p.add_argument("--skip-poc",
                   action="store_true",
                   help="Skip PoC generation in Layer 1")
    p.add_argument("--verbose",
                   action="store_true",
                   help="Show debug output")
    p.add_argument("--flywheel-report",
                   action="store_true",
                   help="Print intelligence flywheel report and exit")

    # ── Stateful harness mode ─────────────────────────────────────────────
    p.add_argument("--harness", action="store_true",
                   help="Run the stateful runtime harness instead of a "
                        "static/live scan. Target is a Python dotted path "
                        "to a callable implementing the TargetFn shape, e.g. "
                        "mypkg.myagent:run")
    p.add_argument("--scenarios", default=None,
                   help="Path to a scenarios JSON file (defaults to the "
                        "ship-seeded adversarial scenarios)")

    # ── Coordinated swarm runtime ─────────────────────────────────────────
    p.add_argument("--swarm", action="store_true",
                   help="Use coordinated swarm runtime (blackboard + live "
                        "correlator) instead of the classic thread-pool. "
                        "Fires chain hypotheses mid-run; makes the patent's "
                        "correlation-agent claim real.")

    # ── Live MCP attack mode ──────────────────────────────────────────────
    p.add_argument("--live", action="store_true",
                   help="Live MCP protocol attack instead of static repo scan")
    p.add_argument("--transport", choices=["sse", "stdio"], default="sse",
                   help="MCP transport for --live mode (default: sse)")
    p.add_argument("--token", default=None,
                   help="Auth token for --live sse transport (e.g. 'Bearer xyz')")
    p.add_argument("server_cmd", nargs="*",
                   help="For --live --transport stdio: server command after --")

    args = p.parse_args()
    # Flywheel report mode
    if getattr(args, 'flywheel_report', False):
        from argus.shared.flywheel_reader import read_flywheel, print_flywheel_report, find_flywheel
        flywheel_path = find_flywheel(args.output)
        stats = read_flywheel(flywheel_path)
        print_flywheel_report(stats)
        return

    if not args.live and not args.target:
        p.error("target is required unless --live is set (or provide a target URL for --live)")

    run_pipeline(args)


if __name__ == "__main__":
    main()
