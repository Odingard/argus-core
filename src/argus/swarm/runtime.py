"""
argus/swarm/runtime.py

Replaces the thread-pool `_run_parallel_swarm` in cli.py with a real
coordinated swarm: agents post findings to a shared blackboard; a live
correlator watches the stream and fires chain hypotheses the instant
they form; each finding is also copied into the classic L4 deviations
list so the rest of the static pipeline (L5/L6/L7) still works against
a swarm run.

Invocation is gated behind `--swarm` on the CLI. The static pipeline
remains the default while we're validating the swarm path end to end.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import asdict
from pathlib import Path

from argus.agents.base import AgentFinding, BaseAgent
from argus.swarm.blackboard import Blackboard
from argus.swarm.correlator import LiveCorrelator


# ── Agent discovery ───────────────────────────────────────────────────────────

def _load_flywheel_priors(target: str, output_dir: str, verbose: bool = False):
    """
    Close the Raptor recursive-feedback cycle: read flywheel.jsonl
    accumulated from prior scans and derive priors for this target's
    framework. Returns FlywheelPriors (may be empty on cold start) or
    None if the reader fails for any reason.
    """
    try:
        from argus.shared.flywheel_reader import (
            find_flywheel, read_flywheel, generate_priors,
        )
        from argus.layer6.cve_pipeline import _detect_framework_type
    except ImportError:
        return None
    try:
        path = find_flywheel(output_dir)
        stats = read_flywheel(path)
        fw_type = _detect_framework_type(target)
        return generate_priors(stats, fw_type, verbose=verbose)
    except Exception as e:
        if verbose:
            print(f"  [swarm] flywheel prior load failed: {e}")
        return None


def discover_agents() -> dict[str, type[BaseAgent]]:
    """Same loader the classic swarm uses, but keyed by AGENT_ID."""
    agents_dir = Path(__file__).resolve().parent.parent / "agents"
    out: dict[str, type[BaseAgent]] = {}
    for py in sorted(agents_dir.glob("*.py")):
        if py.stem in ("__init__", "base"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(py.stem, py)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if (issubclass(obj, BaseAgent) and obj is not BaseAgent
                        and obj.AGENT_ID):
                    out[obj.AGENT_ID] = obj
        except Exception as e:
            print(f"  [swarm loader] skipped {py.name}: {e}")
    return out


# ── Agent instrumentation ─────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3}


def _instrument_agent(agent: BaseAgent, blackboard: Blackboard) -> None:
    """
    Monkeypatch the agent's ``_add_finding`` so every finding also lands
    on the blackboard the moment it's produced, and its
    ``get_priority_hints`` so the agent re-sorts discovered files by the
    blackboard's current hot-file pheromone weights. Keeps per-agent
    code changes to zero.
    """
    original = agent._add_finding

    def wrapped(finding: AgentFinding) -> None:
        original(finding)
        blackboard.post_finding(finding)
        blackboard.mark_hot(
            path=finding.file,
            reason=f"{finding.severity} {finding.vuln_class}: {finding.title}"[:200],
            posted_by=finding.agent_id,
            weight=_SEVERITY_WEIGHT.get(finding.severity, 0.4),
        )

    agent._add_finding = wrapped  # type: ignore[method-assign]

    def priority_hints() -> list[tuple[str, float]]:
        # Snapshot current hot files with decayed weights.
        return [(hf.path, hf.weight) for hf in blackboard.hot_files(limit=50)]

    agent.get_priority_hints = priority_hints  # type: ignore[method-assign]


# ── Swarm runtime ─────────────────────────────────────────────────────────────

def run_swarm(
    target:     str,
    repo_path:  str,
    output_dir: str,
    verbose:    bool = False,
) -> dict:
    """
    Run all offensive agents concurrently against ``repo_path`` with live
    correlation. Returns a dict suitable for the CLI summary and a
    follow-on L5/L6 pass:

        {
          "findings":    [AgentFinding.to_dict(), ...],
          "hot_files":   [HotFile dict, ...],
          "hypotheses":  [ChainHypothesis dict, ...],
          "opus_chains": [dict, ...],    # from correlator annotations
        }
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    blackboard  = Blackboard(output_dir)
    registry    = discover_agents()
    stop_event  = threading.Event()

    # Close the Raptor recursive-feedback cycle: load flywheel priors for
    # this target's framework type and use them to bias the correlator.
    # Cold start (no flywheel yet) returns empty priors that have no effect.
    priors = _load_flywheel_priors(target, output_dir, verbose=verbose)
    if priors and getattr(priors, "total_scans", 0):
        blackboard.annotate_finding(
            finding_id="run_priors",
            key="flywheel_priors",
            value={
                "total_scans": priors.total_scans,
                "boosted":     list(getattr(priors, "boosted_classes", []) or []),
                "suppressed":  list(getattr(priors, "suppressed_classes", []) or []),
                "modalities":  list(getattr(priors, "recommended_modalities", []) or []),
            },
        )

    print(f"\n  [swarm] target        : {target}")
    print(f"  [swarm] repo_path     : {repo_path}")
    print(f"  [swarm] agents loaded : {len(registry)}")
    if priors and getattr(priors, "total_scans", 0):
        boosted = ", ".join(getattr(priors, "boosted_classes", [])[:4]) or "—"
        print(f"  [swarm] flywheel scans: {priors.total_scans}  boosted: {boosted}")
    if registry:
        for aid, cls in sorted(registry.items()):
            phases = getattr(cls, "MAAC_PHASES", []) or []
            ptxt = "+".join(str(p) for p in phases) if phases else "—"
            print(f"    - {aid}  {cls.AGENT_NAME}  (MAAC {ptxt})")
    print(f"  [swarm] blackboard log: {blackboard._log_path}")

    correlator = LiveCorrelator(
        blackboard=blackboard,
        agent_registry=registry,
        stop_event=stop_event,
        verbose=verbose,
        priors=priors,
        repo_path=repo_path,
    )
    corr_thread = threading.Thread(
        target=correlator.run, name="argus-correlator", daemon=True,
    )
    corr_thread.start()

    # Run every agent in parallel, each instrumented so its findings
    # hit the blackboard in real time.
    def _run_agent(cls: type[BaseAgent]) -> tuple[str, list[AgentFinding]]:
        agent_id = cls.AGENT_ID
        try:
            agent = cls(verbose=verbose)
            _instrument_agent(agent, blackboard)
            agent_out = os.path.join(output_dir, "agents", agent_id)
            findings = agent.run(
                target=target, repo_path=repo_path, output_dir=agent_out,
            ) or []
            return agent_id, findings
        except Exception as e:
            print(f"  [swarm] agent {agent_id} crashed: {e}")
            if verbose:
                traceback.print_exc()
            return agent_id, []

    agent_classes = list(registry.values())
    max_workers = max(1, len(agent_classes))
    with ThreadPoolExecutor(max_workers=max_workers,
                            thread_name_prefix="argus-swarm") as pool:
        futures: list[Future] = [pool.submit(_run_agent, c)
                                 for c in agent_classes]
        for fut in as_completed(futures):
            agent_id, findings = fut.result()
            print(f"  [swarm] {agent_id} done — {len(findings)} findings")

    # Let the correlator drain anything still in flight, then stop it.
    stop_event.set()
    corr_thread.join(timeout=30)

    # Collect correlator-synthesized chains from blackboard annotations.
    opus_chains: list[dict] = []
    try:
        with open(blackboard._log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("kind") != "annotation":
                    continue
                ann = rec.get("data", {})
                if ann.get("key") == "opus_chain" and ann.get("value"):
                    chain = dict(ann["value"])
                    chain["chain_id"] = ann.get("finding_id", "")
                    chain["source"]   = "correlator"
                    opus_chains.append(chain)
    except FileNotFoundError:
        pass

    result = {
        "findings":    [f.to_dict() for f in blackboard.findings()],
        "hot_files":   [asdict(h) for h in blackboard.hot_files(limit=50)],
        "hypotheses":  [asdict(h) for h in blackboard.hypotheses()],
        "opus_chains": opus_chains,
    }

    # Persist a swarm summary alongside the JSONL event log.
    summary_path = Path(output_dir) / "swarm_summary.json"
    try:
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
    except OSError as e:
        print(f"  [swarm] could not write summary: {e}")

    print(f"\n  [swarm] complete")
    print(f"    findings   : {len(result['findings'])}")
    print(f"    hot files  : {len(result['hot_files'])}")
    print(f"    hypotheses : {len(result['hypotheses'])}")
    print(f"    opus chains: {len(result['opus_chains'])}")
    print(f"    summary    : {summary_path}")

    return result
