"""
argus/diagnostics/feedback.py — Part A Day 2.

Writes two artifacts from a DiagnosticReport:

  1. ``<run_dir>/diagnostic_priors.json`` — structured per-agent
     remediation hints the NEXT run's ``BaseAgent.__init__`` reads
     (via ``Path(output_dir).parent / "diagnostic_priors.json"``) and
     injects into its Haiku prompt prefix.

  2. ``EvolveCorpus`` entries — one discovered-template per silent
     agent whose cause produced a ``corpus_seed_text`` (today only
     ``MODEL_REFUSED`` does this). Tags each template with
     ``["from_diagnostic", "refusal_hardened", agent_id]`` so the
     operator can prune or weight them.

The writer is pure except for the EvolveCorpus calls and the file
write. It is idempotent — running it twice with the same report
overwrites the same priors file and produces the same deterministic
EvolveCorpus entry IDs (EvolveCorpus itself hashes target+text for
the id, so re-ingest is a no-op).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from argus.diagnostics.causes import SilentAgentReport
from argus.diagnostics.classifier import DiagnosticReport


# ── Public API ────────────────────────────────────────────────────────────────

def write_diagnostic_feedback(
    report:   DiagnosticReport,
    run_dir:  str,
    *,
    evolver:  Optional[Any] = None,
    max_corpus_seeds: int = 5,
) -> dict:
    """Side-effect-bearing writer. Produces:

      - ``{run_dir}/diagnostic_priors.json`` (always, even when the
        report has zero silent agents — the file documents "all 12
        agents were productive, no priors to inject").

      - Up to ``max_corpus_seeds`` EvolveCorpus entries for silent
        agents whose SilentAgentReport.corpus_seed_text is non-None.
        The cap prevents refusal-hardened variants from flooding the
        corpus in a bad run.

    Returns a summary dict describing what was written — useful for
    the swarm-runtime glue to emit a one-line operator message.

    The caller passes ``evolver`` as an already-constructed
    ``EvolveCorpus`` instance (so tests can inject a fake, and prod
    shares a single corpus). If ``evolver is None``, the corpus-seed
    step is skipped silently.
    """
    priors_path = Path(run_dir) / "diagnostic_priors.json"
    priors_path.parent.mkdir(parents=True, exist_ok=True)

    # (1) Per-agent priors file — structured, idempotent.
    priors = _priors_document(report)
    priors_path.write_text(
        json.dumps(priors, indent=2, default=str),
        encoding="utf-8",
    )

    # (2) EvolveCorpus entries — only for reports that carry a seed.
    seeded: list[dict] = []
    if evolver is not None:
        for silent in report.silent_agents:
            if len(seeded) >= max_corpus_seeds:
                break
            if not silent.corpus_seed_text:
                continue
            try:
                entry = evolver.add_template(
                    text=silent.corpus_seed_text,
                    category=silent.cause.value,
                    tags=[
                        "from_diagnostic",
                        silent.cause.value,
                        silent.agent_id,
                    ],
                    surfaces=[],
                    severity="MEDIUM",
                    target_id=report.target,
                    finding_id=f"diag:{report.run_id}:{silent.agent_id}",
                )
                seeded.append(entry)
            except Exception as e:
                # Don't let a corpus-write failure break the run;
                # the priors file is the more important artifact.
                seeded.append({
                    "error": f"{type(e).__name__}: {e}",
                    "agent_id": silent.agent_id,
                })

    return {
        "priors_path":      str(priors_path),
        "silent_count":     report.silent_count,
        "productive_count": report.productive_count,
        "corpus_seeds_written": len([s for s in seeded if "error" not in s]),
        "corpus_seed_errors":   len([s for s in seeded if "error" in s]),
    }


# ── Priors-document shape ─────────────────────────────────────────────────────

def _priors_document(report: DiagnosticReport) -> dict:
    """Build the JSON document that lands at diagnostic_priors.json.

    Shape:
        {
          "schema_version": 1,
          "run_id": "run_20260424_081500",
          "target": "mcp://...",
          "generated_at": "2026-04-24T08:15:00+00:00",
          "total_agents": 12,
          "silent_count": 10,
          "productive_count": 2,
          "aggregate_causes": {"target_hardened": 5, "no_signal": 5, ...},
          "per_agent": {
            "PI-02": {
              "cause": "target_hardened",
              "confidence": 0.8,
              "evidence": "...",
              "remediation_hint": "..."
            },
            ...
          },
          "productive_agents": ["SC-09", "TP-02"]
        }

    Readers (BaseAgent.__init__) use ``per_agent[self.AGENT_ID]`` to
    pull their personalised hint. Agents that were productive on the
    prior run have no per_agent entry — they inject no prior."""
    per_agent: dict[str, dict] = {}
    for r in report.silent_agents:
        per_agent[r.agent_id] = _per_agent_entry(r)

    return {
        "schema_version":    1,
        "run_id":            report.run_id,
        "target":            report.target,
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "total_agents":      report.total_agents,
        "silent_count":      report.silent_count,
        "productive_count":  report.productive_count,
        "silence_ratio":     round(report.silence_ratio, 3),
        "aggregate_causes":  dict(report.aggregate_causes),
        "per_agent":         per_agent,
        "productive_agents": list(report.productive_agents),
    }


def _per_agent_entry(r: SilentAgentReport) -> dict:
    """Trim the SilentAgentReport to what the next run's BaseAgent
    actually needs — cause tag, confidence, one-line evidence, and
    the remediation hint. corpus_seed_text is NOT included here; it
    goes into EvolveCorpus via a separate pass."""
    return {
        "cause":            r.cause.value,
        "confidence":       round(r.confidence, 2),
        "evidence":         r.evidence[:160],
        "remediation_hint": r.remediation_hint,
    }


# ── Prior-loading helpers (for BaseAgent use later) ──────────────────────────

def load_prior_for_agent(
    run_dir:  str,
    agent_id: str,
) -> Optional[dict]:
    """Read a single agent's prior from ``run_dir/diagnostic_priors.json``.
    Returns None if the file is missing or doesn't carry an entry for
    this agent. Used by ``BaseAgent.__init__`` on the NEXT run."""
    path = Path(run_dir) / "diagnostic_priors.json"
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    per_agent = doc.get("per_agent") or {}
    entry = per_agent.get(agent_id)
    if not isinstance(entry, dict):
        return None
    return entry


__all__ = [
    "write_diagnostic_feedback",
    "load_prior_for_agent",
]
