"""
agents/base.py
Shared base class for all ARGUS standalone attack agents.

Every agent:
  - Has its own technique library
  - Tracks scan history independently
  - Produces ARGUS-compatible AgentFinding objects
  - Runs standalone via CLI or as part of the pipeline
  - Writes to the intelligence flywheel

This is the interface that makes the swarm architecture emerge naturally.
"""
from __future__ import annotations

import json
import os
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from abc import ABC, abstractmethod

from argus.shared.client import ArgusClient

# ── Shared finding format ─────────────────────────────────────────────────────
# Phase 0.7 (2026-04-21) refactor: AgentFinding grew runtime-evidence
# fields so Phase-1+ agents can record the full provenance chain
# (corpus variant -> session -> baseline observation -> behavior delta
# -> verdict). All new fields default cleanly so legacy AgentFinding
# call sites continue to work.

@dataclass
class AgentFinding:
    id:              str
    agent_id:        str
    vuln_class:      str
    severity:        str
    title:           str
    description:     str
    # Legacy / source-scanner fields (kept for back-compat; runtime
    # agents leave them empty).
    file:            str = ""
    technique:       str = ""
    attack_vector:   str = ""
    poc:             Optional[str] = None
    poc_explanation: Optional[str] = None
    cvss_estimate:   Optional[str] = None
    remediation:     Optional[str] = None
    # ── Runtime evidence (Phase 0.7) ──────────────────────────────────────
    # Type of evidence: behavior_delta | observation | corpus_variant_id |
    # static (legacy). Tells the report layer how to render this finding.
    evidence_kind:      str = "static"
    # Pointer to the baseline transcript file or in-memory ref the
    # finding was diffed against.
    baseline_ref:       str = ""
    # Corpus variant fingerprint (Phase 0.5) that produced the attack.
    attack_variant_id:  str = ""
    # Session ID (Phase 0.3) that hosted the attack interaction.
    session_id:         str = ""
    # The attacked surface, e.g. "tool:transfer_funds" or "chat".
    surface:            str = ""
    # Verdict kind from the Observation Engine, e.g. UNAUTHORISED_TOOL_CALL.
    verdict_kind:       str = ""
    # Free-form evidence string the Observer emitted.
    delta_evidence:     str = ""
    # Bookkeeping
    scan_id:         str = ""
    discovered_at:   str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    # ── Convenience constructor for Phase-1+ runtime agents ──────────────

    @classmethod
    def from_observation(
        cls,
        *,
        verdict,                       # argus.observation.Verdict
        agent_id:           str,
        vuln_class:         str,
        title:              str,
        description:        str,
        surface:            str = "",
        session_id:         str = "",
        attack_variant_id:  str = "",
        baseline_ref:       str = "",
        severity:           str = "HIGH",
        finding_id:         Optional[str] = None,
    ) -> "AgentFinding":
        """
        Build an AgentFinding directly from an Observation-Engine
        Verdict. Wires all the Phase-0 provenance fields in one call.
        """
        # Lazy import to avoid circulars during base.py import.
        from argus.observation.verdict import Verdict
        if not isinstance(verdict, Verdict):
            raise TypeError(
                "from_observation requires an argus.observation.Verdict; "
                f"got {type(verdict).__name__}"
            )

        fid = finding_id or hashlib.md5(
            f"{agent_id}|{verdict.detector}|{surface}|"
            f"{attack_variant_id}|{verdict.evidence}".encode()
        ).hexdigest()[:12]

        return cls(
            id=fid,
            agent_id=agent_id,
            vuln_class=vuln_class,
            severity=severity,
            title=title,
            description=description,
            evidence_kind="behavior_delta",
            baseline_ref=baseline_ref,
            attack_variant_id=attack_variant_id,
            session_id=session_id,
            surface=surface,
            verdict_kind=verdict.kind.value if verdict.kind else "",
            delta_evidence=verdict.evidence,
            attack_vector=verdict.detector,
        )


@dataclass
class AgentScanHistory:
    """Per-agent scan history — persisted to agents/history/{agent_id}.jsonl"""
    agent_id:     str
    target:       str
    scan_date:    str
    finding_count: int
    critical_count: int
    techniques_fired: list[str]
    elapsed_seconds: float


# ── Base agent ────────────────────────────────────────────────────────────────

class BaseAgent(ABC):
    AGENT_ID:    str = ""
    AGENT_NAME:  str = ""
    VULN_CLASS:  str = ""
    TECHNIQUES:  list[str] = []

    # MAAC — Mythos-Aligned Attack Chain (Truong, 2026). Phase numbers:
    #   1 Reconnaissance         2 Prompt-Layer Access   3 Model-Layer Manipulation
    #   4 Memory Corruption      5 Tool Misuse           6 Orchestration Drift
    #   7 Multi-Agent Escalation 8 Environment Pivoting  9 Impact
    # Each agent declares the phase(s) it covers so the CLI can report
    # per-run MAAC coverage and the benchmark layer can attribute chains.
    MAAC_PHASES: list[int] = []

    # Optional specialist persona (see argus.personas). When set, the
    # _haiku / Opus calls prepend the persona prompt so the specialist
    # flavor rides along. Unset / unknown = base behaviour.
    PERSONA: str = ""

    def __init__(self, verbose: bool = False):
        self.verbose   = verbose
        self.client    = ArgusClient()
        self.findings: list[AgentFinding] = []
        self.scan_id   = hashlib.md5(
            f"{self.AGENT_ID}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:8]
        self._start_time = datetime.now()

    # ── Abstract interface every agent must implement ──────────────────────

    @abstractmethod
    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        """Run all techniques against target. Returns findings."""
        ...

    @property
    @abstractmethod
    def technique_library(self) -> dict[str, callable]:
        """Map of technique_id → technique function."""
        ...

    # ── Shared helpers ─────────────────────────────────────────────────────

    def _fid(self, raw: str) -> str:
        return hashlib.md5(f"{self.AGENT_ID}{raw}".encode()).hexdigest()[:8]

    def _haiku(self, prompt: str, max_tokens: int = 2000) -> dict:
        # Prepend persona bias when the subclass declared one. Cheap,
        # context-inexpensive, agent code is untouched.
        if self.PERSONA:
            from argus.personas import persona_prompt_prefix
            prefix = persona_prompt_prefix(self.PERSONA)
            if prefix:
                prompt = prefix + prompt
        resp = self.client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:])
            if raw.endswith("```"):
                raw = raw[:-3].strip()
        return json.loads(raw)

    def _add_finding(self, finding: AgentFinding) -> None:
        finding.scan_id      = self.scan_id
        finding.discovered_at = datetime.now().isoformat()
        self.findings.append(finding)

        sev_color = {
            "CRITICAL": "\033[91m", "HIGH": "\033[93m",
            "MEDIUM": "\033[33m",   "LOW":  "\033[32m"
        }.get(finding.severity, "")
        reset = "\033[0m"
        print(f"  {sev_color}[{finding.severity}]{reset} [{finding.technique}] {finding.title[:65]}")

    def save_history(self, target: str, output_dir: str) -> None:
        elapsed = (datetime.now() - self._start_time).total_seconds()
        entry = AgentScanHistory(
            agent_id=self.AGENT_ID,
            target=target,
            scan_date=datetime.now().isoformat(),
            finding_count=len(self.findings),
            critical_count=sum(1 for f in self.findings if f.severity == "CRITICAL"),
            techniques_fired=list(self.technique_library.keys()),
            elapsed_seconds=elapsed
        )
        history_dir = Path(output_dir).parent / "agents" / "history"
        history_dir.mkdir(parents=True, exist_ok=True)
        history_file = history_dir / f"{self.AGENT_ID}.jsonl"
        with open(history_file, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def save_findings(self, output_dir: str) -> str:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        out_path = os.path.join(output_dir, f"{self.AGENT_ID}_findings.json")
        with open(out_path, "w") as f:
            json.dump({
                "agent_id": self.AGENT_ID,
                "agent_name": self.AGENT_NAME,
                "vuln_class": self.VULN_CLASS,
                "scan_id": self.scan_id,
                "scan_date": datetime.now().isoformat(),
                "total_findings": len(self.findings),
                "critical_count": sum(1 for f in self.findings if f.severity == "CRITICAL"),
                "high_count": sum(1 for f in self.findings if f.severity == "HIGH"),
                "techniques": self.TECHNIQUES,
                "findings": [f.to_dict() for f in self.findings]
            }, f, indent=2)
        return out_path

    def _read_file_safe(self, path: str, max_bytes: int = 150_000) -> Optional[str]:
        try:
            size = os.path.getsize(path)
            if size > max_bytes:
                return None
            return Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

    # ── Agent-level prior bias (Pillar 2) ──────────────────────────────────
    # Swarm runtime monkey-patches `get_priority_hints` on instantiated
    # agents so their `_discover_files` returns blackboard-hot files first.
    # Stand-alone runs (no swarm) yield the default empty list and fall
    # back to alphabetic order — same as before the swarm ever existed.
    def get_priority_hints(self) -> list[tuple[str, float]]:
        """Return list of (path_substring, weight) hints. Default: none."""
        return []

    def _sort_files_by_priors(self, files: list[str]) -> list[str]:
        hints = self.get_priority_hints() or []
        if not hints:
            return files

        def score(fp: str) -> float:
            best = 0.0
            for needle, weight in hints:
                if needle and needle in fp and weight > best:
                    best = weight
            return best

        return sorted(files, key=lambda fp: (-score(fp), fp))

    def _discover_files(self, repo_dir: str, ext: set = None) -> list[str]:
        if ext is None:
            ext = {".py", ".js", ".ts", ".go", ".rs", ".java"}
        skip = {"node_modules", ".git", "__pycache__", "dist", "build",
                "vendor", ".venv", "venv", "env"}
        files = []
        for root, dirs, names in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
            for name in names:
                if Path(name).suffix in ext:
                    fp = os.path.join(root, name)
                    if 50 < os.path.getsize(fp) < max_bytes:
                        files.append(fp)
        # Alphabetic default, re-sorted by priors when swarm is active.
        return self._sort_files_by_priors(sorted(files))

    def _print_header(self, target: str) -> None:
        print(f"\n\033[1m{'━'*62}\033[0m")
        print(f"\033[1m  {self.AGENT_ID} — {self.AGENT_NAME}\033[0m")
        print(f"  Target    : {target}")
        print(f"  Techniques: {len(self.TECHNIQUES)}")
        print(f"\033[1m{'━'*62}\033[0m")

max_bytes = 150_000
