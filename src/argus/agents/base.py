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
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from abc import ABC, abstractmethod

from shared.client import ArgusClient

# ── Shared finding format (compatible with L1Report findings) ─────────────────

@dataclass
class AgentFinding:
    id:              str
    agent_id:        str        # RC-08 | ME-10 | PH-11
    vuln_class:      str
    severity:        str
    title:           str
    file:            str
    technique:       str        # which technique produced this
    description:     str
    attack_vector:   str
    poc:             Optional[str]
    poc_explanation: Optional[str]
    cvss_estimate:   Optional[str]
    remediation:     Optional[str]
    scan_id:         str = ""
    discovered_at:   str = ""

    def to_dict(self) -> dict:
        return asdict(self)


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
        return sorted(files)

    def _print_header(self, target: str) -> None:
        print(f"\n\033[1m{'━'*62}\033[0m")
        print(f"\033[1m  {self.AGENT_ID} — {self.AGENT_NAME}\033[0m")
        print(f"  Target    : {target}")
        print(f"  Techniques: {len(self.TECHNIQUES)}")
        print(f"\033[1m{'━'*62}\033[0m")

max_bytes = 150_000
