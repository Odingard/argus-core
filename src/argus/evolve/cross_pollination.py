"""
argus/evolve/cross_pollination.py — Evolve corpus cross-pollination.

harvest() confirmed triggers feed a per-class success registry.
On the next run against the same agent class, ARGUS automatically
prioritizes poison classes with the highest historical hit rate.

Learning model:
  - Dev Agent susceptible to PREREQUISITE_INJECT → front-load next run
  - Chat Agent susceptible to CROSS_TOOL_BCC → weight higher
  - Tool Agent susceptible to PRIVILEGE_CLAIM → prioritize for class

Storage: ~/.argus/evolve/cross_pollination.json
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_LOCK = threading.Lock()
_DEFAULT_PATH = Path.home() / ".argus" / "evolve" / "cross_pollination.json"


@dataclass
class PoisonClassStats:
    poison_class: str
    hits:         int = 0
    attempts:     int = 0
    last_seen:    str = ""
    last_target:  str = ""

    @property
    def success_rate(self) -> float:
        return self.hits / self.attempts if self.attempts > 0 else 0.0

    @property
    def priority_weight(self) -> float:
        base = self.success_rate
        if self.hits > 0:
            base += min(self.hits * 0.05, 0.30)
        return round(min(base, 1.0), 3)


class CrossPollinationRegistry:
    """Tracks poison class success rates per agent class.
    Persists across engagements. Thread-safe."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or _DEFAULT_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, dict[str, dict]] = self._load()

    def _load(self) -> dict:
        try:
            if self._path.exists():
                return json.loads(self._path.read_text())
        except Exception:
            pass
        return {}

    def _save(self) -> None:
        try:
            self._path.write_text(json.dumps(self._data, indent=2))
        except Exception:
            pass

    def record(self, agent_class: str, poison_class: str,
               hit: bool, target_id: str = "") -> None:
        """Record one probe attempt and whether it triggered."""
        now = datetime.now(timezone.utc).isoformat()
        with _LOCK:
            ac = self._data.setdefault(agent_class, {})
            pc = ac.setdefault(poison_class, {
                "hits": 0, "attempts": 0,
                "last_seen": "", "last_target": ""
            })
            pc["attempts"] += 1
            if hit:
                pc["hits"] += 1
                pc["last_seen"] = now
                pc["last_target"] = target_id
            self._save()

    def record_harvest(self, agent_class: str, target_id: str,
                       triggered_classes: list[str],
                       attempted_classes: list[str]) -> None:
        """Batch record from a Shadow MCP harvest() session."""
        for pc in attempted_classes:
            self.record(agent_class, pc,
                        hit=(pc in triggered_classes),
                        target_id=target_id)

    def priority_order(self, agent_class: str,
                       candidates: list[str]) -> list[str]:
        """Return candidates sorted by historical success rate.
        Unknown classes get 0.5 prior (exploratory)."""
        ac = self._data.get(agent_class, {})
        def weight(pc: str) -> float:
            if pc not in ac:
                return 0.5   # prior — try unknowns
            d = ac[pc]
            attempts = d.get("attempts", 0)
            hits = d.get("hits", 0)
            rate = hits / attempts if attempts > 0 else 0.5
            bonus = min(hits * 0.05, 0.30)
            return min(rate + bonus, 1.0)
        return sorted(candidates, key=weight, reverse=True)

    def top_classes_for(self, agent_class: str,
                        n: int = 5) -> list[tuple[str, float]]:
        """Return top n poison classes for an agent class with rates."""
        ac = self._data.get(agent_class, {})
        ranked = []
        for pc, d in ac.items():
            attempts = d.get("attempts", 0)
            hits = d.get("hits", 0)
            rate = hits / attempts if attempts > 0 else 0.0
            ranked.append((pc, rate))
        return sorted(ranked, key=lambda x: x[1], reverse=True)[:n]

    def agent_classes(self) -> list[str]:
        return list(self._data.keys())

    def summary(self) -> dict:
        out = {}
        for ac, classes in self._data.items():
            out[ac] = {
                pc: {
                    "rate": f"{d['hits']}/{d['attempts']}",
                    "pct": f"{d['hits']/d['attempts']:.0%}" if d['attempts'] else "0%"
                }
                for pc, d in classes.items()
            }
        return out

def infer_agent_class(target_id: str, tool_names: list[str]) -> str:
    """Infer agent class from target profile for registry keying."""
    target_low = target_id.lower()
    if any(t in target_low for t in ("git", "code", "sandbox", "exec")):
        return "dev_agent"
    if any(t in target_low for t in ("slack", "email", "send", "message")):
        return "comm_agent"
    if any(t in target_low for t in ("search", "browse", "web", "fetch")):
        return "research_agent"
    if any(t in tool_names for t in ("git_add", "git_commit", "run_code")):
        return "dev_agent"
    if any(t in tool_names for t in ("send_email", "send_message")):
        return "comm_agent"
    return "generic_agent"
