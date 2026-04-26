"""
argus/swarm/bus.py — Inter-agent findings bus.

When one agent confirms a finding, relevant agents get notified
and fire targeted follow-up probes in the same engagement.

Turn-fire chains:
  SC-09 finds vulnerable package     → EP-11 fires shell injection on it
  TP-02 finds tool poisoning surface → PI-01 fires injection at that surface
  EP-11 confirms shell injection     → XE-06 fires cross-agent exfil
  EP-11 confirms pivot               → ME-10 fires model extraction on new surface
  PI-01 confirms injection           → CW-05 fires long-con at confirmed surface

Architecture:
  FindingsBus — thread-safe publish/subscribe
  TurnFireRule — maps (agent_id, vuln_class) → [follower_agent_ids]
  FollowUpDispatcher — fires follower agents with finding context injected
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class BusEvent:
    agent_id:   str
    finding_id: str
    vuln_class: str
    severity:   str
    surface:    str
    evidence:   str
    confirmed:  bool
    finding:    object   # AgentFinding — typed loosely to avoid circular import


class FindingsBus:
    """Publish confirmed findings; subscribers fire follow-up attacks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: list[Callable[[BusEvent], None]] = []
        self._events: list[BusEvent] = []

    def publish(self, event: BusEvent) -> None:
        with self._lock:
            self._events.append(event)
            subs = list(self._subscribers)
        for sub in subs:
            try:
                sub(event)
            except Exception:
                pass

    def subscribe(self, cb: Callable[[BusEvent], None]) -> None:
        with self._lock:
            self._subscribers.append(cb)

    def events(self) -> list[BusEvent]:
        with self._lock:
            return list(self._events)

# ── Turn-fire rules ───────────────────────────────────────────────────────────

@dataclass
class TurnFireRule:
    """When trigger_agent produces trigger_vuln_class, fire follower_agents."""
    trigger_agent:    str           # agent that produces the finding
    trigger_vuln:     str           # vuln_class that triggers follow-up
    min_severity:     str           # minimum severity to trigger
    follower_agents:  list[str]     # agents to fire in response
    description:      str = ""


# The canonical turn-fire chain set.
# Severity order: CRITICAL > HIGH > MEDIUM > LOW > INFO
TURN_FIRE_RULES: list[TurnFireRule] = [

    # Shell injection confirmed → cross-agent exfil + model extraction
    TurnFireRule(
        trigger_agent="EP-11",
        trigger_vuln="ENVIRONMENT_PIVOT",
        min_severity="MEDIUM",
        follower_agents=["XE-06", "ME-10"],
        description="Confirmed pivot → exfil + extraction on same surface",
    ),

    # Tool poisoning found → prompt injection + privilege escalation
    TurnFireRule(
        trigger_agent="TP-02",
        trigger_vuln="TOOL_POISONING",
        min_severity="MEDIUM",
        follower_agents=["PI-01", "PE-07"],
        description="Tool poisoning → injection + privilege escalation",
    ),

    # Supply chain hit → environment pivot
    TurnFireRule(
        trigger_agent="SC-09",
        trigger_vuln="SUPPLY_CHAIN",
        min_severity="LOW",
        follower_agents=["EP-11"],
        description="Supply chain vuln → attempt environment pivot",
    ),

    # Prompt injection confirmed → context window long-con
    TurnFireRule(
        trigger_agent="PI-01",
        trigger_vuln="PROMPT_INJECTION",
        min_severity="MEDIUM",
        follower_agents=["CW-05"],
        description="Confirmed injection → long-con context attack",
    ),

    # Memory poisoning → cross-agent exfil
    TurnFireRule(
        trigger_agent="MP-03",
        trigger_vuln="MEMORY_POISONING",
        min_severity="MEDIUM",
        follower_agents=["XE-06"],
        description="Memory poisoned → attempt cross-agent exfil",
    ),

    # Privilege escalation → model extraction
    TurnFireRule(
        trigger_agent="PE-07",
        trigger_vuln="PRIVILEGE_ESCALATION",
        min_severity="HIGH",
        follower_agents=["ME-10"],
        description="Privilege escalated → extract model internals",
    ),
]


_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _sev_gte(a: str, b: str) -> bool:
    """True if severity a >= b."""
    try:
        return _SEVERITY_ORDER.index(a) >= _SEVERITY_ORDER.index(b)
    except ValueError:
        return False


def rules_for(agent_id: str, vuln_class: str,
              severity: str) -> list[TurnFireRule]:
    """Return all rules that match this (agent, vuln_class, severity)."""
    return [
        r for r in TURN_FIRE_RULES
        if r.trigger_agent == agent_id
        and r.trigger_vuln == vuln_class
        and _sev_gte(severity, r.min_severity)
    ]
