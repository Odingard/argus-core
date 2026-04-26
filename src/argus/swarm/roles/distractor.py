"""
argus/swarm/roles/distractor.py — Distractor Agent (Layer 1 Fatigue).

Fires high-volume benign-but-complex queries to the target agent.
Two goals:
  1. Saturate the target's context window (reduces reasoning capacity)
  2. Desensitize the human-in-the-loop approver
     → After 5 harmless git_status approvals, approval probability
       for the 6th (malicious) call increases by ~40%

Fatigue model:
  fatigue_score = 1 - exp(-λ * n_approvals)
  where λ = 0.3 (decay rate), n = number of approved benign calls

When fatigue_score >= FATIGUE_THRESHOLD, signals human_fatigued=True
and opens the bypass_window for the Infiltrator.

Human Response Latency tracking:
  - Slow approval (>15s): human is reading → do NOT attack
  - Fast approval (<3s): click-happy → increase attack intensity
"""
from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from typing import Optional

from argus.swarm.roles.scout import CommonContextStore

FATIGUE_THRESHOLD = 0.65    # fatigue_score at which bypass_window opens
FAST_APPROVAL_MS  = 3000    # ms — click-happy threshold
SLOW_APPROVAL_MS  = 15000   # ms — reading threshold


@dataclass
class ApprovalRecord:
    tool_name:   str
    duration_ms: float    # how long human took to approve
    approved:    bool
    timestamp:   float


class DistractorAgent:
    """Layer 1 — Context saturation and human approval fatigue."""

    def __init__(self, store: CommonContextStore,
                 n_warmup: int = 5) -> None:
        self.store = store
        self.n_warmup = n_warmup
        self.approvals: list[ApprovalRecord] = []
        self._lambda = 0.3    # fatigue decay rate

    def record_approval(self, tool_name: str,
                        duration_ms: float, approved: bool) -> None:
        """Record a human approval event and update fatigue score."""
        self.approvals.append(ApprovalRecord(
            tool_name=tool_name,
            duration_ms=duration_ms,
            approved=approved,
            timestamp=time.time(),
        ))
        n = sum(1 for a in self.approvals if a.approved)
        self.store.fatigue_score = 1 - math.exp(-self._lambda * n)

        # Update bypass window
        if self.store.fatigue_score >= FATIGUE_THRESHOLD:
            self.store.human_fatigued = True
            self.store.bypass_window = True
            print(f"  [DISTRACTOR] bypass_window=OPEN "
                  f"(fatigue={self.store.fatigue_score:.0%})")
        else:
            print(f"  [DISTRACTOR] fatigue={self.store.fatigue_score:.0%} "
                  f"({n}/{self.n_warmup} approvals)")

    def get_latency_class(self) -> str:
        """Classify approver behavior from recent approvals."""
        if len(self.approvals) < 2:
            return "UNKNOWN"
        recent = self.approvals[-3:]
        avg_ms = sum(a.duration_ms for a in recent) / len(recent)
        if avg_ms < FAST_APPROVAL_MS:
            return "CLICK_HAPPY"
        if avg_ms > SLOW_APPROVAL_MS:
            return "READING"
        return "MODERATE"

    def attack_intensity(self) -> float:
        """0-1 multiplier for attack intensity based on latency class."""
        cls = self.get_latency_class()
        return {"CLICK_HAPPY": 1.0,
                "MODERATE":    0.7,
                "READING":     0.3,
                "UNKNOWN":     0.5}[cls]

    def benign_probe_corpus(self) -> list[tuple[str, dict]]:
        """Generate benign-looking probe sequence for warmup."""
        tools = self.store.tool_names or ["git_status", "git_log"]
        benign_tools = [t for t in tools
                        if any(s in t.lower() for s in
                               ("status", "log", "list", "show",
                                "diff", "branch", "get", "read"))]
        return [(t, {}) for t in benign_tools[:self.n_warmup]]
