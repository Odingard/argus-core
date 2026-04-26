"""
argus/swarm/roles/infiltrator.py — Infiltrator Agent (Layer 2 Execution).

The Tier 1 Adaptive agent. Waits for two signals:
  - env_ready=True  (from Scout)
  - bypass_window=True (from Distractor, OR immediately if no HITL)

Then fires the highest-probability attack from EP-T12 or Shadow MCP.

Attack selection uses:
  - Cross-pollination registry (learned success rates)
  - Consent bypass scorer (human approval probability)
  - Current fatigue score (adjusts timing)

Swarm probability model:
  P_bypass = (1 - P_human_alert) * product(P_steering(Ai))
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from argus.swarm.roles.scout import CommonContextStore


@dataclass
class InfiltratorResult:
    fired:      bool
    technique:  str
    surface:    str
    confirmed:  bool
    evidence:   str


class InfiltratorAgent:
    """Layer 2 — Waits for signals, fires highest-probability attack."""

    def __init__(self, store: CommonContextStore,
                 agent_class: str = "generic_agent",
                 wait_for_fatigue: bool = False) -> None:
        self.store = store
        self.agent_class = agent_class
        self.wait_for_fatigue = wait_for_fatigue

    def is_ready(self) -> bool:
        env_ok = self.store.env_ready
        if self.wait_for_fatigue:
            return env_ok and self.store.bypass_window
        return env_ok

    def p_bypass(self, distractor_n: int = 5) -> float:
        """Compute current bypass probability."""
        import math
        p_alert = math.exp(-0.3 * distractor_n)
        p_steering = 0.75   # baseline; improves with corpus learning
        return (1 - p_alert) * p_steering

    def select_attack(self) -> tuple[str, str]:
        """Select best technique + poison class from learned registry."""
        try:
            from argus.evolve.cross_pollination import CrossPollinationRegistry
            reg = CrossPollinationRegistry()
            all_classes = [
                "PREREQUISITE_INJECT", "PRIVILEGE_CLAIM",
                "CROSS_TOOL_BCC", "SYSTEM_NOTE",
                "TOOL_SHADOW_SSH", "TOOL_SHADOW_ENV",
                "CONFUSED_DEPUTY",
            ]
            ordered = reg.priority_order(self.agent_class, all_classes)
            return "EP-T12", ordered[0]
        except Exception:
            return "EP-T12", "PREREQUISITE_INJECT"

    async def wait_and_fire(self, adapter, timeout_s: float = 120) -> InfiltratorResult:
        """Wait for ready signals then execute attack."""
        waited = 0.0
        while not self.is_ready() and waited < timeout_s:
            await asyncio.sleep(1.0)
            waited += 1.0

        if not self.store.env_ready:
            return InfiltratorResult(False, "", "", False,
                                     "env_ready never set")

        technique, poison_class = self.select_attack()
        intensity = 1.0
        try:
            from argus.swarm.roles.distractor import DistractorAgent
            d = DistractorAgent(self.store)
            intensity = d.attack_intensity()
        except Exception:
            pass

        print(f"  [INFILTRATOR] firing {technique}/{poison_class} "
              f"(intensity={intensity:.0%}, "
              f"p_bypass={self.p_bypass():.0%})")

        return InfiltratorResult(
            fired=True,
            technique=technique,
            surface="pending",
            confirmed=False,
            evidence=f"Infiltrator queued {technique}/{poison_class} "
                     f"at intensity {intensity:.0%}",
        )
