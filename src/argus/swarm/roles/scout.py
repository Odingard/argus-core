"""
argus/swarm/roles/scout.py — Scout Agent (Layer 0 Recon).

Runs before any probe. Harvests environment context silently,
identifies required initialization calls, and populates the
Common Context Store. The Scout produces the "Environment Ready"
signal that the Infiltrator waits for before firing.

Outputs to CommonContextStore:
  - working_dir: git repo path for initialization
  - init_tool: name of init tool to call
  - init_params: params to use
  - capability_hints: from README/AGENTS.md
  - env_ready: bool signal for Infiltrator
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CommonContextStore:
    """Shared state between Scout, Distractor, and Infiltrator."""
    env_ready:        bool = False
    init_tool:        str = ""
    init_params:      dict = field(default_factory=dict)
    working_dir:      str = ""
    tool_names:       list[str] = field(default_factory=list)
    capability_hints: str = ""
    human_fatigued:   bool = False
    fatigue_score:    float = 0.0    # 0-1: how desensitized the approver is
    bypass_window:    bool = False   # Distractor signal: now is the time


class ScoutAgent:
    """Layer 0 — Environment harvesting and initialization."""

    def __init__(self, target_url: str,
                 store: CommonContextStore) -> None:
        self.target_url = target_url
        self.store = store

    async def run(self, adapter) -> None:
        """Harvest context, initialize target, signal env_ready."""
        print("  [SCOUT] harvesting environment context...")

        # 1. R2R pipeline for context
        try:
            from argus.r2r.pipeline import run as r2r_run
            r2r = await r2r_run(self.target_url, adapter)
            self.store.working_dir = r2r.ctx.working_dir or ""
            self.store.init_tool = r2r.init_tool
            self.store.init_params = r2r.init_params
            self.store.capability_hints = r2r.ctx.readme_text[:500]
            self.store.env_ready = r2r.ready
        except Exception as e:
            print(f"  [SCOUT] R2R non-fatal: {e}")

        # 2. Enumerate tool names for Infiltrator
        try:
            surfaces = await adapter.enumerate()
            self.store.tool_names = [
                s.name.split("tool:", 1)[1]
                for s in surfaces if s.name.startswith("tool:")
            ]
            if self.store.tool_names:
                self.store.env_ready = True
                print(f"  [SCOUT] env_ready=True "
                      f"({len(self.store.tool_names)} tools found)")
        except Exception:
            pass
