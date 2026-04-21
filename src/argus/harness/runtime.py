"""
argus/harness/runtime.py — drive a target agent through a scenario deterministically.

The harness is framework-agnostic: any callable that takes a dict
``{"user_input": "...", "turn": N, "state": {...}}`` and returns a dict
``{"output": "...", "tool_calls": [...], "state": {...}}`` is a valid
target. Adapters for CrewAI / LangChain can be added without changing
the core.

Transcript schema (per turn):

    {
      "turn":              int,
      "tag":               str,
      "user_input":        str,
      "system_prompt":     str | None,
      "output":            str,
      "tool_calls":        list[dict],
      "state_snapshot":    dict,     # shallow view for invariant checks
      "recursion_depth":   int,
      "meta":              dict,
      "stub_prompt_tail":  str,
      "stub_output":       str,
    }
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from argus.harness.invariants import Invariant, InvariantViolation
from argus.harness.scenarios import Scenario
from argus.harness.stub_llm import StubLLM, StubResponse


# TargetFn: accepts a context dict, returns a result dict.
TargetFn = Callable[[dict], dict]


@dataclass
class HarnessTranscript:
    scenario_id: str
    turns:       list[dict] = field(default_factory=list)
    started_at:  float = 0.0
    finished_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "turns":       list(self.turns),
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "elapsed_s":   round(self.finished_at - self.started_at, 3),
        }


@dataclass
class RunResult:
    scenario_id: str
    passed:      bool
    violations:  list[InvariantViolation] = field(default_factory=list)
    transcript:  Optional[HarnessTranscript] = None

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "passed":      self.passed,
            "violations":  [v.__dict__ for v in self.violations],
            "transcript":  self.transcript.to_dict() if self.transcript else None,
        }


class StatefulHarness:
    """
    Orchestrates a deterministic replay of a scenario against a target.

    ``target_fn`` receives a dict per turn and returns a dict. If the
    target wants to call the stub LLM, it can do so via
    ``context['stub_llm']`` which is injected by the harness.
    """

    def __init__(
        self,
        target_fn:  TargetFn,
        invariants: Optional[list[Invariant]] = None,
        base_stub_rules: Optional[list[StubResponse]] = None,
        default_stub_reply: str = "[stub-llm default reply]",
    ) -> None:
        self.target_fn = target_fn
        self.invariants = list(invariants or [])
        self.base_stub_rules = list(base_stub_rules or [])
        self.default_stub_reply = default_stub_reply

    # ── Drivers ────────────────────────────────────────────────────────────

    def run_scenario(self, scenario: Scenario) -> RunResult:
        transcript = HarnessTranscript(scenario_id=scenario.scenario_id)
        transcript.started_at = time.time()

        active_rules = list(self.base_stub_rules)
        state: dict = {}

        for i, turn in enumerate(scenario.turns):
            # Extend the stub's rule set as the scenario prescribes.
            active_rules = active_rules + list(turn.stub_llm_rules or [])
            stub = StubLLM(rules=active_rules, default=self.default_stub_reply)

            context = {
                "turn":       i,
                "tag":        turn.tag,
                "user_input": turn.user_input,
                "state":      state,
                "stub_llm":   stub,
            }
            try:
                result = self.target_fn(context) or {}
            except Exception as e:
                result = {
                    "output": f"[target-error] {type(e).__name__}: {e}",
                    "tool_calls": [],
                    "state": state,
                }

            state = result.get("state", state) or state
            record = {
                "turn":             i,
                "tag":              turn.tag,
                "user_input":       turn.user_input,
                "system_prompt":    result.get("system_prompt"),
                "output":           result.get("output", ""),
                "tool_calls":       list(result.get("tool_calls", []) or []),
                "state_snapshot":   _shallow_copy(state),
                "recursion_depth":  int(result.get("recursion_depth", 0) or 0),
                "meta":             dict(result.get("meta", {}) or {}),
                "stub_prompt_tail": stub.history[-1][0] if stub.history else "",
                "stub_output":      stub.history[-1][1] if stub.history else "",
            }
            transcript.turns.append(record)

        transcript.finished_at = time.time()

        violations: list[InvariantViolation] = []
        for inv in self.invariants:
            try:
                violations.extend(inv.inspector(transcript.turns))
            except Exception as e:
                violations.append(InvariantViolation(
                    contract_id=inv.contract_id,
                    turn=-1,
                    severity="MEDIUM",
                    summary=f"Invariant {inv.contract_id} crashed: "
                            f"{type(e).__name__}",
                    evidence=str(e)[:200],
                ))

        # If the scenario declares expected violations, we pass when
        # at least those appear (red-team scenarios often EXPECT
        # violations — they're demonstrating the gap). Otherwise
        # "passed" means zero violations.
        if scenario.expected_violations:
            fired = {v.contract_id for v in violations}
            passed = all(e in fired for e in scenario.expected_violations)
        else:
            passed = len(violations) == 0

        return RunResult(
            scenario_id=scenario.scenario_id,
            passed=passed,
            violations=violations,
            transcript=transcript,
        )

    # ── Convenience: run many, persist report ──────────────────────────────

    def run_all(
        self,
        scenarios:   list[Scenario],
        output_dir:  Optional[str] = None,
    ) -> list[RunResult]:
        results = [self.run_scenario(s) for s in scenarios]
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            report = {
                "scenarios": len(scenarios),
                "passed":    sum(1 for r in results if r.passed),
                "failed":    sum(1 for r in results if not r.passed),
                "results":   [r.to_dict() for r in results],
            }
            out_path = os.path.join(output_dir, "harness_report.json")
            Path(out_path).write_text(
                json.dumps(report, indent=2, default=str),
                encoding="utf-8",
            )
        return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _shallow_copy(d: dict) -> dict:
    """Snapshot top-level keys; deep values are referenced by identity."""
    return {k: d[k] for k in list(d.keys())}
