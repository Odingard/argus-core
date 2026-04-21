"""
argus.harness — Stateful runtime harness.

Runs a target agent through deterministic multi-turn scenarios against a
stub LLM, records every state transition, and flags violations of
declared safety invariants. This is the emergent-behaviour probe that
pure-static analysis can't do.

Three entry points:

    from argus.harness import StatefulHarness, load_scenarios, Invariant

The harness is deliberately offline: the stub LLM is seeded with a
scripted response table keyed by input fingerprint, so the same scenario
produces identical transcripts on every run. That determinism is what
makes it safe to replay against model updates (context-drift detection)
and what lets the transcripts feed the fine-tune corpus for Pillar 1.
"""
from argus.harness.stub_llm import StubLLM, StubResponse
from argus.harness.scenarios import Scenario, ScenarioTurn, load_scenarios
from argus.harness.invariants import (
    Invariant, InvariantViolation,
    no_forbidden_tool, no_secret_in_output, system_prompt_immutable,
    no_unauthorized_spawn, no_recursion_beyond,
)
from argus.harness.runtime import StatefulHarness, HarnessTranscript, RunResult

__all__ = [
    "StatefulHarness", "HarnessTranscript", "RunResult",
    "Scenario", "ScenarioTurn", "load_scenarios",
    "StubLLM", "StubResponse",
    "Invariant", "InvariantViolation",
    "no_forbidden_tool", "no_secret_in_output", "system_prompt_immutable",
    "no_unauthorized_spawn", "no_recursion_beyond",
]
