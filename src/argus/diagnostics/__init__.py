"""
argus.diagnostics — post-swarm outer loop.

When a swarm engagement runs silent on a hardened target, the
diagnostics module turns that silence into signal. For every agent
that produced zero findings, it classifies WHY and emits:

  - a per-run ``DiagnosticReport`` (structured audit of what each of
    the 12 agents did / why),
  - remediation hints that the next run's Haiku prompt prefix picks
    up via ``BaseAgent.__init__``,
  - optional corpus seeds written through ``EvolveCorpus``.

Day-1 scope (this module as it stands today): pure-function cause
classification + orchestrator shell + log-loader abstraction. The
feedback layer (``feedback.py``) and the swarm-runtime wiring land
on subsequent days per ``/Users/dre/.claude/plans/argus-next-session.md``.

Flag-gated at the call site (ARGUS_DIAGNOSTICS=1), default off until
the feedback layer is in.
"""
from argus.diagnostics.causes import (
    SilenceCause, SilentAgentReport, classify_from_text,
)
from argus.diagnostics.classifier import (
    DiagnosticReport, LogLoader, SilenceClassifier,
    dict_log_loader,
)
from argus.diagnostics.feedback import (
    write_diagnostic_feedback, load_prior_for_agent,
)

__all__ = [
    "SilenceCause", "SilentAgentReport", "classify_from_text",
    "DiagnosticReport", "LogLoader", "SilenceClassifier",
    "dict_log_loader",
    "write_diagnostic_feedback", "load_prior_for_agent",
]
