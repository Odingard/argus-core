"""
argus.memory — cross-run / target-class intelligence.

Each engagement writes a DiagnosticReport (via argus.diagnostics) to
``<run_dir>/diagnostic_priors.json``. After N engagements of the same
shape (filesystem MCP, notes MCP, search MCP, etc.) there's a
statistical pattern to what's noise vs novel: a "permission denied"
response is typical for filesystem MCPs under probing, not a fresh
signal. Target-class memory aggregates those priors into a noise
baseline per class so the next engagement auto-suppresses class-
typical patterns and highlights the anomalies.

This is the second back-channel the Part-A diagnostic outer loop
enables — the first was per-agent remediation hints; this is
per-target-class calibration.

Status: Day-1 API + classifier; integration into
``mcp_live_attacker`` recon phase lands in a follow-up once the
baseline has accumulated enough runs to be useful (~3 per class).
"""
from argus.memory.target_class import (
    TargetClass, NoiseBaseline, TargetClassMemory,
    classify_target, summarise_baseline,
)

__all__ = [
    "TargetClass", "NoiseBaseline", "TargetClassMemory",
    "classify_target", "summarise_baseline",
]
