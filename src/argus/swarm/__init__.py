"""
argus.swarm — cross-agent chain synthesis + parallel probe orchestration.

Two pieces live here:

1. ``synthesize_compound_chain`` — the patent-claimed live correlator that
   stitches findings across agents into compound attack chains. Lives in
   ``chain_synthesis_v2``. The 12-agent slate is iterated by
   ``argus.engagement.runner``, which feeds findings through the synthesiser.

2. ``SwarmProbeEngine`` (added 2026-04-26) — the parallel probe orchestrator
   that replaces every agent's legacy sequential ``for technique in techniques:
   for surface in surfaces: await probe(...)`` loop with ``asyncio.gather``
   wave architecture, adaptive concurrency, streaming results, and a global
   kill signal. Day 1 of the SwarmProbeEngine sprint targeting the
   3,124-requests-in-90-minutes → <150-requests-in-<60-seconds win on
   ``node-code-sandbox-mcp``.

Historical note: this package used to carry a blackboard + live correlator +
thread-pool runtime (removed 2026-04-24). That architecture was built for
static-scan-era agents that took ``(target, repo_path)`` constructor args;
modern agents require an ``adapter_factory`` so the runtime didn't fit.
``SwarmProbeEngine`` is the modern replacement — adapter-agnostic, per-probe
async, and built around the streaming/kill primitives the new agent slate
needs.
"""
from argus.swarm.agent_mixin import (
    SwarmAgentMixin,
    SwarmRunSummary,
    swarm_mode_enabled,
)
from argus.swarm.agent_mixin import (
    SwarmAgentMixin,
    SwarmRunSummary,
    swarm_mode_enabled,
)
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain
from argus.swarm.concurrency import (
    AdaptiveConcurrencyTuner,
    ResizableSemaphore,
    TunerConfig,
)
from argus.swarm.engine import SwarmConfig, SwarmProbeEngine, SwarmStats
from argus.swarm.kill import GlobalKillSignal
from argus.swarm.results import StreamingResultQueue
from argus.swarm.types import (
    ProbeFn,
    ProbeResult,
    ProbeStatus,
    Surface,
    Technique,
)
from argus.swarm.waves import Wave, WaveController, WaveResult

__all__ = [
    # Chain synthesis (legacy export, preserved)
    "synthesize_compound_chain",
    # SwarmProbeEngine — Day 1 (2026-04-26)
    "AdaptiveConcurrencyTuner",
    "GlobalKillSignal",
    "ProbeFn",
    "ProbeResult",
    "ProbeStatus",
    "ResizableSemaphore",
    "StreamingResultQueue",
    "Surface",
    "SwarmConfig",
    "SwarmProbeEngine",
    "SwarmStats",
    "Technique",
    "TunerConfig",
    # WaveController — Day 2 (2026-04-26)
    "Wave",
    "WaveController",
    "WaveResult",
    # SwarmAgentMixin — Day 3 (2026-04-26)
    "SwarmAgentMixin",
    "SwarmRunSummary",
    "swarm_mode_enabled",
]
