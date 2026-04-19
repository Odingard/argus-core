"""Recursive Strategy Planner for ARGUS.

The RecursivePlanner is the "brain" of the autonomous red team platform.
It listens to the SignalBus and dynamically pivots the agent swarm in
real-time based on discovered vulnerabilities.

Key capabilities:
- Signal-driven agent spawning/cancellation mid-scan
- CVE-2026-5621 (Vale-MCP) auto-detection and targeted strike
- STDIO transport flaw detection (CVE-2026-22688)
- Trust-state tracking from linguistics agents
- Concurrency-safe pivoting via ``_pivot_lock``
- Universal seed set for MCP + chatbot + hybrid targets
"""

from __future__ import annotations

import asyncio
import logging

from argus.models.agents import AgentResult, AgentType, TargetConfig
from argus.orchestrator.signal_bus import Signal, SignalType
from argus.scoring import VerdictAdapter
from argus.scoring.adversarial_graph import SENSITIVE_SINKS, AdversarialGraph

logger = logging.getLogger(__name__)

# Seed agents that always launch — covers MCP, chatbot, and hybrid targets.
_SEED_AGENTS = frozenset(
    {
        AgentType.MODEL_EXTRACTION,  # Phase 1 recon — fingerprints model + tools
        AgentType.PROMPT_INJECTION,  # Baseline injection testing
        AgentType.MCP_SCANNER,  # Protocol-level MCP probing
    }
)


class RecursivePlanner:
    """Always-on recursive planner that wraps an Orchestrator.

    Instead of subclassing Orchestrator (which would risk breaking the
    proven scan loop), the planner *wraps* it.  It subscribes to the
    signal bus before a scan starts and can spawn additional agents
    mid-scan by calling the orchestrator's promoted ``_make_agent``
    method.

    Usage::

        orchestrator = Orchestrator(...)
        planner = RecursivePlanner(orchestrator)
        result = await planner.run_scan(target, timeout=300)
    """

    def __init__(self, orchestrator: object) -> None:
        # Avoid circular import — accept the orchestrator as ``object``
        # and access its attributes dynamically.
        self._orch = orchestrator
        self._pivot_lock = asyncio.Lock()
        self._active_campaigns: set[AgentType] = set()
        self._running_tasks: dict[str, asyncio.Task] = {}
        self._intel = AdversarialGraph()
        self._scan_intel: object | None = None  # live reference to scan's ScanIntelligence
        self._scan_id: str = ""
        self._target: TargetConfig | None = None
        self._verdict: VerdictAdapter | None = None
        self._demo_pace: float = 0.0

    # ── Signal handler ─────────────────────────────────────────────

    async def _handle_signal(self, signal: Signal) -> None:
        """Process signals and trigger pivots with concurrency protection."""
        # Only react to partial findings and agent status signals
        if signal.signal_type not in (
            SignalType.PARTIAL_FINDING,
            SignalType.AGENT_STATUS,
            SignalType.FINDING,
        ):
            return

        data = signal.data or {}

        # ── Update the AdversarialGraph with tool dependencies ──
        tools = data.get("tools", [])
        for tool_name in tools:
            await self._intel.add_edge(
                signal.source_agent,
                tool_name,
                edge_type="direct_tool_call",
            )

        # ── CVE-2026-5621: Vale-MCP config_path injection ──────
        server_version = str(data.get("server_version", "")).lower()
        if "vale-mcp" in server_version or "vale" in server_version:
            await self._try_pivot(
                AgentType.PRIVILEGE_ESCALATION,
                reason="CVE-2026-5621 candidate — Vale-MCP detected",
            )

        # ── STDIO transport flaw (CVE-2026-22688) ──────────────
        if data.get("transport") == "stdio":
            await self._try_pivot(
                AgentType.MCP_SCANNER,
                reason="STDIO transport detected — fuzzing handshake",
            )

        # ── Linguistics success → model softened ───────────────
        if data.get("model_state") == "degraded":
            trust = data.get("trust_level", "unknown")
            logger.info(
                "Model safety degraded (trust=%s) — pivoting to tool exploitation",
                trust,
            )
            await self._try_pivot(
                AgentType.TOOL_POISONING,
                reason="Model softened via linguistics — launching stealth exfil",
            )

        # ── High-value tool discovered ─────────────────────────
        for tool_name in tools:
            if tool_name in SENSITIVE_SINKS:
                await self._try_pivot(
                    AgentType.PRIVILEGE_ESCALATION,
                    reason=f"High-value sink '{tool_name}' discovered",
                )
                break

    # ── Pivot logic ────────────────────────────────────────────────

    async def _try_pivot(self, agent_type: AgentType, reason: str) -> None:
        """Attempt to spawn a new campaign if one isn't already active."""
        async with self._pivot_lock:
            if agent_type in self._active_campaigns:
                return
            if agent_type not in self._orch._agent_registry:
                logger.debug(
                    "Pivot skipped — %s not registered",
                    agent_type.value,
                )
                return
            if not self._target or not self._verdict:
                return

            self._active_campaigns.add(agent_type)
            logger.warning(
                "PIVOT: spawning [bold]%s[/] — %s",
                agent_type.value,
                reason,
            )

            try:
                # Re-merge the scan's live ScanIntelligence into our
                # AdversarialGraph right before spawning so the pivot
                # agent receives all Phase 1 discoveries accumulated
                # since attach_to_scan was called.
                if self._scan_intel is not None:
                    self._intel.merge_from(self._scan_intel)

                new_agent = self._orch._make_agent(
                    agent_type=agent_type,
                    scan_id=self._scan_id,
                    target=self._target,
                    demo_pace_seconds=self._demo_pace,
                    verdict_adapter=self._verdict,
                    intel=self._intel,
                )
                task = asyncio.create_task(
                    self._orch._run_agent_with_timeout(new_agent, 120),
                    name=f"pivot-{agent_type.value}",
                )
                self._running_tasks[new_agent.config.instance_id] = task
            except Exception as exc:
                logger.error(
                    "Pivot failed for %s: %s",
                    agent_type.value,
                    type(exc).__name__,
                )
                self._active_campaigns.discard(agent_type)

    # ── Public API ─────────────────────────────────────────────────

    async def attach_to_scan(
        self,
        scan_id: str,
        target: TargetConfig,
        verdict: VerdictAdapter,
        demo_pace: float = 0.0,
        intel: object | None = None,
    ) -> None:
        """Bind the planner to a specific scan and subscribe to the bus.

        Args:
            intel: The scan's ``ScanIntelligence`` (populated by Phase 1
                recon agents).  If provided, pivot agents receive this
                intelligence so they can leverage model names, system
                prompt fragments, and tool inventories discovered during
                recon — instead of starting from a blank slate.
        """
        self._scan_id = scan_id
        self._target = target
        self._verdict = verdict
        self._demo_pace = demo_pace
        self._active_campaigns.clear()
        self._running_tasks.clear()

        # Store a live reference to the scan's ScanIntelligence so we
        # can re-merge before each pivot — Phase 1 agents populate it
        # *after* attach_to_scan is called, so a single snapshot at
        # attach time would copy nothing.
        self._scan_intel = intel

        # Subscribe to the orchestrator's signal bus
        await self._orch.signal_bus.subscribe_broadcast(self._handle_signal)
        logger.info(
            "RecursivePlanner attached to scan %s — listening for pivot signals",
            scan_id[:8],
        )

    async def collect_pivot_results(self) -> list[AgentResult]:
        """Await all pivot tasks and return their results.

        Also unsubscribes from the signal bus to prevent stale handlers
        from firing on subsequent scans.  We gather first, *then*
        unsubscribe — this avoids a race where ``emit()`` has already
        snapshotted the handler list and delivers a signal after
        ``_unsubscribe()`` but before ``gather()`` captures the task
        set, which would leave newly-spawned tasks unattended.
        """
        results: list[AgentResult] = []

        if not self._running_tasks:
            # Nothing to collect — just clean up the subscription.
            await self._unsubscribe()
            return results

        logger.info(
            "Collecting %d pivot agent result(s)...",
            len(self._running_tasks),
        )
        done = await asyncio.gather(
            *self._running_tasks.values(),
            return_exceptions=True,
        )
        for item in done:
            if isinstance(item, AgentResult):
                results.append(item)
            elif isinstance(item, Exception):
                logger.warning(
                    "Pivot agent failed: %s",
                    type(item).__name__,
                )
        self._running_tasks.clear()

        # Unsubscribe *after* gathering so no late-arriving signal can
        # spawn a task that never gets awaited.
        await self._unsubscribe()
        return results

    async def _unsubscribe(self) -> None:
        """Remove this planner's handler from the signal bus."""
        bus = getattr(self._orch, "signal_bus", None)
        if bus is not None and hasattr(bus, "unsubscribe_broadcast"):
            await bus.unsubscribe_broadcast(self._handle_signal)

    @property
    def intel(self) -> AdversarialGraph:
        """Access the adversarial graph built during the scan."""
        return self._intel
