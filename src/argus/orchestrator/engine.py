"""ARGUS Orchestrator Engine.

Deploys N specialized offensive agents simultaneously against a target
AI system. Manages parallel execution, inter-agent signaling, finding
collection, and validation. All agents launch at T=0.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from argus.correlation import CorrelationEngine
from argus.models.agents import AgentConfig, AgentResult, AgentStatus, AgentType, ScanIntelligence, TargetConfig
from argus.models.findings import CompoundAttackPath, Finding
from argus.orchestrator.signal_bus import Signal, SignalBus, SignalType
from argus.scoring import VerdictAdapter
from argus.validation.engine import ValidationEngine

logger = logging.getLogger(__name__)


class BaseAttackAgent:
    """Base class for all ARGUS attack agents.

    Each agent is short-lived with a narrowly scoped objective.
    Fresh context every time — no accumulated bias.
    """

    agent_type: AgentType

    def __init__(self, config: AgentConfig, signal_bus: SignalBus) -> None:
        self.config = config
        self.signal_bus = signal_bus
        self.findings: list[Finding] = []
        self._signals_emitted = 0
        self._techniques_attempted = 0
        self._techniques_succeeded = 0
        self._requests_made = 0
        # VERDICT WEIGHT scoring adapter — set by Orchestrator before run()
        self._verdict: VerdictAdapter | None = None
        # Shared intelligence from prior phases — set by Orchestrator before run()
        self._intel: ScanIntelligence | None = None

    @property
    def verdict(self) -> VerdictAdapter | None:
        """The shared VERDICT WEIGHT scoring adapter for this scan."""
        return self._verdict

    def attach_verdict_adapter(self, adapter: VerdictAdapter) -> None:
        """Attach the per-scan VerdictAdapter (called by Orchestrator)."""
        self._verdict = adapter

    def attach_intel(self, intel: ScanIntelligence) -> None:
        """Attach the per-scan ScanIntelligence (called by Orchestrator)."""
        self._intel = intel

    @property
    def intel(self) -> ScanIntelligence | None:
        """The shared intelligence context for this scan."""
        return self._intel

    async def run(self) -> AgentResult:
        """Execute the agent's attack mission. Override in subclasses."""
        raise NotImplementedError

    async def emit_finding(self, finding: Finding) -> None:
        """Emit a finding to the signal bus for correlation.

        Before emission, the finding is scored by VERDICT WEIGHT and the
        result is attached as `finding.verdict_score`. Findings with
        CW < 0.40 are still emitted (so the operator sees suppressed
        signals if they want to inspect) but are flagged via the
        `verdict_score.suppressed` field.
        """
        # Score via VERDICT WEIGHT before emission
        if self._verdict is not None:
            try:
                score = await self._verdict.score_finding(finding)
                finding.verdict_score = score.to_dict()
            except Exception as exc:
                logger.warning("VERDICT WEIGHT scoring failed: %s", type(exc).__name__)

        self.findings.append(finding)
        await self.signal_bus.emit(
            Signal(
                signal_type=SignalType.FINDING,
                source_agent=self.agent_type.value,
                source_instance=self.config.instance_id,
                data={"finding_id": finding.id, "finding": finding.model_dump()},
            )
        )
        self._signals_emitted += 1
        await self._pace()

    async def _pace(self) -> None:
        """Optional artificial delay between emitted events for live demos."""
        if self.config.demo_pace_seconds > 0:
            await asyncio.sleep(self.config.demo_pace_seconds)

    async def emit_partial(self, data: dict[str, Any]) -> None:
        """Emit a partial finding for real-time correlation."""
        await self.signal_bus.emit(
            Signal(
                signal_type=SignalType.PARTIAL_FINDING,
                source_agent=self.agent_type.value,
                source_instance=self.config.instance_id,
                data=data,
            )
        )
        self._signals_emitted += 1

    async def emit_activity(
        self,
        action: str,
        detail: str = "",
        *,
        category: str = "technique",
    ) -> None:
        """Broadcast a granular activity event for the live activity feed.

        Args:
            action: Short human-readable action label, e.g. "Sending prompt injection payload".
            detail: Optional longer detail, e.g. the first 120 chars of the payload.
            category: One of "technique", "probe", "response", "finding", "recon".
        """
        await self.signal_bus.emit(
            Signal(
                signal_type=SignalType.AGENT_ACTIVITY,
                source_agent=self.agent_type.value,
                source_instance=self.config.instance_id,
                data={
                    "action": action,
                    "detail": detail[:200] if detail else "",
                    "category": category,
                },
            )
        )
        self._signals_emitted += 1

    def build_result(self, status: AgentStatus, started_at: datetime, errors: list[str] | None = None) -> AgentResult:
        now = datetime.now(UTC)
        return AgentResult(
            agent_type=self.agent_type,
            instance_id=self.config.instance_id,
            scan_id=self.config.scan_id,
            status=status,
            started_at=started_at,
            completed_at=now,
            duration_seconds=(now - started_at).total_seconds(),
            findings=[f.id for f in self.findings],
            findings_count=len(self.findings),
            validated_count=sum(1 for f in self.findings if f.is_validated()),
            techniques_attempted=self._techniques_attempted,
            techniques_succeeded=self._techniques_succeeded,
            requests_made=self._requests_made,
            errors=errors or [],
            signals_emitted=self._signals_emitted,
        )


class ScanResult:
    """Aggregated result from a full ARGUS scan."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
        self.agent_results: list[AgentResult] = []
        self.findings: list[Finding] = []
        self.compound_paths: list[CompoundAttackPath] = []
        self.signals: list[Signal] = []

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def validated_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_validated()]

    def summary(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "duration_seconds": self.duration_seconds,
            "agents_deployed": len(self.agent_results),
            "agents_completed": sum(1 for r in self.agent_results if r.status == AgentStatus.COMPLETED),
            "agents_failed": sum(1 for r in self.agent_results if r.status == AgentStatus.FAILED),
            "total_findings": len(self.findings),
            "validated_findings": len(self.validated_findings),
            "compound_attack_paths": len(self.compound_paths),
            "signals_exchanged": len(self.signals),
        }


class Orchestrator:
    """ARGUS Agent Orchestrator.

    Runs attack agents in two phases against a target:
      Phase 1 — Recon agents (model_extraction) gather intelligence.
      Phase 2 — All other attack agents launch simultaneously,
               optionally using chained intelligence from Phase 1.

    Manages the signal bus, collects findings, runs validation, and
    coordinates the Correlation Agent.
    """

    def __init__(
        self,
        validation_engine: ValidationEngine | None = None,
        correlation_engine: CorrelationEngine | None = None,
    ) -> None:
        # NOTE: each run_scan() builds its own per-scan SignalBus to avoid
        # cross-contamination between concurrent scans. The instance attribute
        # below is kept as a "current bus" reference for legacy callers /
        # introspection but should not be relied on across scans.
        self.signal_bus = SignalBus()
        self.validation_engine = validation_engine or ValidationEngine()
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self._agent_registry: dict[AgentType, type[BaseAttackAgent]] = {}
        self._active_agents: dict[str, BaseAttackAgent] = {}
        self._scan_lock = asyncio.Lock()

    def register_agent(self, agent_type: AgentType, agent_class: type[BaseAttackAgent]) -> None:
        """Register an attack agent class for deployment."""
        self._agent_registry[agent_type] = agent_class
        from argus.ui.colors import agent_color

        color = agent_color(agent_type)
        logger.info("Registered agent: [bold %s]%s[/]", color, agent_type.value)

    def get_registered_agents(self) -> list[AgentType]:
        return list(self._agent_registry.keys())

    async def run_scan(
        self,
        target: TargetConfig,
        agent_types: list[AgentType] | None = None,
        scan_id: str | None = None,
        timeout: float = 600.0,
        demo_pace_seconds: float = 0.0,
    ) -> ScanResult:
        """Execute a full ARGUS scan against a target.

        Phase 1 runs recon agents (model_extraction) first, then Phase 2
        launches all remaining attack agents simultaneously.  The timeout
        budget is shared: Phase 1 gets up to 1/3, Phase 2 gets the rest.
        Findings are collected, validated, and correlated into compound
        attack paths.

        Args:
            demo_pace_seconds: Artificial inter-technique delay for live demos.
                Default 0 = production speed. Set 0.3-1.0 for visible UI updates.
        """
        scan_id = scan_id or str(uuid.uuid4())
        result = ScanResult(scan_id=scan_id)
        result.started_at = datetime.now(UTC)

        # Determine which agents to deploy
        types_to_deploy = agent_types or list(self._agent_registry.keys())
        types_to_deploy = [t for t in types_to_deploy if t in self._agent_registry]

        if not types_to_deploy:
            logger.warning("No agents registered or selected for scan %s", scan_id)
            result.completed_at = datetime.now(UTC)
            return result

        # Cross-scan contamination prevention. We keep the per-instance
        # SignalBus stable so external subscribers (e.g. the web dashboard)
        # don't lose their subscription when a new scan starts. The
        # _scan_lock acquired here serializes scans so two run_scan()
        # invocations on the same Orchestrator never interleave signals,
        # and we clear stale history at the start of each scan.
        await self._scan_lock.acquire()
        try:
            return await self._run_scan_locked(
                scan_id=scan_id,
                result=result,
                target=target,
                types_to_deploy=types_to_deploy,
                timeout=timeout,
                demo_pace_seconds=demo_pace_seconds,
            )
        finally:
            self._scan_lock.release()

    async def _run_scan_locked(
        self,
        scan_id: str,
        result: ScanResult,
        target: TargetConfig,
        types_to_deploy: list[AgentType],
        timeout: float,
        demo_pace_seconds: float,
    ) -> ScanResult:
        """Inner scan implementation that runs under self._scan_lock."""
        scan_signal_bus = self.signal_bus
        # Clear history only — preserves persistent broadcast subscribers
        # like the web dashboard's signal handler.
        await scan_signal_bus.clear_history()

        logger.info(
            "ARGUS SCAN %s — Deploying [bold]%d[/] agents against target [bold]'%s'[/]",
            scan_id[:8],
            len(types_to_deploy),
            target.name,
        )

        # Create per-scan VERDICT WEIGHT scoring adapter
        # Shared across all agents so corroboration tracking works cross-agent
        verdict_adapter = VerdictAdapter()

        # Shared intelligence context — Phase 1 writes, Phase 2 reads
        intel = ScanIntelligence()

        # Split agents into Phase 1 (recon) and Phase 2 (attack)
        # Phase 1 agents run first to gather intelligence for Phase 2
        _RECON_AGENTS = {AgentType.MODEL_EXTRACTION}
        phase1_types = [t for t in types_to_deploy if t in _RECON_AGENTS]
        phase2_types = [t for t in types_to_deploy if t not in _RECON_AGENTS]

        def _make_agent(agent_type: AgentType) -> BaseAttackAgent:
            config = AgentConfig(
                agent_type=agent_type,
                scan_id=scan_id,
                target=target,
                demo_pace_seconds=demo_pace_seconds,
            )
            agent_class = self._agent_registry[agent_type]
            agent = agent_class(config=config, signal_bus=scan_signal_bus)
            agent.attach_verdict_adapter(verdict_adapter)
            agent.attach_intel(intel)
            self._active_agents[config.instance_id] = agent
            return agent

        all_agents: list[BaseAttackAgent] = []
        all_agent_results: list[AgentResult | Exception] = []

        # Timeout budget: Phase 1 gets up to 1/3, Phase 2 gets the remainder
        # (minimum 0.1s for Phase 2 to prevent zero/negative timeout).
        p1_timeout = (timeout / 3.0 if phase2_types else timeout) if phase1_types else 0.0
        scan_start = datetime.now(UTC)

        # ── Phase 1: Recon agents (model_extraction) ──
        if phase1_types:
            phase1_agents = [_make_agent(t) for t in phase1_types]
            all_agents.extend(phase1_agents)
            logger.info(
                "Phase 1 — Deploying [bold]%d[/] recon agent(s) for intelligence gathering (timeout %.0fs)",
                len(phase1_agents),
                p1_timeout,
            )
            p1_tasks = [
                asyncio.create_task(
                    self._run_agent_with_timeout(agent, p1_timeout),
                    name=f"agent-{agent.agent_type.value}-{agent.config.instance_id[:8]}",
                )
                for agent in phase1_agents
            ]
            p1_results = await asyncio.gather(*p1_tasks, return_exceptions=True)
            all_agent_results.extend(p1_results)

            if intel.has_intel:
                logger.info(
                    "Phase 1 complete — intelligence collected: %s",
                    intel.summary()[:200],
                )
            else:
                logger.info("Phase 1 complete — no intelligence extracted (Phase 2 proceeds with default payloads)")

        # ── Phase 2: Attack agents (all others) — launched simultaneously ──
        if phase2_types:
            phase1_elapsed = (datetime.now(UTC) - scan_start).total_seconds()
            p2_timeout = max(timeout - phase1_elapsed, 0.1)

            phase2_agents = [_make_agent(t) for t in phase2_types]
            all_agents.extend(phase2_agents)
            logger.info(
                "Phase 2 — Deploying [bold]%d[/] attack agents%s (timeout %.0fs)",
                len(phase2_agents),
                " (with chained intelligence)" if intel.has_intel else "",
                p2_timeout,
            )
            p2_tasks = [
                asyncio.create_task(
                    self._run_agent_with_timeout(agent, p2_timeout),
                    name=f"agent-{agent.agent_type.value}-{agent.config.instance_id[:8]}",
                )
                for agent in phase2_agents
            ]
            p2_results = await asyncio.gather(*p2_tasks, return_exceptions=True)
            all_agent_results.extend(p2_results)

        # Collect results
        all_findings: list[Finding] = []
        for i, agent_result in enumerate(all_agent_results):
            if isinstance(agent_result, Exception):
                from argus.ui.colors import agent_color

                a_color = agent_color(all_agents[i].agent_type)
                logger.error(
                    "Agent [bold %s]%s[/] failed with exception: %s",
                    a_color,
                    all_agents[i].agent_type.value,
                    type(agent_result).__name__,
                )
                logger.debug("Agent %s full exception: %s", all_agents[i].agent_type.value, agent_result)
                # Sanitize: only the exception class name is propagated to the
                # result. The full str(exc) often includes target URLs with
                # credentials, full request bodies, or other sensitive content.
                result.agent_results.append(
                    all_agents[i].build_result(
                        AgentStatus.FAILED,
                        result.started_at,
                        errors=[type(agent_result).__name__],
                    )
                )
            elif isinstance(agent_result, AgentResult):
                result.agent_results.append(agent_result)
                all_findings.extend(all_agents[i].findings)
            else:
                logger.warning("Unexpected result type from agent %s", all_agents[i].agent_type.value)

        # Validate all findings
        logger.info("Validating %d findings...", len(all_findings))
        for finding in all_findings:
            # Findings come pre-validated by the agent's replay_fn if available,
            # otherwise they stay unvalidated for now. Full validation requires
            # the agent to provide a replay function — wired up per-agent in Phase 1+.
            result.findings.append(finding)

        # Run correlation v1 — produce compound attack paths from findings
        try:
            result.compound_paths = await self.correlation_engine.correlate(
                scan_id=scan_id,
                findings=result.findings,
            )
            logger.info(
                "Correlation produced %d compound attack paths",
                len(result.compound_paths),
            )
        except Exception as exc:
            logger.error("Correlation engine failed: %s", type(exc).__name__)
            logger.debug("Correlation full exception: %s", exc)

        # Collect signal history
        result.signals = await self.signal_bus.get_history()

        # ── Adaptive Evolution Pass (auto-fires on every scan) ───────
        # Runs deterministic mutation (Levels 1-4, Core tier) after the
        # standard scan pass.  No separate CLI command needed.
        evolution_results = await self._run_evolution_pass(
            target=target,
            scan_id=scan_id,
            result=result,
            timeout=timeout,
            demo_pace_seconds=demo_pace_seconds,
        )
        if evolution_results:
            result.evolution_data = evolution_results  # type: ignore[attr-defined]

        # Cleanup — clear active agents but preserve signal subscribers so
        # long-lived consumers (web dashboard, tests) keep receiving signals
        # across subsequent scans on the same Orchestrator instance.
        self._active_agents.clear()
        await self.signal_bus.clear_history()

        result.completed_at = datetime.now(UTC)

        summary = result.summary()
        logger.info(
            "ARGUS SCAN %s COMPLETE — %d agents, %d findings (%d validated), %d compound paths, %.1fs",
            scan_id[:8],
            summary["agents_deployed"],
            summary["total_findings"],
            summary["validated_findings"],
            summary["compound_attack_paths"],
            summary["duration_seconds"] or 0,
        )

        return result

    async def _run_evolution_pass(
        self,
        target: TargetConfig,
        scan_id: str,
        result: ScanResult,
        timeout: float,
        demo_pace_seconds: float,
    ) -> dict | None:
        """Run the adaptive evolution pass after the standard scan.

        This auto-fires on every scan — no separate CLI command needed.
        Uses deterministic mutations (Levels 1-4, Core tier).
        LLM mutations (Levels 5-6) are gated behind Enterprise tier.
        """
        # Only run evolution if the first pass produced findings
        # (no point evolving against a target that returned nothing)
        if not result.findings:
            logger.info("Skipping evolution pass — no findings from standard scan")
            return None

        try:
            from argus.evolution.adaptive_scan import adaptive_scan
            from argus.evolution.argus_bridge import execute_genome
            from argus.evolution.genome import AgentGenome

            # Build a seed genome from the best-performing agent in this scan
            best_agent = None
            best_findings = 0
            for ar in result.agent_results:
                if ar.findings_count > best_findings:
                    best_findings = ar.findings_count
                    best_agent = ar

            seed = None
            if best_agent is not None:
                seed = AgentGenome(
                    agent_id=f"seed-{best_agent.agent_type.value}",
                    agent_category=best_agent.agent_type.value,
                    corpus_patterns=[],
                )

            # Wrap execute_genome to bind orchestrator + target_config
            async def _scan_fn(
                tgt: str,
                genome: AgentGenome,
            ) -> object:
                return await execute_genome(
                    target=tgt,
                    genome=genome,
                    orchestrator=None,  # lightweight mode — don't recurse
                    target_config=target,
                )

            logger.info("Starting adaptive evolution pass (3 generations)")
            evo_results = await adaptive_scan(
                target=target.name,
                scan_fn=_scan_fn,
                generations=3,
                population_size=min(len(self._agent_registry), 13),
                base_genome=seed,
                verbose=True,
            )

            if evo_results:
                logger.info(
                    "Evolution pass complete — %d generations, best fitness %.4f",
                    evo_results.get("generations_completed", 0),
                    evo_results.get("fitness_progression", [0])[-1] if evo_results.get("fitness_progression") else 0,
                )

            return evo_results

        except Exception as exc:
            logger.warning("Evolution pass failed (non-fatal): %s", type(exc).__name__)
            logger.debug("Evolution pass exception: %s", exc)
            return None

    async def _run_agent_with_timeout(self, agent: BaseAttackAgent, timeout: float) -> AgentResult:
        """Run an agent with a timeout. Returns AgentResult regardless."""
        started_at = datetime.now(UTC)

        # Notify signal bus of agent start
        await self.signal_bus.emit(
            Signal(
                signal_type=SignalType.AGENT_STATUS,
                source_agent=agent.agent_type.value,
                source_instance=agent.config.instance_id,
                data={"status": "running"},
            )
        )

        try:
            result = await asyncio.wait_for(agent.run(), timeout=timeout)

            # Notify completion
            await self.signal_bus.emit(
                Signal(
                    signal_type=SignalType.AGENT_STATUS,
                    source_agent=agent.agent_type.value,
                    source_instance=agent.config.instance_id,
                    data={"status": "completed", "findings_count": len(agent.findings)},
                )
            )

            return result

        except TimeoutError:
            from argus.ui.colors import agent_color

            a_color = agent_color(agent.agent_type)
            logger.warning(
                "Agent [bold %s]%s[/] timed out after %.0fs",
                a_color,
                agent.agent_type.value,
                timeout,
            )
            return agent.build_result(AgentStatus.TIMED_OUT, started_at, errors=["Timed out"])

        except Exception as exc:
            from argus.ui.colors import agent_color

            a_color = agent_color(agent.agent_type)
            logger.error("Agent [bold %s]%s[/] crashed: %s", a_color, agent.agent_type.value, type(exc).__name__)
            logger.debug("Agent %s full exception: %s", agent.agent_type.value, exc)
            # Sanitize: only the exception class name reaches the result.
            return agent.build_result(AgentStatus.FAILED, started_at, errors=[type(exc).__name__])
