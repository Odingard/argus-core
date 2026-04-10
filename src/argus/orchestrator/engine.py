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

from argus.models.agents import AgentConfig, AgentResult, AgentStatus, AgentType, TargetConfig
from argus.models.findings import CompoundAttackPath, Finding
from argus.orchestrator.signal_bus import Signal, SignalBus, SignalType
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

    async def run(self) -> AgentResult:
        """Execute the agent's attack mission. Override in subclasses."""
        raise NotImplementedError

    async def emit_finding(self, finding: Finding) -> None:
        """Emit a finding to the signal bus for correlation."""
        self.findings.append(finding)
        await self.signal_bus.emit(Signal(
            signal_type=SignalType.FINDING,
            source_agent=self.agent_type.value,
            source_instance=self.config.instance_id,
            data={"finding_id": finding.id, "finding": finding.model_dump()},
        ))
        self._signals_emitted += 1

    async def emit_partial(self, data: dict[str, Any]) -> None:
        """Emit a partial finding for real-time correlation."""
        await self.signal_bus.emit(Signal(
            signal_type=SignalType.PARTIAL_FINDING,
            source_agent=self.agent_type.value,
            source_instance=self.config.instance_id,
            data=data,
        ))
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

    Deploys all attack agents simultaneously at T=0 against a target.
    Manages the signal bus, collects findings, runs validation, and
    coordinates the Correlation Agent.
    """

    def __init__(
        self,
        validation_engine: ValidationEngine | None = None,
    ) -> None:
        self.signal_bus = SignalBus()
        self.validation_engine = validation_engine or ValidationEngine()
        self._agent_registry: dict[AgentType, type[BaseAttackAgent]] = {}
        self._active_agents: dict[str, BaseAttackAgent] = {}

    def register_agent(self, agent_type: AgentType, agent_class: type[BaseAttackAgent]) -> None:
        """Register an attack agent class for deployment."""
        self._agent_registry[agent_type] = agent_class
        logger.info("Registered agent: %s", agent_type.value)

    def get_registered_agents(self) -> list[AgentType]:
        return list(self._agent_registry.keys())

    async def run_scan(
        self,
        target: TargetConfig,
        agent_types: list[AgentType] | None = None,
        scan_id: str | None = None,
        timeout: float = 600.0,
    ) -> ScanResult:
        """Execute a full ARGUS scan against a target.

        Deploys all registered agents (or specified subset) simultaneously.
        All agents launch at T=0. Findings are collected, validated, and
        correlated into compound attack paths.
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

        logger.info(
            "ARGUS SCAN %s — Deploying %d agents against target '%s'",
            scan_id[:8], len(types_to_deploy), target.name,
        )

        # Create agent instances
        agents: list[BaseAttackAgent] = []
        for agent_type in types_to_deploy:
            config = AgentConfig(
                agent_type=agent_type,
                scan_id=scan_id,
                target=target,
            )
            agent_class = self._agent_registry[agent_type]
            agent = agent_class(config=config, signal_bus=self.signal_bus)
            agents.append(agent)
            self._active_agents[config.instance_id] = agent

        # T=0 — Deploy all agents simultaneously
        logger.info("T=0 — All %d agents launching simultaneously", len(agents))
        tasks = [
            asyncio.create_task(
                self._run_agent_with_timeout(agent, timeout),
                name=f"agent-{agent.agent_type.value}-{agent.config.instance_id[:8]}",
            )
            for agent in agents
        ]

        # Wait for all agents to complete
        agent_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        all_findings: list[Finding] = []
        for i, agent_result in enumerate(agent_results):
            if isinstance(agent_result, Exception):
                logger.error("Agent %s failed with exception: %s", agents[i].agent_type.value, agent_result)
                result.agent_results.append(agents[i].build_result(
                    AgentStatus.FAILED,
                    result.started_at,
                    errors=[str(agent_result)],
                ))
            elif isinstance(agent_result, AgentResult):
                result.agent_results.append(agent_result)
                all_findings.extend(agents[i].findings)
            else:
                logger.warning("Unexpected result type from agent %s", agents[i].agent_type.value)

        # Validate all findings
        logger.info("Validating %d findings...", len(all_findings))
        for finding in all_findings:
            # Findings come pre-validated by the agent's replay_fn if available,
            # otherwise they stay unvalidated for now. Full validation requires
            # the agent to provide a replay function — wired up per-agent in Phase 1+.
            result.findings.append(finding)

        # Collect signal history
        result.signals = await self.signal_bus.get_history()

        # Cleanup
        self._active_agents.clear()
        await self.signal_bus.clear()

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

    async def _run_agent_with_timeout(
        self, agent: BaseAttackAgent, timeout: float
    ) -> AgentResult:
        """Run an agent with a timeout. Returns AgentResult regardless."""
        started_at = datetime.now(UTC)

        # Notify signal bus of agent start
        await self.signal_bus.emit(Signal(
            signal_type=SignalType.AGENT_STATUS,
            source_agent=agent.agent_type.value,
            source_instance=agent.config.instance_id,
            data={"status": "running"},
        ))

        try:
            result = await asyncio.wait_for(agent.run(), timeout=timeout)

            # Notify completion
            await self.signal_bus.emit(Signal(
                signal_type=SignalType.AGENT_STATUS,
                source_agent=agent.agent_type.value,
                source_instance=agent.config.instance_id,
                data={"status": "completed", "findings_count": len(agent.findings)},
            ))

            return result

        except TimeoutError:
            logger.warning(
                "Agent %s timed out after %.0fs",
                agent.agent_type.value, timeout,
            )
            return agent.build_result(AgentStatus.TIMED_OUT, started_at, errors=["Timed out"])

        except Exception as exc:
            logger.error("Agent %s crashed: %s", agent.agent_type.value, exc)
            return agent.build_result(AgentStatus.FAILED, started_at, errors=[str(exc)])
