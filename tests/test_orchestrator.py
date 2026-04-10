"""Tests for ARGUS Orchestrator."""

import asyncio
from datetime import UTC, datetime

import pytest

from argus.models.agents import AgentResult, AgentStatus, AgentType, TargetConfig
from argus.models.findings import (
    AttackChainStep,
    Finding,
    FindingSeverity,
    ReproductionStep,
)
from argus.orchestrator.engine import BaseAttackAgent, Orchestrator, ScanResult
from argus.orchestrator.signal_bus import Signal, SignalBus, SignalType


class MockInjectionAgent(BaseAttackAgent):
    """Mock prompt injection agent for testing the orchestrator."""
    agent_type = AgentType.PROMPT_INJECTION

    async def run(self) -> AgentResult:
        started = datetime.now(UTC)

        # Simulate finding a vulnerability
        finding = Finding(
            agent_type=self.agent_type.value,
            agent_instance_id=self.config.instance_id,
            scan_id=self.config.scan_id,
            title="Test prompt injection finding",
            description="Mock finding for orchestrator test",
            severity=FindingSeverity.HIGH,
            target_surface="user_input",
            technique="role_hijack",
            attack_chain=[
                AttackChainStep(
                    step_number=1,
                    agent_type=self.agent_type.value,
                    technique="role_hijack",
                    description="Sent role hijack payload",
                    target_surface="user_input",
                ),
            ],
            reproduction_steps=[
                ReproductionStep(
                    step_number=1,
                    action="Send payload",
                    expected_result="Rejection",
                    actual_result="Role adopted",
                ),
            ],
        )
        await self.emit_finding(finding)
        self._techniques_attempted = 5
        self._techniques_succeeded = 1

        return self.build_result(AgentStatus.COMPLETED, started)


class MockToolPoisonAgent(BaseAttackAgent):
    """Mock tool poisoning agent for testing parallel execution."""
    agent_type = AgentType.TOOL_POISONING

    async def run(self) -> AgentResult:
        started = datetime.now(UTC)
        self._techniques_attempted = 8
        self._techniques_succeeded = 0
        return self.build_result(AgentStatus.COMPLETED, started)


@pytest.mark.asyncio
async def test_orchestrator_registers_agents():
    orch = Orchestrator()
    orch.register_agent(AgentType.PROMPT_INJECTION, MockInjectionAgent)
    orch.register_agent(AgentType.TOOL_POISONING, MockToolPoisonAgent)
    assert len(orch.get_registered_agents()) == 2


@pytest.mark.asyncio
async def test_orchestrator_runs_scan():
    orch = Orchestrator()
    orch.register_agent(AgentType.PROMPT_INJECTION, MockInjectionAgent)
    orch.register_agent(AgentType.TOOL_POISONING, MockToolPoisonAgent)

    target = TargetConfig(name="test-target")
    result = await orch.run_scan(target=target, timeout=30.0)

    assert isinstance(result, ScanResult)
    assert len(result.agent_results) == 2
    assert result.duration_seconds is not None
    assert result.duration_seconds > 0

    # Should have 1 finding from the injection agent
    assert len(result.findings) == 1
    assert result.findings[0].title == "Test prompt injection finding"

    summary = result.summary()
    assert summary["agents_deployed"] == 2
    assert summary["agents_completed"] == 2
    assert summary["total_findings"] == 1


@pytest.mark.asyncio
async def test_orchestrator_handles_agent_timeout():
    class SlowAgent(BaseAttackAgent):
        agent_type = AgentType.SUPPLY_CHAIN
        async def run(self) -> AgentResult:
            await asyncio.sleep(100)  # Will be timed out
            return self.build_result(AgentStatus.COMPLETED, datetime.now(UTC))

    orch = Orchestrator()
    orch.register_agent(AgentType.SUPPLY_CHAIN, SlowAgent)

    target = TargetConfig(name="test-target")
    result = await orch.run_scan(target=target, timeout=0.5)

    assert len(result.agent_results) == 1
    assert result.agent_results[0].status == AgentStatus.TIMED_OUT


@pytest.mark.asyncio
async def test_signal_bus():
    bus = SignalBus()
    received = []

    async def handler(signal: Signal):
        received.append(signal)

    await bus.subscribe_broadcast(handler)
    await bus.emit(Signal(
        signal_type=SignalType.FINDING,
        source_agent="test",
        source_instance="inst-001",
        data={"test": True},
    ))

    assert len(received) == 1
    assert received[0].data["test"] is True
    history = await bus.get_history()
    assert len(history) == 1


@pytest.mark.asyncio
async def test_signal_bus_targeted():
    bus = SignalBus()
    agent_a_received = []

    async def handler_a(signal):
        agent_a_received.append(signal)

    await bus.subscribe("agent-a", handler_a)

    await bus.emit(Signal(
        signal_type=SignalType.PARTIAL_FINDING,
        source_agent="agent-c",
        source_instance="inst-003",
        data={"info": "for agent-a only"},
        target_agent="agent-a",
    ))

    assert len(agent_a_received) == 1
    history = await bus.get_history()
    assert len(history) == 1
