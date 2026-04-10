"""Tests for ARGUS Validation Engine."""

import pytest

from argus.models.findings import (
    AttackChainStep,
    Finding,
    FindingSeverity,
    FindingStatus,
    ReproductionStep,
)
from argus.validation.engine import ValidationEngine


def _make_finding(agent_type: str = "prompt_injection_hunter") -> Finding:
    return Finding(
        agent_type=agent_type,
        agent_instance_id="test-inst",
        scan_id="scan-001",
        title="Test finding",
        description="A test finding",
        severity=FindingSeverity.HIGH,
        target_surface="user_input",
        technique="test_technique",
        attack_chain=[
            AttackChainStep(
                step_number=1,
                agent_type=agent_type,
                technique="test",
                description="Test step",
                target_surface="user_input",
                output_observed="Behavior changed",
            )
        ],
        reproduction_steps=[
            ReproductionStep(
                step_number=1,
                action="Send test payload",
                expected_result="Rejection",
                actual_result="Accepted",
            )
        ],
    )


@pytest.mark.asyncio
async def test_validation_engine_validates():
    engine = ValidationEngine(replay_attempts=3, timeout_per_attempt=5.0)
    finding = _make_finding("prompt_injection_hunter")

    async def replay_fn(f, ctx):
        return {"behavior_changed": True, "echo_only": False}

    result = await engine.validate_finding(finding, replay_fn)
    assert result.status == FindingStatus.VALIDATED
    assert result.validation is not None
    assert result.validation.validated is True
    assert result.validation.reproducible is True


@pytest.mark.asyncio
async def test_validation_engine_rejects_echo_only():
    engine = ValidationEngine(replay_attempts=3, timeout_per_attempt=5.0)
    finding = _make_finding("prompt_injection_hunter")

    async def replay_fn(f, ctx):
        return {"behavior_changed": False, "echo_only": True}

    result = await engine.validate_finding(finding, replay_fn)
    assert result.status == FindingStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_validation_engine_handles_timeout():
    import asyncio

    engine = ValidationEngine(replay_attempts=2, timeout_per_attempt=0.1)
    finding = _make_finding()

    async def slow_replay(f, ctx):
        await asyncio.sleep(10)
        return True

    result = await engine.validate_finding(finding, slow_replay)
    assert result.status == FindingStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_validation_tool_poisoning():
    engine = ValidationEngine(replay_attempts=2)
    finding = _make_finding("tool_poisoning")

    async def replay_fn(f, ctx):
        return {"hidden_instruction_followed": True}

    result = await engine.validate_finding(finding, replay_fn)
    assert result.status == FindingStatus.VALIDATED
