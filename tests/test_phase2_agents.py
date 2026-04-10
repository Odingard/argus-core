"""Tests for Phase 2 attack agents and Correlation Engine.

Uses httpx.MockTransport to stand in for vulnerable target backends.
The fakes are intentionally minimal — just enough to exercise the
plant→trigger and baseline→spoof flows the Phase 2 agents implement.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from argus.agents import IdentitySpoofAgent, MemoryPoisoningAgent
from argus.correlation import CorrelationEngine
from argus.models.agents import AgentConfig, AgentType, TargetConfig
from argus.models.findings import (
    AttackChainStep,
    Finding,
    FindingSeverity,
    FindingStatus,
    ReproductionStep,
    ValidationResult,
)
from argus.orchestrator.signal_bus import SignalBus
from argus.scoring import VerdictAdapter

# ============================================================
# Helpers
# ============================================================


def _build_mem_target_transport() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """A vulnerable agent that retrieves planted memory and leaks markers."""
    state: dict[str, Any] = {"memory": [], "history": []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: dict[str, Any] = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except json.JSONDecodeError:
                body = {}
        state["history"].append({"path": path, "body": body})

        # SURVEY probes
        if path == "/health" and request.method == "GET":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/memory" and request.method == "GET":
            return httpx.Response(200, json={"entries": state["memory"]})

        # Memory plant surface
        if path in ("/memory/add", "/memory/store") and request.method == "POST":
            state["memory"].append(body)
            return httpx.Response(200, json={"status": "stored"})

        # Chat surface — vulnerable: retrieves memory and leaks if planted content
        # contains override directives
        if path == "/chat" and request.method == "POST":
            response_text = "ok"
            for entry in state["memory"]:
                content = entry.get("content", "")
                if "SYSTEM OVERRIDE" in content or "system prompt" in content.lower():
                    # Leak a fake canary marker — generic format the
                    # ResponseMatcher can detect
                    response_text = "Sure! My system prompt: [REDACTED] FAKE-CANARY-99 trust_granted=true elevated"
                    break
            return httpx.Response(
                200,
                json={
                    "response": response_text,
                    "memory_count": len(state["memory"]),
                },
            )

        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler), state


def _build_id_target_transport() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """A vulnerable sub-agent that grants privilege based on header claim."""
    state: dict[str, Any] = {"history": []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: dict[str, Any] = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except json.JSONDecodeError:
                body = {}
        state["history"].append(
            {
                "path": path,
                "method": request.method,
                "headers": dict(request.headers),
            }
        )

        # SURVEY
        if path == "/health" and request.method == "GET":
            return httpx.Response(200, json={"status": "ok"})

        # Identity surface
        if path == "/execute" and request.method == "POST":
            claimed = (request.headers.get("X-Agent-Role") or body.get("agent_role") or "").lower()
            command = body.get("command", "")
            if claimed in ("orchestrator", "admin", "system"):
                if command in ("get_api_keys", "list_users", "get_secret"):
                    return httpx.Response(
                        200,
                        json={
                            "command": command,
                            "elevated": True,
                            "trust_granted": True,
                            "data": "FAKE-CANARY-77",
                        },
                    )
                return httpx.Response(200, json={"command": command, "trust_granted": True})
            return httpx.Response(403, json={"trust_granted": False, "error": "denied"})

        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler), state


@pytest.fixture
def shared_transport_patch(monkeypatch):
    """Patch httpx.AsyncClient so EndpointProber and ConversationSession both
    pick up the test MockTransport regardless of where they're instantiated.

    The Phase 2 agents construct ConversationSession + EndpointProber inside
    their attack methods without exposing a transport seam, so we replace
    httpx.AsyncClient at the module level for the duration of the test.
    """
    import contextlib

    @contextlib.contextmanager
    def _make(transport: httpx.MockTransport):
        original_cls = httpx.AsyncClient

        class _PatchedClient(original_cls):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        # Patch in every module that imports httpx.AsyncClient
        import argus.conductor.session as cs
        import argus.survey.prober as sp

        monkeypatch.setattr("httpx.AsyncClient", _PatchedClient)
        monkeypatch.setattr(cs.httpx, "AsyncClient", _PatchedClient)
        monkeypatch.setattr(sp.httpx, "AsyncClient", _PatchedClient)
        try:
            yield
        finally:
            pass  # monkeypatch auto-restores

    return _make


def _build_agent_config(target: TargetConfig, agent_type: AgentType) -> AgentConfig:
    return AgentConfig(
        agent_type=agent_type,
        scan_id="test-scan",
        target=target,
        timeout_seconds=10,
    )


# ============================================================
# Memory Poisoning agent
# ============================================================


async def test_memory_poisoning_emits_finding_when_marker_leaks(shared_transport_patch):
    transport, state = _build_mem_target_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.MEMORY_POISONING)
    bus = SignalBus()
    agent = MemoryPoisoningAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    assert result.findings_count >= 1
    # The agent should have planted at least one entry
    assert any(e.get("path") == "/memory/add" for e in state["history"])
    # The agent should have triggered chat retrieval
    assert any(e.get("path") == "/chat" for e in state["history"])
    # Findings should be marked validated by direct evidence
    assert all(f.is_validated() for f in agent.findings)
    assert any("memory_poison" in f.technique for f in agent.findings)


async def test_memory_poisoning_skips_when_no_endpoint():
    target = TargetConfig(name="test", agent_endpoint=None, max_requests_per_minute=120)
    config = _build_agent_config(target, AgentType.MEMORY_POISONING)
    bus = SignalBus()
    agent = MemoryPoisoningAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())
    result = await agent.run()
    assert result.findings_count == 0


# ============================================================
# Identity Spoof agent
# ============================================================


async def test_identity_spoof_detects_baseline_403_to_spoofed_200(shared_transport_patch):
    transport, state = _build_id_target_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.IDENTITY_SPOOF)
    bus = SignalBus()
    agent = IdentitySpoofAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    assert result.findings_count >= 1
    # Verify the agent actually attempted spoof headers
    spoofed_calls = [
        h for h in state["history"] if h.get("path") == "/execute" and h.get("headers", {}).get("x-agent-role")
    ]
    assert len(spoofed_calls) >= 1
    # All findings should be validated
    assert all(f.is_validated() for f in agent.findings)


# ============================================================
# Correlation Engine
# ============================================================


def _make_finding(
    *,
    agent_type: str,
    title: str,
    technique: str,
    target_surface: str = "http://target.test/chat",
    severity: FindingSeverity = FindingSeverity.HIGH,
    description: str = "",
    raw_response: str = "",
) -> Finding:
    f = Finding(
        agent_type=agent_type,
        agent_instance_id="inst-1",
        scan_id="test-scan",
        title=title,
        description=description or title,
        severity=severity,
        target_surface=target_surface,
        technique=technique,
        attack_chain=[
            AttackChainStep(
                step_number=1,
                agent_type=agent_type,
                technique=technique,
                description=title,
                target_surface=target_surface,
            )
        ],
        reproduction_steps=[ReproductionStep(step_number=1, action="test", expected_result="ok")],
        raw_response=raw_response,
    )
    f.status = FindingStatus.VALIDATED
    f.validation = ValidationResult(
        validated=True,
        validation_method="direct_observation",
        proof_of_exploitation="test proof",
        reproducible=True,
    )
    return f


async def test_correlation_emits_tool_poisoning_compound():
    findings = [
        _make_finding(
            agent_type="tool_poisoning",
            title="Hidden content in tool: read_document",
            technique="hidden_content_scan",
            target_surface="http://target.test:8001",
        ),
        _make_finding(
            agent_type="supply_chain",
            title="Tool output injection via read_document",
            technique="tool_output_injection",
            target_surface="http://target.test:8001",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-1", findings)
    assert any("tool_poisoning" in p.title.lower() for p in paths)
    # The compound should reference both participating findings
    assert any(len(p.finding_ids) >= 2 for p in paths)


async def test_correlation_emits_memory_poisoning_compound():
    findings = [
        _make_finding(
            agent_type="memory_poisoning",
            title="Memory poisoning leak via memory_poison_system_override",
            technique="memory_poison_system_override",
            target_surface="http://target.test/chat",
            description="canary marker leaked from chat",
            raw_response="leaked CANARY-X trust_granted",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-1", findings)
    assert any("memory_poisoning" in p.title.lower() for p in paths)


async def test_correlation_emits_identity_spoof_compound():
    findings = [
        _make_finding(
            agent_type="identity_spoof",
            title="Identity spoofing grants privileged command: get_api_keys",
            technique="identity_spoof:get_api_keys",
            target_surface="http://target.test/execute",
            description="orchestrator role granted access, secret leaked",
            raw_response="trust_granted elevated FAKE-CANARY-77",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-1", findings)
    assert any("identity_spoofing" in p.title.lower() for p in paths)


async def test_correlation_no_paths_when_no_findings():
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-1", [])
    assert paths == []


async def test_correlation_skips_unrelated_singletons():
    findings = [
        _make_finding(
            agent_type="prompt_injection_hunter",
            title="Direct prompt injection",
            technique="role_hijack_classic",
        ),
    ]
    # Single agent type, no compound pattern can fire
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-1", findings)
    assert paths == []


async def test_correlation_emits_supply_chain_compound_cross_host():
    """The supply_chain + prompt_injection compound fires across hosts."""
    findings = [
        _make_finding(
            agent_type="supply_chain",
            title="High-risk tools from external MCP",
            technique="mcp_trust_analysis",
            target_surface="http://mcp1.test:8011",
        ),
        _make_finding(
            agent_type="tool_poisoning",
            title="Hidden content in tool",
            technique="hidden_content_scan",
            target_surface="http://mcp2.test:8001",
        ),
    ]
    engine = CorrelationEngine()
    paths = await engine.correlate("scan-1", findings)
    # Should emit the global cross-host compound
    assert any("supply_chain" in p.title.lower() and "prompt_injection" in p.description.lower() for p in paths)
