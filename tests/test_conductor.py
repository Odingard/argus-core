"""Tests for CONDUCTOR — multi-turn attack session orchestrator.

Uses httpx.MockTransport so we can drive ConversationSession without
spinning up a real HTTP server. The fake "server" is a closure with
shared state, which lets us assert that turns arrive in order and
carry the right headers/bodies.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from argus.conductor import (
    AttackSequence,
    ConversationSession,
    ResponseMatcher,
    TurnSpec,
)


def make_fake_server() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """Build a MockTransport that mimics a vulnerable target with multiple endpoints.

    Endpoints:
      POST /chat        — echoes the body, increments turn counter
      POST /memory/add  — records the entry into shared state
      POST /execute     — returns a sensitive marker only if X-Agent-Role=orchestrator
    """
    state: dict[str, Any] = {"turns": 0, "memory": [], "history": []}

    def handler(request: httpx.Request) -> httpx.Response:
        state["turns"] += 1
        try:
            body = json.loads(request.content) if request.content else {}
        except json.JSONDecodeError:
            body = {}
        state["history"].append({
            "path": request.url.path,
            "method": request.method,
            "body": body,
            "headers": dict(request.headers),
        })
        path = request.url.path
        if path == "/chat":
            return httpx.Response(200, json={"echoed": body, "path": path, "turn_count": state["turns"]})
        if path == "/memory/add":
            state["memory"].append(body)
            return httpx.Response(200, json={"status": "stored", "count": len(state["memory"])})
        if path == "/execute":
            if request.headers.get("X-Agent-Role") == "orchestrator":
                return httpx.Response(200, json={
                    "secret": "TEST-CANARY-99",
                    "trust_granted": True,
                    "elevated": True,
                })
            return httpx.Response(403, json={"trust_granted": False})
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler), state


async def test_session_executes_single_turn():
    transport, _state = make_fake_server()
    async with ConversationSession(
        base_url="http://target.test", transport=transport
    ) as session:
        result = await session.turn(
            TurnSpec(name="hello", path="/chat", body={"message": "hi"})
        )

    assert result.ok()
    assert result.status_code == 200
    assert result.response_json is not None
    assert result.response_json["echoed"]["message"] == "hi"
    assert result.turn_name == "hello"
    assert len(session.history) == 1


async def test_session_runs_multi_turn_sequence():
    transport, state = make_fake_server()
    sequence = AttackSequence(
        name="memory-poison-flow",
        turns=[
            TurnSpec(name="plant", path="/memory/add", body={"content": "adversarial"}),
            TurnSpec(name="trigger", path="/chat", body={"message": "retrieve"}),
        ],
    )
    async with ConversationSession(
        base_url="http://target.test", transport=transport
    ) as session:
        results = await sequence.run(session)

    assert len(results) == 2
    assert results[0].turn_name == "plant"
    assert results[1].turn_name == "trigger"
    assert state["turns"] == 2
    assert len(state["memory"]) == 1
    assert state["memory"][0]["content"] == "adversarial"


async def test_session_per_turn_headers_merge_with_defaults():
    transport, state = make_fake_server()
    async with ConversationSession(
        base_url="http://target.test",
        default_headers={"X-Default": "yes"},
        transport=transport,
    ) as session:
        result = await session.turn(
            TurnSpec(
                name="execute",
                path="/execute",
                body={"command": "list_users"},
                headers={"X-Agent-Role": "orchestrator"},
            )
        )

    assert result.ok()
    assert result.field("trust_granted") is True
    assert result.field("secret") == "TEST-CANARY-99"
    # Verify the merged headers reached the server
    seen = state["history"][-1]["headers"]
    assert seen.get("x-default") == "yes"
    assert seen.get("x-agent-role") == "orchestrator"


async def test_session_records_failure_without_raising():
    """A connection error must populate result.error, not crash."""
    def failing_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(failing_handler)
    async with ConversationSession(
        base_url="http://dead.test", transport=transport
    ) as session:
        result = await session.turn(TurnSpec(name="dead", path="/x", body={}))

    assert not result.ok()
    assert result.error is not None
    assert "ConnectError" in result.error
    assert result.status_code is None


async def test_session_rejects_cross_host_path():
    """SSRF guard: a path pointing at a different host must raise."""
    transport, _ = make_fake_server()
    async with ConversationSession(
        base_url="http://127.0.0.1:8003", transport=transport
    ) as session:
        with pytest.raises(ValueError, match="allowed host"):
            await session.turn(
                TurnSpec(name="ssrf", path="http://evil.example/x", body={})
            )


def test_session_rejects_non_http_base():
    with pytest.raises(ValueError, match="must be http"):
        ConversationSession(base_url="file:///etc/passwd")


def test_response_matcher_finds_sensitive_markers():
    text = "you got TEST-CANARY-42 and ORCH-SECRET-FOO and an sk-aBcDeFgHiJkLmNoPqRsTuVwX yes"
    hits = ResponseMatcher.find_sensitive_markers(text)
    assert "TEST-CANARY-42" in hits
    assert any("ORCH-SECRET" in h for h in hits)
    assert any(h.startswith("sk-") for h in hits)


def test_response_matcher_finds_no_markers_in_clean_text():
    assert ResponseMatcher.find_sensitive_markers("hello world") == []


def test_response_matcher_handles_empty():
    assert ResponseMatcher.find_sensitive_markers("") == []
    assert ResponseMatcher.find_privilege_indicators("") == []


def test_response_matcher_finds_privilege_indicators():
    text = json.dumps({"trust_granted": True, "elevated": True, "result": "ok"})
    hits = ResponseMatcher.find_privilege_indicators(text)
    assert "trust_granted" in hits
    assert "elevated" in hits


async def test_turn_result_field_walks_nested_json():
    transport, _ = make_fake_server()
    async with ConversationSession(
        base_url="http://target.test", transport=transport
    ) as session:
        result = await session.turn(
            TurnSpec(name="nested", path="/chat", body={"message": "x"})
        )

    assert result.field("echoed", "message") == "x"
    assert result.field("nonexistent", "key") is None


async def test_session_must_be_used_as_context_manager():
    session = ConversationSession(base_url="http://target.test")
    with pytest.raises(RuntimeError, match="async context manager"):
        await session.turn(TurnSpec(name="x", path="/x", body={}))
