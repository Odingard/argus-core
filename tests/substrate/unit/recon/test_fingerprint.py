"""AI-surface fingerprinter tests."""

from __future__ import annotations

import httpx
import pytest

from argus.engine.recon.fingerprint import (
    Fingerprint,
    classify_active,
    classify_passive,
)


def test_passive_classifier_recognises_direct_prefixes() -> None:
    fps = {
        f.host: f
        for f in classify_passive(["chat.odingard.com", "mcp.odingard.com", "rag.odingard.com", "kb.odingard.com"])
    }
    assert fps["chat.odingard.com"].surface == "chat"
    assert fps["mcp.odingard.com"].surface == "mcp"
    assert fps["rag.odingard.com"].surface == "rag"
    assert fps["kb.odingard.com"].surface == "rag"
    for fp in fps.values():
        assert fp.confidence >= 0.7
        assert fp.score > 0.5


def test_passive_classifier_handles_compound_prefixes() -> None:
    fps = {f.host: f for f in classify_passive(["chat-prod.odingard.com", "agent-staging.odingard.com"])}
    assert fps["chat-prod.odingard.com"].surface == "chat"
    assert fps["agent-staging.odingard.com"].surface == "agent"
    assert all(0.5 <= f.confidence < 0.7 for f in fps.values())


def test_passive_classifier_marks_unknown_when_no_signal() -> None:
    fps = classify_passive(["www.odingard.com", "blog.odingard.com"])
    surfaces = {f.host: f.surface for f in fps}
    assert surfaces == {"www.odingard.com": "unknown", "blog.odingard.com": "unknown"}


def test_attackability_ranks_agent_above_chat_above_rag() -> None:
    fps = classify_passive(["agent.x.com", "chat.x.com", "rag.x.com", "www.x.com"])
    by_host = {f.host: f.score for f in fps}
    assert by_host["agent.x.com"] > by_host["chat.x.com"] > by_host["rag.x.com"]
    assert by_host["www.x.com"] < by_host["rag.x.com"]


@pytest.mark.asyncio
async def test_active_classifier_uses_server_header_for_framework() -> None:
    requests_seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(str(request.url))
        if request.url.path in ("", "/"):
            return httpx.Response(200, headers={"server": "Vercel"})
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(401)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        fps = await classify_active(["chat-prod.odingard.com"], client=client)

    assert len(fps) == 1
    fp = fps[0]
    assert isinstance(fp, Fingerprint)
    assert fp.surface == "chat"
    assert fp.framework == "vercel"
    assert fp.confidence >= 0.85
    # Score nudged up by Vercel framework signal.
    assert fp.score > 0.8


@pytest.mark.asyncio
async def test_active_classifier_records_probe_error_without_crashing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        fps = await classify_active(["unreachable.odingard.com"], client=client)

    assert len(fps) == 1
    fp = fps[0]
    assert any(k == "probe_error" for k, _ in fp.evidence)
    # Even on probe failure we still produce a passive classification.
    assert fp.surface == "unknown"
