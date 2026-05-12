"""Passive recon source tests.

All sources are exercised against an in-process ``httpx.MockTransport``
so the test suite does not depend on external services. The mocks
return realistic payloads captured from real responses (with the
sensitive bits redacted).
"""

from __future__ import annotations

import json

import httpx
import pytest

from argus.engine.recon.sources import crt_sh, hackertarget, wayback


def _client(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, timeout=5.0)


@pytest.mark.asyncio
async def test_crt_sh_extracts_unique_hosts_and_drops_wildcards() -> None:
    body = json.dumps(
        [
            {
                "name_value": "chat.odingard.com\n*.odingard.com",
                "not_before": "2024-09-01T00:00:00",
            },
            {
                "name_value": "agent.odingard.com\nchat.odingard.com",
                "not_before": "2024-08-15T00:00:00",
            },
            {
                "name_value": "rag.odingard.com",
                "not_before": "2024-10-12T00:00:00",
            },
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert "crt.sh" in str(request.url)
        return httpx.Response(200, text=body)

    async with _client(handler) as client:
        obs = await crt_sh.fetch("odingard.com", client=client)

    hosts = [o.host for o in obs]
    assert hosts == ["agent.odingard.com", "chat.odingard.com", "rag.odingard.com"]
    chat = next(o for o in obs if o.host == "chat.odingard.com")
    # Earliest not_before for repeat hosts wins.
    assert chat.first_seen == "2024-08-15T00:00:00"
    assert chat.record_type == "cert_san"


@pytest.mark.asyncio
async def test_crt_sh_returns_error_observation_on_http_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="bad gateway")

    async with _client(handler) as client:
        obs = await crt_sh.fetch("odingard.com", client=client)

    assert len(obs) == 1
    assert obs[0].record_type == "error"
    assert "503" in dict(obs[0].extra).get("error", "")


@pytest.mark.asyncio
async def test_hackertarget_parses_csv() -> None:
    body = "chat.odingard.com,1.2.3.4\nagent.odingard.com,5.6.7.8\n"

    def handler(request: httpx.Request) -> httpx.Response:
        assert "hackertarget.com" in str(request.url)
        return httpx.Response(200, text=body)

    async with _client(handler) as client:
        obs = await hackertarget.fetch("odingard.com", client=client)

    hosts = [o.host for o in obs]
    assert hosts == ["agent.odingard.com", "chat.odingard.com"]
    chat = next(o for o in obs if o.host == "chat.odingard.com")
    assert dict(chat.extra)["a_record"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_hackertarget_quota_exhausted_emits_error_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="API count exceeded - upgrade")

    async with _client(handler) as client:
        obs = await hackertarget.fetch("odingard.com", client=client)

    assert len(obs) == 1
    assert obs[0].record_type == "error"


@pytest.mark.asyncio
async def test_wayback_dedupes_hosts_and_keeps_earliest_timestamp() -> None:
    rows = [
        ["original", "timestamp"],
        ["http://chat.odingard.com/login", "20231201000000"],
        ["http://chat.odingard.com/foo", "20220101000000"],
        ["https://Agent.Odingard.com/api", "20240115000000"],
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert "web.archive.org" in str(request.url)
        return httpx.Response(200, text=json.dumps(rows))

    async with _client(handler) as client:
        obs = await wayback.fetch("odingard.com", client=client)

    hosts = [o.host for o in obs]
    assert hosts == ["agent.odingard.com", "chat.odingard.com"]
    chat = next(o for o in obs if o.host == "chat.odingard.com")
    assert chat.first_seen == "20220101000000"


@pytest.mark.asyncio
async def test_wayback_empty_index_returns_no_observations() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps([["original", "timestamp"]]))

    async with _client(handler) as client:
        obs = await wayback.fetch("odingard.com", client=client)

    assert obs == []
