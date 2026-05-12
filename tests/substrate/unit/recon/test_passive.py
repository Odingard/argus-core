"""Passive recon orchestrator tests.

These exercise the full crt.sh + hackertarget + wayback + scope-filter
+ fingerprint pipeline against an in-process ``httpx.MockTransport``.
The orchestrator's contract under test:

* every host is filtered through the operator scope before
  fingerprinting (out-of-scope hosts are reported but never probed)
* duplicate hosts across sources are de-duped
* source errors are surfaced in ``source_errors`` rather than
  swallowed silently (AGENTS.md rule 9)
* the JSON serialisation is stable and ranks fingerprints by score
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from argus.engine.recon.passive import discover
from argus.engine.recon.scope import load


def _scope_file(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "scope.txt"
    p.write_text(body, encoding="utf-8")
    return p


def _make_handler() -> httpx.MockTransport:
    crtsh_body = json.dumps(
        [
            {
                "name_value": "chat.odingard.com\nagent.odingard.com\n*.odingard.com",
                "not_before": "2024-01-01T00:00:00",
            },
            {
                "name_value": "leaked-from-acquisition.evil.com",
                "not_before": "2023-06-01T00:00:00",
            },
        ]
    )
    hackertarget_body = "chat.odingard.com,1.2.3.4\nrag.odingard.com,9.9.9.9\n"
    wayback_body = json.dumps(
        [
            ["original", "timestamp"],
            ["http://chat.odingard.com/login", "20220101000000"],
            ["http://www.odingard.com/", "20210101000000"],
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "crt.sh" in url:
            return httpx.Response(200, text=crtsh_body)
        if "hackertarget.com" in url:
            return httpx.Response(200, text=hackertarget_body)
        if "web.archive.org" in url:
            return httpx.Response(200, text=wayback_body)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_discover_dedupes_across_sources_and_enforces_scope(tmp_path: Path) -> None:
    scope = load(_scope_file(tmp_path, "*.odingard.com\n"))
    transport = _make_handler()
    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        smap = await discover(scope, client=client)

    # In-scope hosts: chat / agent / rag / www.odingard.com
    assert sorted(smap.hosts) == [
        "agent.odingard.com",
        "chat.odingard.com",
        "rag.odingard.com",
        "www.odingard.com",
    ]
    # leaked-from-acquisition.evil.com is filtered out.
    assert "leaked-from-acquisition.evil.com" in smap.out_of_scope
    # Fingerprint count matches in-scope count exactly.
    assert len(smap.fingerprints) == len(smap.hosts)
    # No source errors on a clean run.
    assert smap.source_errors == ()


@pytest.mark.asyncio
async def test_discover_reports_source_errors_without_failing(tmp_path: Path) -> None:
    scope = load(_scope_file(tmp_path, "*.odingard.com\n"))

    def handler(request: httpx.Request) -> httpx.Response:
        if "crt.sh" in str(request.url):
            return httpx.Response(503)
        if "hackertarget.com" in str(request.url):
            return httpx.Response(200, text="chat.odingard.com,1.2.3.4\n")
        return httpx.Response(200, text=json.dumps([["original", "timestamp"]]))

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        smap = await discover(scope, client=client)

    assert smap.hosts == ("chat.odingard.com",)
    assert any(s == "crt.sh" for s, _, _ in smap.source_errors)


@pytest.mark.asyncio
async def test_to_json_ranks_by_score(tmp_path: Path) -> None:
    scope = load(_scope_file(tmp_path, "*.odingard.com\n"))
    transport = _make_handler()
    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        smap = await discover(scope, client=client)

    payload = smap.to_json()
    surfaces = [fp["surface"] for fp in payload["fingerprints"]]
    # agent ranks above chat ranks above rag ranks above unknown.
    assert surfaces.index("agent") < surfaces.index("chat")
    assert surfaces.index("chat") < surfaces.index("rag")
    assert surfaces.index("rag") < surfaces.index("unknown")
    assert payload["host_count"] == 4
    assert payload["out_of_scope_count"] == 1


@pytest.mark.asyncio
async def test_empty_scope_returns_empty_surface_map(tmp_path: Path) -> None:
    # A scope whose zones() is empty (only CIDRs) — the discover() path
    # still has to terminate cleanly.
    scope = load(_scope_file(tmp_path, "10.0.0.0/24\n"))
    transport = _make_handler()
    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        smap = await discover(scope, client=client)
    assert smap.hosts == ()
    assert smap.out_of_scope == ()
