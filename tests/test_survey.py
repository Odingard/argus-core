"""Tests for SURVEY — AI agent attack surface mapper."""

from __future__ import annotations

import httpx
import pytest

from argus.survey import (
    CapabilityMapper,
    EndpointProber,
    SurfaceClass,
    SurveyReport,
)


def make_target_transport() -> httpx.MockTransport:
    """A fake target that exposes a subset of common AI agent endpoints."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        # Health
        if path == "/health" and method == "GET":
            return httpx.Response(200, json={"status": "ok"})
        # Chat — only /chat exists, the others 404
        if path == "/chat" and method == "POST":
            return httpx.Response(200, json={"response": "hi", "session_id": "x"})
        # Memory
        if path == "/memory" and method == "GET":
            return httpx.Response(200, json={"entries": []})
        # Identity
        if path == "/execute" and method == "POST":
            return httpx.Response(200, json={"trust_granted": False})
        # Exfil log (the kind benchmark scenarios expose)
        if path == "/exfil-log" and method == "GET":
            return httpx.Response(200, json={"exfil_events": []})
        # Everything else: not found
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


async def test_prober_discovers_live_endpoints():
    transport = make_target_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    # The 5 endpoints we serve should all be live
    live_paths = [d.path for d in report.discovered if d.is_live()]
    assert "/health" in live_paths
    assert "/chat" in live_paths
    assert "/memory" in live_paths
    assert "/execute" in live_paths
    assert "/exfil-log" in live_paths


async def test_prober_classifies_by_surface():
    transport = make_target_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    assert report.has_surface(SurfaceClass.CHAT)
    assert report.has_surface(SurfaceClass.MEMORY)
    assert report.has_surface(SurfaceClass.IDENTITY)
    assert report.has_surface(SurfaceClass.EXFILTRATION)
    assert report.has_surface(SurfaceClass.HEALTH)
    # We did not stub /tools, /admin, /agents
    assert not report.has_surface(SurfaceClass.TOOLS)
    assert not report.has_surface(SurfaceClass.ADMIN)


async def test_prober_marks_404_as_dead():
    transport = make_target_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    # /admin returned 404 — should be in discovered list but is_live() False
    admin = next(d for d in report.discovered if d.path == "/admin")
    assert admin.status_code == 404
    assert not admin.is_live()


async def test_prober_handles_connection_errors():
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    transport = httpx.MockTransport(fail)
    prober = EndpointProber(base_url="http://dead.test", transport=transport)
    report = await prober.probe_all()

    # All discoveries should be dead with errors set
    assert all(not d.is_live() for d in report.discovered)
    assert all(d.error is not None for d in report.discovered)


def test_prober_rejects_non_http_base():
    with pytest.raises(ValueError, match="must be http"):
        EndpointProber(base_url="ftp://target")


async def test_capability_mapper_routes_endpoints_to_phase2_agents():
    transport = make_target_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    routing = CapabilityMapper.map_for_phase2(report)

    # Memory poisoning gets MEMORY + CHAT
    mem_paths = {e.path for e in routing["memory_poisoning"]}
    assert "/memory" in mem_paths
    assert "/chat" in mem_paths

    # Identity spoof gets the /execute surface
    id_paths = {e.path for e in routing["identity_spoof"]}
    assert "/execute" in id_paths

    # Exfil recon collects observability surfaces
    exfil_paths = {e.path for e in routing["exfiltration_recon"]}
    assert "/exfil-log" in exfil_paths


def test_survey_report_filtering():
    report = SurveyReport(target_base_url="http://t.test")
    # Build manually
    from argus.survey.prober import DiscoveredEndpoint

    report.discovered = [
        DiscoveredEndpoint(
            base_url="http://t.test",
            path="/chat",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
        ),
        DiscoveredEndpoint(
            base_url="http://t.test",
            path="/admin",
            method="GET",
            surface_class=SurfaceClass.ADMIN,
            status_code=404,
        ),
    ]
    assert len(report.endpoints_for(SurfaceClass.CHAT)) == 1
    assert len(report.endpoints_for(SurfaceClass.ADMIN)) == 0  # 404 = not live
    assert report.has_surface(SurfaceClass.CHAT)
    assert not report.has_surface(SurfaceClass.ADMIN)
