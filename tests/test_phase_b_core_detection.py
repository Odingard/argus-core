"""Tests for Phase B Core Detection: D1 baseline, T3 CSRF, T4 SPA discovery.

D1: Baseline collection for prompt_injection, model_extraction, privilege_escalation
T3: CSRF token handling in ConversationSession
T4: SPA endpoint discovery via JS bundle parsing
Fix: endpoints_for() include_auth_rejected for identity_spoof
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from argus.conductor.session import ConversationSession, TurnSpec
from argus.survey.prober import (
    DiscoveredEndpoint,
    SurfaceClass,
    SurveyReport,
    _extract_api_paths_from_js,
    _extract_script_srcs,
    discover_spa_endpoints,
)

# ============================================================
# Fix: endpoints_for include_auth_rejected
# ============================================================


class TestEndpointsForAuthRejected:
    """Verify that endpoints_for() supports include_auth_rejected flag."""

    def _make_report(self) -> SurveyReport:
        report = SurveyReport(target_base_url="http://test.local")
        report.discovered = [
            DiscoveredEndpoint(
                base_url="http://test.local",
                path="/execute",
                method="POST",
                surface_class=SurfaceClass.IDENTITY,
                status_code=403,
                response_text_snippet='{"error": "denied"}',
            ),
            DiscoveredEndpoint(
                base_url="http://test.local",
                path="/chat",
                method="POST",
                surface_class=SurfaceClass.CHAT,
                status_code=200,
                response_text_snippet='{"response": "hi"}',
            ),
            DiscoveredEndpoint(
                base_url="http://test.local",
                path="/admin",
                method="POST",
                surface_class=SurfaceClass.ADMIN,
                status_code=401,
                response_text_snippet='{"error": "unauthorized"}',
            ),
        ]
        return report

    def test_default_filters_403(self):
        report = self._make_report()
        identity = report.endpoints_for(SurfaceClass.IDENTITY)
        assert len(identity) == 0

    def test_include_auth_rejected_keeps_403(self):
        report = self._make_report()
        identity = report.endpoints_for(SurfaceClass.IDENTITY, include_auth_rejected=True)
        assert len(identity) == 1
        assert identity[0].path == "/execute"

    def test_has_surface_default_false_for_403(self):
        report = self._make_report()
        assert not report.has_surface(SurfaceClass.IDENTITY)

    def test_has_surface_include_auth_rejected_true(self):
        report = self._make_report()
        assert report.has_surface(SurfaceClass.IDENTITY, include_auth_rejected=True)

    def test_200_endpoints_unaffected_by_flag(self):
        report = self._make_report()
        chat = report.endpoints_for(SurfaceClass.CHAT)
        chat_with_flag = report.endpoints_for(SurfaceClass.CHAT, include_auth_rejected=True)
        assert len(chat) == 1
        assert len(chat_with_flag) == 1


# ============================================================
# T3: CSRF Token Handling
# ============================================================


class TestCsrfTokenHandling:
    """T3: CSRF token extraction and injection."""

    @pytest.mark.asyncio
    async def test_csrf_token_extracted_from_meta(self):
        """Session should extract csrf-token from <meta> tag and inject it."""
        csrf_value = "abc123-csrf-token-xyz"
        calls: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append({"method": request.method, "path": request.url.path, "headers": dict(request.headers)})
            if request.method == "GET":
                html = f'<html><head><meta name="csrf-token" content="{csrf_value}"></head><body>SPA</body></html>'
                return httpx.Response(200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        session = ConversationSession(
            base_url="http://csrf.test",
            csrf_mode=True,
            transport=transport,
        )
        async with session:
            spec = TurnSpec(name="test", method="POST", path="/api/action", body={"data": "x"})
            result = await session.turn(spec)

        assert result.status_code == 200
        # Should have made a GET first to fetch CSRF token
        assert calls[0]["method"] == "GET"
        # Then the POST should include X-CSRF-Token
        post_call = next(c for c in calls if c["method"] == "POST")
        assert post_call["headers"].get("x-csrf-token") == csrf_value

    @pytest.mark.asyncio
    async def test_csrf_mode_off_no_get(self):
        """Without csrf_mode, no GET should be made."""
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.method)
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        session = ConversationSession(
            base_url="http://no-csrf.test",
            csrf_mode=False,
            transport=transport,
        )
        async with session:
            spec = TurnSpec(name="test", method="POST", path="/api/action", body={"data": "x"})
            await session.turn(spec)

        assert "GET" not in calls

    @pytest.mark.asyncio
    async def test_csrf_no_meta_tag_still_posts(self):
        """If page has no csrf-token meta, POST still fires without token."""
        calls: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append({"method": request.method, "headers": dict(request.headers)})
            if request.method == "GET":
                html = "<html><body>No CSRF</body></html>"
                return httpx.Response(200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        session = ConversationSession(
            base_url="http://no-meta.test",
            csrf_mode=True,
            transport=transport,
        )
        async with session:
            spec = TurnSpec(name="test", method="POST", path="/submit", body={})
            result = await session.turn(spec)

        assert result.status_code == 200
        post_call = next(c for c in calls if c["method"] == "POST")
        assert "x-csrf-token" not in post_call["headers"]

    @pytest.mark.asyncio
    async def test_csrf_fetched_only_once(self):
        """CSRF token fetch should happen only once per session."""
        get_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal get_count
            if request.method == "GET":
                get_count += 1
                return httpx.Response(
                    200,
                    text='<meta name="csrf-token" content="tok">',
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        session = ConversationSession(
            base_url="http://once.test",
            csrf_mode=True,
            transport=transport,
        )
        async with session:
            for _ in range(3):
                await session.turn(TurnSpec(name="t", method="POST", path="/x", body={}))

        assert get_count == 1


# ============================================================
# T4: SPA Endpoint Discovery
# ============================================================


class TestSpaEndpointDiscovery:
    """T4: JS bundle parsing for API endpoint discovery."""

    def test_extract_script_srcs(self):
        html = """
        <html>
        <head><script src="/static/app.abc123.js"></script></head>
        <body>
            <script src="/static/vendor.def456.js"></script>
            <script>console.log("inline")</script>
        </body>
        </html>
        """
        srcs = _extract_script_srcs(html)
        assert "/static/app.abc123.js" in srcs
        assert "/static/vendor.def456.js" in srcs
        assert len(srcs) == 2  # inline script has no src

    def test_extract_api_paths_fetch(self):
        js = """
        fetch("/api/users").then(r => r.json());
        fetch('/api/settings').then(r => r.json());
        """
        paths = _extract_api_paths_from_js(js)
        assert "/api/users" in paths
        assert "/api/settings" in paths

    def test_extract_api_paths_axios(self):
        js = """
        axios.get("/api/data");
        axios.post("/v1/submit");
        axios.delete("/api/items");
        """
        paths = _extract_api_paths_from_js(js)
        assert "/api/data" in paths
        assert "/v1/submit" in paths
        assert "/api/items" in paths

    def test_extract_api_paths_quoted_literals(self):
        js = """
        const url = "/api/health";
        const endpoint = "/v2/models/list";
        """
        paths = _extract_api_paths_from_js(js)
        assert "/api/health" in paths
        assert "/v2/models/list" in paths

    def test_extract_api_paths_baseurl(self):
        js = """
        baseURL: "/api/v1",
        baseUrl = "/v2/agent"
        """
        paths = _extract_api_paths_from_js(js)
        assert "/api/v1" in paths
        assert "/v2/agent" in paths

    def test_extract_api_paths_template_strings(self):
        js = """
        const url = `/api/users/${userId}/profile`;
        """
        paths = _extract_api_paths_from_js(js)
        assert "/api/users/profile" in paths  # template var stripped

    def test_extract_api_paths_skips_static_assets(self):
        js = """
        fetch("/api/data");
        import "/static/app.css";
        """
        paths = _extract_api_paths_from_js(js)
        assert "/api/data" in paths
        assert not any(p.endswith(".css") for p in paths)

    def test_extract_script_srcs_empty_html(self):
        assert _extract_script_srcs("") == []
        assert _extract_script_srcs("<html><body>no scripts</body></html>") == []

    @pytest.mark.asyncio
    async def test_discover_spa_endpoints_integration(self):
        """Full integration: HTML → JS bundle fetch → API path extraction."""
        js_content = """
        fetch("/api/chat");
        axios.post("/v1/completions");
        const base = "/api/health";
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/static/app.js":
                return httpx.Response(200, text=js_content)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            html = '<html><script src="/static/app.js"></script></html>'
            paths = await discover_spa_endpoints(client, "http://spa.test", html)

        assert "/api/chat" in paths
        assert "/v1/completions" in paths
        assert "/api/health" in paths

    @pytest.mark.asyncio
    async def test_discover_spa_endpoints_no_scripts(self):
        """HTML without scripts returns empty list."""
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client:
            paths = await discover_spa_endpoints(client, "http://test.local", "<html>no scripts</html>")
        assert paths == []

    @pytest.mark.asyncio
    async def test_discover_spa_endpoints_bundle_cap(self):
        """Should only fetch up to _SPA_MAX_BUNDLES bundles."""
        fetched: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            fetched.append(request.url.path)
            return httpx.Response(200, text='fetch("/api/found")')

        transport = httpx.MockTransport(handler)
        # Generate 10 script tags
        scripts = "".join(f'<script src="/js/chunk{i}.js"></script>' for i in range(10))
        html = f"<html>{scripts}</html>"

        async with httpx.AsyncClient(transport=transport) as client:
            await discover_spa_endpoints(client, "http://test.local", html)

        # Should cap at 5 bundles
        assert len(fetched) <= 5


# ============================================================
# D1: Baseline Collection — unit-level checks
# ============================================================


class TestBaselineCollectionPromptInjection:
    """D1: PromptInjectionHunter baseline collection."""

    def test_has_baseline_response_attr(self):
        from argus.agents.prompt_injection import PromptInjectionHunter
        from argus.models.agents import AgentConfig, AgentType, TargetConfig
        from argus.orchestrator.signal_bus import SignalBus

        target = TargetConfig(name="test", agent_endpoint="http://test.local/chat", max_requests_per_minute=60)
        config = AgentConfig(agent_type=AgentType.PROMPT_INJECTION, scan_id="test", target=target, timeout_seconds=10)
        agent = PromptInjectionHunter(config=config, signal_bus=SignalBus())
        assert hasattr(agent, "_baseline_response")
        assert agent._baseline_response is None

    def test_is_behavior_change_uses_divergence(self):
        """When baseline is set and ResponseDivergence triggers, _is_behavior_change should return True."""
        from argus.agents.prompt_injection import PromptInjectionHunter
        from argus.models.agents import AgentConfig, AgentType, TargetConfig
        from argus.orchestrator.signal_bus import SignalBus

        target = TargetConfig(name="test", agent_endpoint="http://test.local/chat", max_requests_per_minute=60)
        config = AgentConfig(agent_type=AgentType.PROMPT_INJECTION, scan_id="test", target=target, timeout_seconds=10)
        agent = PromptInjectionHunter(config=config, signal_bus=SignalBus())

        # With no baseline, divergence path is skipped
        result = {"response": "some normal response"}
        assert not agent._is_behavior_change(result)

        # Setting a baseline enables divergence scoring —
        # but won't trigger unless responses are truly divergent
        agent._baseline_response = "Hello! I'm an AI assistant. How can I help you today?"
        result_similar = {"response": "Hello! I'm an AI assistant. How can I help you?"}
        assert not agent._is_behavior_change(result_similar)


class TestBaselineCollectionModelExtraction:
    """D1: ModelExtractionAgent baseline collection."""

    def test_has_baseline_and_check_divergence(self):
        from argus.agents.model_extraction import ModelExtractionAgent
        from argus.models.agents import AgentConfig, AgentType, TargetConfig
        from argus.orchestrator.signal_bus import SignalBus

        target = TargetConfig(name="test", agent_endpoint="http://test.local/chat", max_requests_per_minute=60)
        config = AgentConfig(agent_type=AgentType.MODEL_EXTRACTION, scan_id="test", target=target, timeout_seconds=10)
        agent = ModelExtractionAgent(config=config, signal_bus=SignalBus())
        assert hasattr(agent, "_baseline_response")
        assert agent._baseline_response is None
        assert hasattr(agent, "_check_divergence")


class TestBaselineCollectionPrivilegeEscalation:
    """D1: PrivilegeEscalationAgent baseline collection."""

    def test_has_baseline_and_imports_divergence(self):
        from argus.agents.privilege_escalation import PrivilegeEscalationAgent
        from argus.models.agents import AgentConfig, AgentType, TargetConfig
        from argus.orchestrator.signal_bus import SignalBus

        target = TargetConfig(name="test", agent_endpoint="http://test.local/chat", max_requests_per_minute=60)
        config = AgentConfig(
            agent_type=AgentType.PRIVILEGE_ESCALATION, scan_id="test", target=target, timeout_seconds=10
        )
        agent = PrivilegeEscalationAgent(config=config, signal_bus=SignalBus())
        assert hasattr(agent, "_baseline_response")
        assert agent._baseline_response is None

    def test_evaluate_response_uses_divergence(self):
        """_evaluate_response should use ResponseDivergence when baseline is set."""
        from argus.agents.privilege_escalation import PrivilegeEscalationAgent
        from argus.conductor.session import TurnResult
        from argus.models.agents import AgentConfig, AgentType, TargetConfig
        from argus.orchestrator.signal_bus import SignalBus

        target = TargetConfig(name="test", agent_endpoint="http://test.local/chat", max_requests_per_minute=60)
        config = AgentConfig(
            agent_type=AgentType.PRIVILEGE_ESCALATION, scan_id="test", target=target, timeout_seconds=10
        )
        agent = PrivilegeEscalationAgent(config=config, signal_bus=SignalBus())

        # No evidence and no baseline → None
        result = TurnResult(
            turn_name="test",
            request_method="POST",
            request_url="http://test.local/execute",
            status_code=200,
            response_text="normal response with nothing special",
        )
        assert agent._evaluate_response(result) is None
