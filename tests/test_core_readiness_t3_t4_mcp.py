"""Tests for Core readiness gaps: T3 (NDJSON), T4 (multipart), MCP Scanner.

T3: NDJSON/chunked stream reassembly — Ollama, vLLM, TGI, LiteLLM style.
T4: multipart/form-data payload support for file-upload attack surfaces.
MCP Scanner: dedicated MCP protocol-level scanning agent.
"""

from __future__ import annotations

import httpx

from argus.survey.prober import _parse_ndjson_to_text, build_multipart_fields

# ---------------------------------------------------------------------------
# T3: NDJSON Stream Reassembly
# ---------------------------------------------------------------------------


class TestT3NdjsonParsing:
    """T3 — newline-delimited JSON stream reassembly."""

    def test_ollama_style_response(self):
        """Ollama streams one JSON object per line with 'response' key."""
        raw = '{"response": "Hello"}\n{"response": " world"}\n{"done": true}\n'
        assert _parse_ndjson_to_text(raw) == "Hello world"

    def test_openai_style_choices_delta(self):
        """OpenAI-compatible NDJSON with choices[0].delta.content."""
        raw = '{"choices": [{"delta": {"content": "Hi"}}]}\n{"choices": [{"delta": {"content": " there"}}]}\n'
        assert _parse_ndjson_to_text(raw) == "Hi there"

    def test_generic_content_field(self):
        raw = '{"content": "A"}\n{"content": "B"}\n'
        assert _parse_ndjson_to_text(raw) == "AB"

    def test_generic_text_field(self):
        raw = '{"text": "one"}\n{"text": " two"}\n'
        assert _parse_ndjson_to_text(raw) == "one two"

    def test_generic_token_field(self):
        raw = '{"token": "tok1"}\n{"token": "tok2"}\n'
        assert _parse_ndjson_to_text(raw) == "tok1tok2"

    def test_generic_message_field(self):
        raw = '{"message": "full message"}\n'
        assert _parse_ndjson_to_text(raw) == "full message"

    def test_generic_output_field(self):
        raw = '{"output": "result"}\n'
        assert _parse_ndjson_to_text(raw) == "result"

    def test_done_frame_with_no_content_skipped(self):
        """Terminal frames with done=true and no content are skipped."""
        raw = '{"response": "Hello"}\n{"done": true}\n'
        assert _parse_ndjson_to_text(raw) == "Hello"

    def test_done_frame_with_content_not_skipped(self):
        """Terminal frame that has both done=true AND content should include the content."""
        raw = '{"response": "last", "done": true}\n'
        assert _parse_ndjson_to_text(raw) == "last"

    def test_empty_lines_ignored(self):
        raw = '{"response": "A"}\n\n{"response": "B"}\n\n'
        assert _parse_ndjson_to_text(raw) == "AB"

    def test_non_json_lines_ignored(self):
        raw = 'not json\n{"response": "valid"}\nalso not json\n'
        assert _parse_ndjson_to_text(raw) == "valid"

    def test_non_dict_json_ignored(self):
        raw = '[1, 2, 3]\n{"response": "ok"}\n"just a string"\n'
        assert _parse_ndjson_to_text(raw) == "ok"

    def test_empty_input_returns_empty(self):
        assert _parse_ndjson_to_text("") == ""

    def test_no_recognized_fields_returns_raw_prefix(self):
        raw = '{"unknown_key": "val"}\n'
        result = _parse_ndjson_to_text(raw)
        # Should return raw[:5000] since no parts were extracted
        assert result == raw[:5000]

    def test_choices_delta_text_field(self):
        """OpenAI choices with 'text' instead of 'content'."""
        raw = '{"choices": [{"delta": {"text": "alt"}}]}\n'
        assert _parse_ndjson_to_text(raw) == "alt"

    def test_mixed_providers(self):
        """Different NDJSON formats mixed (shouldn't happen but be resilient)."""
        raw = '{"response": "A"}\n{"content": "B"}\n{"text": "C"}\n'
        assert _parse_ndjson_to_text(raw) == "ABC"


# ---------------------------------------------------------------------------
# T3: Integration — prober and session handle NDJSON
# ---------------------------------------------------------------------------


async def test_prober_ndjson_content_type():
    """T3: prober detects application/x-ndjson and reassembles."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/chat" and request.method == "POST":
            body = '{"response": "Hello"}\n{"response": " NDJSON"}\n{"done": true}\n'
            return httpx.Response(
                200,
                text=body,
                headers={"content-type": "application/x-ndjson"},
            )
        return httpx.Response(404)

    from argus.survey.prober import EndpointProber

    transport = httpx.MockTransport(handler)
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    chat = next((d for d in report.discovered if d.path == "/chat"), None)
    assert chat is not None
    assert "Hello NDJSON" in (chat.response_text_snippet or "")


async def test_prober_ndjson_heuristic():
    """T3: prober detects NDJSON by heuristic when no content-type."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/chat" and request.method == "POST":
            body = '{"response": "first"}\n{"response": " second"}\n'
            return httpx.Response(200, text=body, headers={"content-type": ""})
        return httpx.Response(404)

    from argus.survey.prober import EndpointProber

    transport = httpx.MockTransport(handler)
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    chat = next((d for d in report.discovered if d.path == "/chat"), None)
    assert chat is not None
    assert "first second" in (chat.response_text_snippet or "")


async def test_session_ndjson_reassembly():
    """T3: ConversationSession.turn() reassembles NDJSON streams."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = '{"response": "Hello"}\n{"response": " from NDJSON"}\n{"done": true}\n'
        return httpx.Response(
            200,
            text=body,
            headers={"content-type": "application/x-ndjson"},
        )

    from argus.conductor import ConversationSession, TurnSpec

    transport = httpx.MockTransport(handler)
    async with ConversationSession(base_url="http://target.test", transport=transport) as session:
        result = await session.turn(TurnSpec(name="ndjson", path="/stream", body={"message": "hi"}))

    assert result.ok()
    assert "Hello from NDJSON" in result.response_text


# ---------------------------------------------------------------------------
# T4: Multipart Form-Data
# ---------------------------------------------------------------------------


class TestT4Multipart:
    """T4 — multipart/form-data payload construction."""

    def test_build_multipart_fields_default(self):
        result = build_multipart_fields("attack payload")
        assert "file" in result
        filename, content, mime = result["file"]
        assert filename == "payload.txt"
        assert content == b"attack payload"
        assert mime == "text/plain"

    def test_build_multipart_fields_custom_field(self):
        result = build_multipart_fields("payload", field_name="document")
        assert "document" in result
        assert "file" not in result

    def test_build_multipart_fields_unicode(self):
        result = build_multipart_fields("unicode: \u00e9\u00e8\u00ea")
        _, content, _ = result["file"]
        assert "unicode" in content.decode("utf-8")


async def test_session_multipart_upload():
    """T4: ConversationSession.turn() sends multipart when multipart_files set."""
    received_content_type = {}

    def handler(request: httpx.Request) -> httpx.Response:
        ct = request.headers.get("content-type", "")
        received_content_type["ct"] = ct
        return httpx.Response(200, json={"response": "file received"})

    from argus.conductor import ConversationSession, TurnSpec

    transport = httpx.MockTransport(handler)
    async with ConversationSession(base_url="http://target.test", transport=transport) as session:
        spec = TurnSpec(
            name="upload",
            path="/upload",
            body={"ignored": True},
            multipart_files={"file": ("test.txt", b"attack payload", "text/plain")},
            multipart_data={"description": "test upload"},
        )
        result = await session.turn(spec)

    assert result.ok()
    # Content-type should be multipart/form-data
    assert "multipart/form-data" in received_content_type.get("ct", "")


# ---------------------------------------------------------------------------
# MCP Scanner Agent
# ---------------------------------------------------------------------------


class TestMCPScannerAgent:
    """MCP Scanner agent registration and structure."""

    def test_agent_type_enum_exists(self):
        from argus.models.agents import AgentType

        assert hasattr(AgentType, "MCP_SCANNER")
        assert AgentType.MCP_SCANNER.value == "mcp_scanner"

    def test_agent_registered_in_registry(self):
        from argus.agents import AGENT_REGISTRY

        assert "mcp_scanner" in AGENT_REGISTRY

    def test_agent_class_structure(self):
        from argus.agents.mcp_scanner import MCPScannerAgent
        from argus.models.agents import AgentType

        assert MCPScannerAgent.agent_type == AgentType.MCP_SCANNER

    def test_agent_color_registered(self):
        from argus.models.agents import AgentType
        from argus.ui.colors import AGENT_COLORS

        assert AgentType.MCP_SCANNER in AGENT_COLORS

    def test_find_injectable_param_prefers_named(self):
        from argus.agents.mcp_scanner import MCPScannerAgent
        from argus.mcp_client.models import MCPTool, MCPToolParameter

        tool = MCPTool(
            name="test_tool",
            description="Test",
            parameters=[
                MCPToolParameter(name="id", type="integer", description="ID"),
                MCPToolParameter(name="query", type="string", description="Search query"),
                MCPToolParameter(name="limit", type="integer", description="Limit"),
            ],
        )
        assert MCPScannerAgent._find_injectable_param(tool) == "query"

    def test_find_injectable_param_falls_back_to_string(self):
        from argus.agents.mcp_scanner import MCPScannerAgent
        from argus.mcp_client.models import MCPTool, MCPToolParameter

        tool = MCPTool(
            name="test_tool",
            description="Test",
            parameters=[
                MCPToolParameter(name="custom_field", type="string", description="Custom"),
                MCPToolParameter(name="count", type="integer", description="Count"),
            ],
        )
        assert MCPScannerAgent._find_injectable_param(tool) == "custom_field"

    def test_find_injectable_param_none_when_no_params(self):
        from argus.agents.mcp_scanner import MCPScannerAgent
        from argus.mcp_client.models import MCPTool

        tool = MCPTool(name="no_params", description="Test", parameters=[])
        assert MCPScannerAgent._find_injectable_param(tool) is None

    def test_analyze_injection_response_detects_sensitive_data(self):
        from argus.agents.mcp_scanner import MCPScannerAgent

        result = MCPScannerAgent._analyze_injection_response(
            '{"data": "root:x:0:0:root:/root:/bin/bash"}',
            "test payload",
        )
        assert result is not None
        assert result["direct"] is True

    def test_analyze_injection_response_detects_cloud_metadata(self):
        from argus.agents.mcp_scanner import MCPScannerAgent

        # Output contains ami- and instance-id which are NOT in the payload
        result = MCPScannerAgent._analyze_injection_response(
            '{"instance": "ami-12345", "instance-id": "i-abc"}',
            "http://169.254.169.254/latest/meta-data/",
        )
        assert result is not None
        assert "ami-" in result["reason"] or "instance-id" in result["reason"]

    def test_analyze_injection_response_ssrf_echo_not_false_positive(self):
        """SSRF check should not flag when the tool just echoes the payload back."""
        from argus.agents.mcp_scanner import MCPScannerAgent

        result = MCPScannerAgent._analyze_injection_response(
            '{"error": "URL not allowed: http://169.254.169.254/latest/meta-data/"}',
            "http://169.254.169.254/latest/meta-data/",
        )
        # 169.254.169.254 is in the payload, so it should be excluded
        # No other SSRF indicators present, so result should be None
        assert result is None

    def test_analyze_injection_response_none_for_clean(self):
        from argus.agents.mcp_scanner import MCPScannerAgent

        result = MCPScannerAgent._analyze_injection_response(
            '{"status": "ok", "message": "Request processed"}',
            "test payload",
        )
        assert result is None

    def test_analyze_injection_response_detects_error_disclosure(self):
        from argus.agents.mcp_scanner import MCPScannerAgent

        result = MCPScannerAgent._analyze_injection_response(
            "Error: syntax error at line 5 in module.py",
            "test payload",
        )
        assert result is not None
        assert "Internal error disclosure" in result["reason"]
