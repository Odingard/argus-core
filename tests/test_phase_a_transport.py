"""Tests for Phase A transport layer gaps (T1, T2, T5, T6).

T1: HTML Response Filter — SPAs return HTML for all routes; agents must not
    treat HTML catch-all pages as AI responses.
T2: SSE Response Parsing — Real AI targets stream via text/event-stream;
    the parser must reassemble data: frames into coherent text.
T5: Response-Type Classification — DiscoveredEndpoint.content_type field.
T6: Body Format Negotiation — build_body_for_format() constructs the
    correct request body shape for each target format.
"""

from __future__ import annotations

import httpx

from argus.survey.prober import (
    DiscoveredEndpoint,
    EndpointProber,
    SurfaceClass,
    _is_html_catchall,
    _parse_sse_to_text,
    build_body_for_format,
    is_ai_response,
)

# ---------------------------------------------------------------------------
# T1: HTML Response Filter
# ---------------------------------------------------------------------------


class TestT1HtmlFilter:
    """T1 — HTML catch-all detection and filtering."""

    def test_html_doctype_detected(self):
        body = "<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>"
        assert _is_html_catchall("text/html", body) is True

    def test_html_tag_detected(self):
        body = "<html><head></head><body>SPA shell</body></html>"
        assert _is_html_catchall("text/html; charset=utf-8", body) is True

    def test_json_not_html(self):
        assert _is_html_catchall("application/json", '{"response": "hello"}') is False

    def test_plain_text_not_html(self):
        assert _is_html_catchall("text/plain", "Hello world") is False

    def test_html_content_type_without_html_body(self):
        # Some servers send text/html for non-HTML content
        assert _is_html_catchall("text/html", '{"response": "hi"}') is False

    def test_empty_body(self):
        assert _is_html_catchall("text/html", "") is False

    def test_is_ai_response_rejects_html(self):
        body = "<!DOCTYPE html><html><body>SPA</body></html>"
        assert is_ai_response("text/html", body) is False

    def test_is_ai_response_accepts_json(self):
        assert is_ai_response("application/json", '{"response": "hi"}') is True

    def test_is_ai_response_accepts_sse(self):
        assert is_ai_response("text/event-stream", "data: hello\n\n") is True

    def test_is_ai_response_accepts_plain_text(self):
        assert is_ai_response("text/plain", "I am an AI assistant") is True

    def test_discovered_endpoint_is_live_false_for_html_catchall(self):
        ep = DiscoveredEndpoint(
            base_url="http://t.test",
            path="/chat",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
            is_html_catchall=True,
        )
        assert not ep.is_live()

    def test_discovered_endpoint_is_live_true_for_json(self):
        ep = DiscoveredEndpoint(
            base_url="http://t.test",
            path="/chat",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
            is_html_catchall=False,
        )
        assert ep.is_live()


# ---------------------------------------------------------------------------
# T2: SSE Response Parsing
# ---------------------------------------------------------------------------


class TestT2SseParsing:
    """T2 — Server-Sent Events frame reassembly."""

    def test_openai_style_delta(self):
        raw = (
            'data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n'
            'data: {"choices": [{"delta": {"content": " world"}}]}\n\n'
            "data: [DONE]\n\n"
        )
        assert _parse_sse_to_text(raw) == "Hello world"

    def test_generic_content_field(self):
        raw = 'data: {"content": "Hi "}\n\ndata: {"content": "there"}\n\ndata: [DONE]\n\n'
        assert _parse_sse_to_text(raw) == "Hi there"

    def test_generic_text_field(self):
        raw = 'data: {"text": "Result A"}\n\ndata: {"text": " Result B"}\n\n'
        assert _parse_sse_to_text(raw) == "Result A Result B"

    def test_generic_token_field(self):
        raw = 'data: {"token": "tok1"}\n\ndata: {"token": "tok2"}\n\n'
        assert _parse_sse_to_text(raw) == "tok1tok2"

    def test_generic_message_field(self):
        raw = 'data: {"message": "Hello from SSE"}\n\n'
        assert _parse_sse_to_text(raw) == "Hello from SSE"

    def test_nested_data_key(self):
        raw = 'data: {"data": {"content": "nested value"}}\n\n'
        assert _parse_sse_to_text(raw) == "nested value"

    def test_raw_text_fallback(self):
        """When data: frames aren't JSON, concatenate raw values."""
        raw = "data: Hello\n\ndata: World\n\n"
        assert _parse_sse_to_text(raw) == "HelloWorld"

    def test_done_frame_ignored(self):
        raw = "data: partial\n\ndata: [DONE]\n\n"
        assert _parse_sse_to_text(raw) == "partial"

    def test_empty_data_ignored(self):
        raw = "data: \n\ndata: real\n\n"
        assert _parse_sse_to_text(raw) == "real"

    def test_non_data_lines_ignored(self):
        raw = "event: message\nid: 1\ndata: content\n\n"
        assert _parse_sse_to_text(raw) == "content"

    def test_no_data_frames_returns_raw_prefix(self):
        """If no data: lines at all, return first 5000 chars of raw."""
        raw = "not-sse-at-all: just garbage"
        result = _parse_sse_to_text(raw)
        assert result == raw[:5000]

    def test_openai_choices_with_text_field(self):
        raw = 'data: {"choices": [{"delta": {"text": "alt"}}]}\n\n'
        assert _parse_sse_to_text(raw) == "alt"

    def test_response_field(self):
        raw = 'data: {"response": "from response field"}\n\n'
        assert _parse_sse_to_text(raw) == "from response field"


# ---------------------------------------------------------------------------
# T5: Response-Type Classification
# ---------------------------------------------------------------------------


class TestT5ContentType:
    """T5 — content_type field on DiscoveredEndpoint."""

    def test_content_type_default_empty(self):
        ep = DiscoveredEndpoint(
            base_url="http://t.test",
            path="/chat",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
        )
        assert ep.content_type == ""

    def test_content_type_stored(self):
        ep = DiscoveredEndpoint(
            base_url="http://t.test",
            path="/chat",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
            content_type="application/json; charset=utf-8",
        )
        assert "application/json" in ep.content_type

    def test_content_type_sse(self):
        ep = DiscoveredEndpoint(
            base_url="http://t.test",
            path="/stream",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
            content_type="text/event-stream",
        )
        assert "text/event-stream" in ep.content_type


# ---------------------------------------------------------------------------
# T6: Body Format Negotiation
# ---------------------------------------------------------------------------


class TestT6BodyFormat:
    """T6 — build_body_for_format() constructs correct request bodies."""

    def test_message_format(self):
        body = build_body_for_format("hello", "message")
        assert body["message"] == "hello"
        assert "context" in body

    def test_openai_format(self):
        body = build_body_for_format("hello", "openai")
        assert body["model"] == "probe"
        assert body["messages"] == [{"role": "user", "content": "hello"}]

    def test_prompt_format(self):
        body = build_body_for_format("hello", "prompt")
        assert body == {"prompt": "hello"}

    def test_input_format(self):
        body = build_body_for_format("hello", "input")
        assert body == {"input": "hello"}

    def test_unknown_format_defaults_to_message(self):
        body = build_body_for_format("hello", "unknown_thing")
        assert body["message"] == "hello"

    def test_request_format_field_default(self):
        ep = DiscoveredEndpoint(
            base_url="http://t.test",
            path="/chat",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
        )
        assert ep.request_format == "message"

    def test_request_format_field_stored(self):
        ep = DiscoveredEndpoint(
            base_url="http://t.test",
            path="/v1/chat/completions",
            method="POST",
            surface_class=SurfaceClass.CHAT,
            status_code=200,
            request_format="openai",
        )
        assert ep.request_format == "openai"


# ---------------------------------------------------------------------------
# Integration: Prober captures T1/T2/T5/T6 fields
# ---------------------------------------------------------------------------


def _make_phase_a_transport() -> httpx.MockTransport:
    """Mock transport returning varied content types for Phase A testing."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path

        # JSON AI endpoint
        if path == "/chat" and request.method == "POST":
            return httpx.Response(
                200,
                json={"response": "I'm an AI"},
                headers={"content-type": "application/json"},
            )

        # SSE streaming endpoint
        if path == "/v1/chat/completions" and request.method == "POST":
            sse_body = (
                'data: {"choices": [{"delta": {"content": "streamed "}}]}\n\n'
                'data: {"choices": [{"delta": {"content": "response"}}]}\n\n'
                "data: [DONE]\n\n"
            )
            return httpx.Response(
                200,
                text=sse_body,
                headers={"content-type": "text/event-stream"},
            )

        # HTML SPA catch-all
        if path in ("/health", "/admin", "/memory", "/execute"):
            return httpx.Response(
                200,
                text="<!DOCTYPE html><html><body><div id='app'></div></body></html>",
                headers={"content-type": "text/html; charset=utf-8"},
            )

        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


async def test_prober_captures_content_type():
    """T5: content_type is populated from response headers."""
    transport = _make_phase_a_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    chat = next((d for d in report.discovered if d.path == "/chat"), None)
    assert chat is not None
    assert "application/json" in chat.content_type


async def test_prober_marks_html_catchall():
    """T1: HTML catch-all endpoints are flagged and excluded from by_surface."""
    transport = _make_phase_a_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    health = next((d for d in report.discovered if d.path == "/health"), None)
    assert health is not None
    assert health.is_html_catchall is True
    assert not health.is_live()

    # HTML catch-all endpoints should NOT appear in endpoints_for (by_surface)
    health_endpoints = report.endpoints_for(SurfaceClass.HEALTH)
    assert all(not e.is_html_catchall for e in health_endpoints)


async def test_prober_sse_endpoint_parsed():
    """T2: SSE endpoint snippet is reassembled from data: frames."""
    transport = _make_phase_a_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    sse_ep = next((d for d in report.discovered if d.path == "/v1/chat/completions"), None)
    assert sse_ep is not None
    assert "text/event-stream" in sse_ep.content_type
    # The snippet should contain reassembled text, not raw SSE frames
    assert "streamed response" in (sse_ep.response_text_snippet or "")


async def test_prober_json_endpoint_not_html_catchall():
    """JSON endpoints should not be marked as HTML catch-all."""
    transport = _make_phase_a_transport()
    prober = EndpointProber(base_url="http://target.test", transport=transport)
    report = await prober.probe_all()

    chat = next((d for d in report.discovered if d.path == "/chat"), None)
    assert chat is not None
    assert chat.is_html_catchall is False
    assert chat.is_live()


# ---------------------------------------------------------------------------
# Integration: ConversationSession handles SSE + HTML
# ---------------------------------------------------------------------------


async def test_session_sse_reassembly():
    """T2: ConversationSession.turn() reassembles SSE frames."""

    def handler(request: httpx.Request) -> httpx.Response:
        sse = (
            'data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n'
            'data: {"choices": [{"delta": {"content": " from SSE"}}]}\n\n'
            "data: [DONE]\n\n"
        )
        return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})

    from argus.conductor import ConversationSession, TurnSpec

    transport = httpx.MockTransport(handler)
    async with ConversationSession(base_url="http://target.test", transport=transport) as session:
        result = await session.turn(TurnSpec(name="sse", path="/stream", body={"message": "hi"}))

    assert result.ok()
    assert "Hello from SSE" in result.response_text


async def test_session_html_catchall_flags_error():
    """T1: ConversationSession.turn() sets error='html_response' for HTML catch-alls."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<!DOCTYPE html><html><body><div id='root'></div></body></html>",
            headers={"content-type": "text/html"},
        )

    from argus.conductor import ConversationSession, TurnSpec

    transport = httpx.MockTransport(handler)
    async with ConversationSession(base_url="http://target.test", transport=transport) as session:
        result = await session.turn(TurnSpec(name="html", path="/app", body={"message": "hi"}))

    assert result.error == "html_response"
