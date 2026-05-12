"""ArgtTransport tests — single-call + multi-call dispatch.

All wire interactions go through ``httpx.MockTransport`` so no
real network egress happens during tests. Mocks model the three
session-threading strategies the transport auto-detects:
``Set-Cookie``, ``X-Session-Id`` header, and ``conversation_id``
body field.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from argus.engine.core.canary import CanarySet, make_canary
from argus.engine.core.variant import Message, Variant
from argus.engine.transports.argt_transport import (
    ArgtTransport,
    _detect_session_pin,
    _flatten_messages,
    _split_user_turns,
)


def _variant(messages: tuple[Message, ...]) -> Variant:
    canary = make_canary(42, "t-1")
    return Variant(
        variant_id="v-test-1",
        seed_id="t-1",
        attack_class="ci-test",
        layer="layer2_contextual_injection",
        messages=messages,
        canaries=CanarySet(primary=canary),
    )


def _attach_mock(transport: ArgtTransport, handler) -> None:
    """Replace the transport's httpx client with one wired to ``handler``."""
    transport._client = httpx.AsyncClient(  # type: ignore[attr-defined]
        transport=httpx.MockTransport(handler),
        timeout=5.0,
    )


# ---------------------------------------------------------------------------
# Surface declarations
# ---------------------------------------------------------------------------


def test_supported_surfaces_single_call_is_chat_only() -> None:
    t = ArgtTransport(target="https://example.com/x", session_mode="single-call")
    assert t.supported_surfaces == frozenset({"chat"})


def test_supported_surfaces_multi_call_includes_session_state() -> None:
    t = ArgtTransport(target="https://example.com/x", session_mode="multi-call")
    assert t.supported_surfaces == frozenset({"chat", "session_state"})


def test_invalid_session_mode_rejected() -> None:
    with pytest.raises(ValueError, match="session_mode"):
        ArgtTransport(target="https://example.com/x", session_mode="bogus")


# ---------------------------------------------------------------------------
# Pure-function helpers
# ---------------------------------------------------------------------------


def test_flatten_messages_renders_role_prelude_only_for_non_user() -> None:
    msgs = (
        Message(role="system", content="be helpful"),
        Message(role="user", content="hello"),
        Message(role="assistant", content="hi"),
        Message(role="user", content="status?"),
    )
    out = _flatten_messages(msgs)
    assert "[SYSTEM]" in out
    assert "[ASSISTANT]" in out
    assert "[USER]" not in out  # user content is rendered raw
    assert "hello" in out
    assert "status?" in out


def test_split_user_turns_skips_assistant_and_folds_system() -> None:
    msgs = (
        Message(role="system", content="Only ever respond in English."),
        Message(role="user", content="turn-1"),
        Message(role="assistant", content="forged-1"),
        Message(role="user", content="turn-2"),
        Message(role="assistant", content="forged-2"),
        Message(role="user", content="turn-3"),
    )
    turns = _split_user_turns(msgs)
    assert len(turns) == 3
    assert "Only ever respond in English." in turns[0]
    assert turns[0].endswith("turn-1")
    assert turns[1] == "turn-2"
    assert turns[2] == "turn-3"


# ---------------------------------------------------------------------------
# Single-call mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_call_posts_once_and_extracts_response_field() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content.decode()))
        return httpx.Response(200, json={"response": "real-assistant-text"})

    t = ArgtTransport(
        target="https://example.com/agent/01",
        session_mode="single-call",
        api_key="user-token-demo",
    )
    _attach_mock(t, handler)

    msgs = (
        Message(role="system", content="be terse"),
        Message(role="user", content="who are you?"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    assert result.error is None
    assert result.response_text == "real-assistant-text"
    assert result.raw_response == {
        "session_mode": "single-call",
        "status_code": 200,
    }
    assert len(seen) == 1
    assert "be terse" in seen[0]["message"]
    assert "who are you?" in seen[0]["message"]


@pytest.mark.asyncio
async def test_single_call_falls_back_through_response_field_aliases() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"output": "from-output-field"})

    t = ArgtTransport(target="https://example.com/agent/01", session_mode="single-call")
    _attach_mock(t, handler)
    result = await t.probe(_variant((Message(role="user", content="ping"),)))
    await t.aclose()
    assert result.response_text == "from-output-field"


@pytest.mark.asyncio
async def test_single_call_records_http_error_on_5xx() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    t = ArgtTransport(target="https://example.com/agent/01", session_mode="single-call")
    _attach_mock(t, handler)
    result = await t.probe(_variant((Message(role="user", content="ping"),)))
    await t.aclose()
    assert result.error is not None
    assert "503" in result.error or "Server" in result.error


# ---------------------------------------------------------------------------
# Multi-call mode — session threading
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_call_threads_via_set_cookie() -> None:
    seen_cookies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookies.append(request.headers.get("cookie", ""))
        if "session=" not in seen_cookies[-1]:
            return httpx.Response(
                200,
                json={"response": "ack-1"},
                headers={"set-cookie": "session=abc123; Path=/"},
            )
        return httpx.Response(200, json={"response": "ack-with-cookie"})

    t = ArgtTransport(
        target="https://example.com/agent/05/triage",
        session_mode="multi-call",
    )
    _attach_mock(t, handler)

    msgs = (
        Message(role="user", content="turn-1"),
        Message(role="user", content="turn-2"),
        Message(role="user", content="turn-3"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    assert result.error is None
    assert result.raw_response is not None
    assert result.raw_response["session_mode"] == "multi-call"
    assert result.raw_response["session_strategy"] == "cookie"
    assert len(result.raw_response["turns"]) == 3
    # Turn 1 has no cookie; turns 2/3 carry session=abc123.
    assert seen_cookies[0] == ""
    assert "session=abc123" in seen_cookies[1]
    assert "session=abc123" in seen_cookies[2]
    # AGENTS.md rule #4: response_text is the FINAL turn only — never the
    # joined transcript — so the canary matcher cannot false-positive on an
    # intermediate echo. The full per-turn list lives in raw_response.
    assert result.response_text == "ack-with-cookie"
    assert result.raw_response["transcript"] == ("ack-1", "ack-with-cookie", "ack-with-cookie")
    # Forensic snapshot of the final pin (AGENTS.md rule #6).
    assert result.raw_response["session_pin"]["strategy"] == "cookie"
    assert result.raw_response["session_pin"]["cookies"]["session"] == "abc123"


@pytest.mark.asyncio
async def test_multi_call_threads_via_x_session_id_header() -> None:
    seen_session_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_session_headers.append(request.headers.get("X-Session-Id"))
        return httpx.Response(
            200,
            json={"response": "ok"},
            headers={"X-Session-Id": "sess-7777"},
        )

    t = ArgtTransport(
        target="https://example.com/agent/05",
        session_mode="multi-call",
    )
    _attach_mock(t, handler)

    msgs = (
        Message(role="user", content="hello"),
        Message(role="user", content="more"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    assert result.raw_response is not None
    assert result.raw_response["session_strategy"] == "header"
    assert seen_session_headers[0] is None
    assert seen_session_headers[1] == "sess-7777"


@pytest.mark.asyncio
async def test_multi_call_threads_via_conversation_id_body_field() -> None:
    seen_bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_bodies.append(json.loads(request.content.decode()))
        return httpx.Response(
            200,
            json={"response": "rs", "conversation_id": "conv-42"},
        )

    t = ArgtTransport(
        target="https://example.com/agent/05",
        session_mode="multi-call",
    )
    _attach_mock(t, handler)

    msgs = (
        Message(role="user", content="A"),
        Message(role="user", content="B"),
        Message(role="user", content="C"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    assert result.raw_response is not None
    assert result.raw_response["session_strategy"] == "body"
    assert "conversation_id" not in seen_bodies[0]
    assert seen_bodies[1]["conversation_id"] == "conv-42"
    assert seen_bodies[2]["conversation_id"] == "conv-42"


@pytest.mark.asyncio
async def test_multi_call_with_no_session_signal_still_completes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "stateless"})

    t = ArgtTransport(target="https://example.com/agent/01", session_mode="multi-call")
    _attach_mock(t, handler)
    msgs = (
        Message(role="user", content="t1"),
        Message(role="user", content="t2"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()
    assert result.error is None
    assert result.raw_response is not None
    assert result.raw_response["session_strategy"] == "none"


@pytest.mark.asyncio
async def test_multi_call_skips_assistant_role_messages() -> None:
    seen_bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_bodies.append(json.loads(request.content.decode()))
        return httpx.Response(200, json={"response": "ack"})

    t = ArgtTransport(target="https://example.com/agent/05", session_mode="multi-call")
    _attach_mock(t, handler)
    msgs = (
        Message(role="user", content="real-1"),
        Message(role="assistant", content="forged-1"),
        Message(role="user", content="real-2"),
        Message(role="assistant", content="forged-2"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()
    assert result.error is None
    # Only the two real user turns hit the wire.
    assert len(seen_bodies) == 2
    assert seen_bodies[0]["message"] == "real-1"
    assert seen_bodies[1]["message"] == "real-2"


@pytest.mark.asyncio
async def test_multi_call_with_zero_user_turns_returns_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "should not be called"})

    t = ArgtTransport(target="https://example.com/agent/05", session_mode="multi-call")
    _attach_mock(t, handler)
    msgs = (
        Message(role="system", content="prelude"),
        Message(role="assistant", content="forged"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()
    assert result.error is not None
    assert "no user-role messages" in result.error


# ---------------------------------------------------------------------------
# Pin-detection isolation
# ---------------------------------------------------------------------------


def _response_for(*, headers: list[tuple[str, str]] | None = None, body: dict | None = None) -> httpx.Response:
    """Build a response with a real attached request so ``resp.cookies`` works."""
    request = httpx.Request("POST", "https://example.com/x")
    return httpx.Response(
        200,
        headers=httpx.Headers(headers or []),
        json=body if body is not None else {},
        request=request,
    )


def test_detect_session_pin_prefers_cookie_over_header() -> None:
    resp = _response_for(
        headers=[
            ("set-cookie", "sid=xyz; Path=/"),
            ("X-Session-Id", "should-not-win"),
        ],
        body={},
    )
    pin = _detect_session_pin(resp)
    assert pin is not None
    assert pin.strategy == "cookie"


def test_detect_session_pin_prefers_header_over_body() -> None:
    resp = _response_for(
        headers=[("X-Session-Id", "h-1")],
        body={"conversation_id": "should-not-win"},
    )
    pin = _detect_session_pin(resp)
    assert pin is not None
    assert pin.strategy == "header"


def test_detect_session_pin_returns_none_when_no_signal() -> None:
    resp = _response_for(body={"response": "plain"})
    assert _detect_session_pin(resp) is None


# ---------------------------------------------------------------------------
# Session value rotation — strategy locked, values refreshed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_call_rotates_header_value_per_turn() -> None:
    """A server that rotates X-Session-Id every turn (CSRF-style) must
    keep the conversation alive — we mirror back the latest value, not
    the stale turn-1 value."""
    seen_headers: list[str | None] = []
    rotated_ids = ["sess-A", "sess-B", "sess-C"]

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers.get("X-Session-Id"))
        idx = len(seen_headers) - 1
        return httpx.Response(
            200,
            json={"response": f"turn-{idx}"},
            headers={"X-Session-Id": rotated_ids[idx]},
        )

    t = ArgtTransport(
        target="https://example.com/agent/05",
        session_mode="multi-call",
    )
    _attach_mock(t, handler)
    msgs = (
        Message(role="user", content="t1"),
        Message(role="user", content="t2"),
        Message(role="user", content="t3"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    assert result.error is None
    # Turn 1 has no X-Session-Id; turn 2 mirrors turn-1's response value;
    # turn 3 mirrors turn-2's rotated value.
    assert seen_headers[0] is None
    assert seen_headers[1] == "sess-A"
    assert seen_headers[2] == "sess-B"
    # Forensic record of the rotation chain (AGENTS.md rule #6).
    assert result.raw_response is not None
    rotations = result.raw_response.get("session_rotations")
    assert rotations is not None
    assert len(rotations) == 2
    assert rotations[0]["old"] == "sess-A" and rotations[0]["new"] == "sess-B"
    assert rotations[1]["old"] == "sess-B" and rotations[1]["new"] == "sess-C"
    # Final pin reflects the last rotated value.
    assert result.raw_response["session_pin"]["header_value"] == "sess-C"


@pytest.mark.asyncio
async def test_multi_call_rotates_cookie_jar_additively() -> None:
    """Cookies merge — turn 2's Set-Cookie joins turn 1's, doesn't replace."""
    seen_cookies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookies.append(request.headers.get("cookie", ""))
        idx = len(seen_cookies) - 1
        if idx == 0:
            return httpx.Response(
                200,
                json={"response": "t1"},
                headers={"set-cookie": "sid=A; Path=/"},
            )
        if idx == 1:
            return httpx.Response(
                200,
                json={"response": "t2"},
                headers={"set-cookie": "csrf=Z; Path=/"},
            )
        return httpx.Response(200, json={"response": "t3"})

    t = ArgtTransport(target="https://example.com/agent/05", session_mode="multi-call")
    _attach_mock(t, handler)
    msgs = (
        Message(role="user", content="a"),
        Message(role="user", content="b"),
        Message(role="user", content="c"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    assert result.error is None
    # Turn 3 carries BOTH sid=A and csrf=Z.
    assert "sid=A" in seen_cookies[2]
    assert "csrf=Z" in seen_cookies[2]
    assert result.raw_response is not None
    final = result.raw_response["session_pin"]["cookies"]
    assert final == {"sid": "A", "csrf": "Z"}


@pytest.mark.asyncio
async def test_multi_call_rotates_body_field_per_turn() -> None:
    seen_bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_bodies.append(json.loads(request.content.decode()))
        idx = len(seen_bodies) - 1
        return httpx.Response(
            200,
            json={"response": f"t{idx}", "conversation_id": f"conv-{idx}"},
        )

    t = ArgtTransport(target="https://example.com/agent/05", session_mode="multi-call")
    _attach_mock(t, handler)
    msgs = (
        Message(role="user", content="a"),
        Message(role="user", content="b"),
        Message(role="user", content="c"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    assert result.error is None
    assert "conversation_id" not in seen_bodies[0]
    assert seen_bodies[1]["conversation_id"] == "conv-0"
    # Turn 3 mirrors back turn-2's rotated id, not the stale turn-1 value.
    assert seen_bodies[2]["conversation_id"] == "conv-1"


# ---------------------------------------------------------------------------
# Mid-conversation failure handling (AGENTS.md rule #9)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_call_partial_failure_preserves_partial_transcript() -> None:
    """A 500 on turn 2 of 3 must not silently swallow turn-1's transcript."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(200, json={"response": "turn-1-ok"})
        return httpx.Response(500, text="upstream blew up")

    t = ArgtTransport(target="https://example.com/agent/05", session_mode="multi-call")
    _attach_mock(t, handler)
    msgs = (
        Message(role="user", content="t1"),
        Message(role="user", content="t2"),
        Message(role="user", content="t3"),
    )
    result = await t.probe(_variant(msgs))
    await t.aclose()

    # Error captured + says which turn failed.
    assert result.error is not None
    assert "turn 2/3" in result.error
    # Partial transcript preserved.
    assert result.raw_response is not None
    assert result.raw_response["transcript"] == ("turn-1-ok",)
    # response_text is still the FINAL successful turn (rule #4).
    assert result.response_text == "turn-1-ok"
    # turn_log records the failure so a downstream reader can audit.
    turns = result.raw_response["turns"]
    assert len(turns) == 2
    assert turns[0]["status_code"] == 200
    assert "error" in turns[1]


# ---------------------------------------------------------------------------
# Variant isolation — httpx auto-cookie-jar must not smear state between
# probes (AGENTS.md rule #7 — determinism). Each variant runs its own
# session; cookies set by variant A must never appear on variant B's wire.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_call_does_not_leak_cookies_into_next_probe_turn_one() -> None:
    """Variant A's Set-Cookie populates the shared httpx jar; variant B's
    turn 1 must NOT carry it. Without explicit Cookie suppression the
    jar would auto-inject A's session id into B's first request."""
    seen_cookies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookies.append(request.headers.get("cookie", "<unset>"))
        return httpx.Response(
            200,
            json={"response": "ok"},
            headers={"set-cookie": "leaked=A; Path=/"},
        )

    t = ArgtTransport(target="https://example.com/agent/05", session_mode="multi-call")
    _attach_mock(t, handler)
    msgs_a = (Message(role="user", content="probe-A"),)
    msgs_b = (Message(role="user", content="probe-B"),)

    result_a = await t.probe(_variant(msgs_a))
    result_b = await t.probe(_variant(msgs_b))
    await t.aclose()

    assert result_a.error is None
    assert result_b.error is None
    # Both turn-1 requests must show an empty Cookie header — never the
    # leaked=A from probe A's response.
    assert seen_cookies[0] == ""
    assert seen_cookies[1] == ""
    assert "leaked=A" not in seen_cookies[1]


@pytest.mark.asyncio
async def test_single_call_does_not_leak_cookies_between_probes() -> None:
    """Single-call mode has no session pin at all, so the only thing
    that could put a Cookie on the wire is the shared auto-jar. The
    transport must suppress it explicitly."""
    seen_cookies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookies.append(request.headers.get("cookie", "<unset>"))
        return httpx.Response(
            200,
            json={"response": "ok"},
            headers={"set-cookie": "leaked=X; Path=/"},
        )

    t = ArgtTransport(target="https://example.com/agent/01", session_mode="single-call")
    _attach_mock(t, handler)
    await t.probe(_variant((Message(role="user", content="A"),)))
    await t.probe(_variant((Message(role="user", content="B"),)))
    await t.probe(_variant((Message(role="user", content="C"),)))
    await t.aclose()

    # Probe A primed the jar; probes B and C must still see an empty
    # Cookie header on the wire.
    assert seen_cookies == ["", "", ""]


@pytest.mark.asyncio
async def test_concurrent_multi_call_probes_do_not_cross_contaminate() -> None:
    """Supervisor fires ``concurrency`` variants in parallel through one
    transport (``asyncio.gather``). Each variant's cookie pin must reach
    only its own wire — never the other variant's."""
    # Each request carries "<variant>|<turn-tag>" in the body. The handler
    # echoes a Set-Cookie scoped to that variant. If isolation is broken,
    # turn-2 of one variant will carry the sid of another variant.
    observed: list[tuple[str, str, str]] = []  # (variant, turn_tag, cookie)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        variant_tag, turn_tag = body["message"].split("|", 1)
        observed.append((variant_tag, turn_tag, request.headers.get("cookie", "")))
        return httpx.Response(
            200,
            json={"response": f"ack-{variant_tag}"},
            headers={"set-cookie": f"sid={variant_tag}; Path=/"},
        )

    t = ArgtTransport(target="https://example.com/agent/05", session_mode="multi-call")
    _attach_mock(t, handler)

    def _two_turn_variant(variant_tag: str) -> Variant:
        return _variant(
            (
                Message(role="user", content=f"{variant_tag}|turn-1"),
                Message(role="user", content=f"{variant_tag}|turn-2"),
            )
        )

    results = await asyncio.gather(
        t.probe(_two_turn_variant("alpha")),
        t.probe(_two_turn_variant("beta")),
        t.probe(_two_turn_variant("gamma")),
    )
    await t.aclose()

    for r in results:
        assert r.error is None

    # Group by variant, preserve turn order.
    per_variant: dict[str, list[tuple[str, str]]] = {}
    for variant_tag, turn_tag, cookie in observed:
        per_variant.setdefault(variant_tag, []).append((turn_tag, cookie))

    assert set(per_variant) == {"alpha", "beta", "gamma"}
    for variant_tag, entries in per_variant.items():
        assert len(entries) == 2, f"{variant_tag} did not run both turns"
        # Turn 1: empty Cookie (no pin yet, no leak from siblings).
        assert entries[0] == ("turn-1", ""), f"{variant_tag} turn 1 had stale cookie: {entries[0]!r}"
        # Turn 2: carries its own sid only — never another variant's.
        assert entries[1] == ("turn-2", f"sid={variant_tag}"), f"{variant_tag} turn 2 carried wrong sid: {entries[1]!r}"
