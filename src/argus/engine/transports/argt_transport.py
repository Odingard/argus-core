"""ARGT (ARGUS Targets) transport — chat + multi-call session mode.

The ARGT family of targets are HTTP/JSON agents (Cloudflare Workers,
DVLA, custom session-bearing endpoints). Two dispatch modes:

* ``single-call`` — flatten ``variant.messages`` into one request.
  Default. ``supported_surfaces = {"chat"}``.
* ``multi-call`` — iterate user-role messages, send each as its own
  request, thread server state via auto-detected session strategy
  (Set-Cookie / ``X-Session-Id`` / ``conversation_id``).
  ``supported_surfaces = {"chat", "session_state"}`` — unblocks the
  three Layer 2 classes that need real server-tracked turns
  (c04 indirect-payload-splitting / c08 context-window-stuffing /
  c09 conversation-history-forgery).

Auto-detection runs on the first response of every conversation:

1. ``Set-Cookie`` header → carry the cookie jar across turns.
2. ``X-Session-Id`` / ``X-Conversation-Id`` header → mirror back on
   subsequent requests and accept any rotation the server emits.
3. JSON body field named ``conversation_id`` / ``session_id`` /
   ``thread_id`` → mirror back as a body field.

The **strategy** (cookie / header / body) is locked on turn 1. The
**values** the strategy carries (cookie jar, header value, body field
value) are refreshed from every subsequent response so that servers
that rotate session ids per turn (typical of CSRF-style anti-replay
defences) keep working. Cookies merge additively; header / body
values replace if the server emits a non-empty value (an absent
header is treated as "server is happy with the previous one").

Strategy + locked values + per-turn rotation history are recorded
on ``ProbeResult.raw_response`` for forensic auditing.

``response_text`` is the **final** assistant turn only — never the
joined transcript — so the canary matcher cannot false-positive on
an intermediate turn that the model later repudiated (AGENTS.md
rule #4). The full per-turn transcript is preserved in
``raw_response['turns']``.

Variant isolation: ``httpx.AsyncClient`` maintains an internal
cookie jar that auto-extracts every ``Set-Cookie`` and silently
injects them into subsequent requests that don't set an explicit
``Cookie`` header. Because the supervisor runs ``concurrency``
variants in parallel through a single shared transport instance
(``asyncio.gather``), an unsuppressed jar would smear cookies
between variants and break determinism (AGENTS.md rule #7). Every
request therefore carries an **explicit** ``Cookie`` header (empty
string when the variant has no pin yet), which httpx prefers over
the auto-jar — the variant's own pin is the only source of session
state that ever reaches the wire.

Determinism: same seed → same wire payload sequence. Server
non-determinism (clock-derived ids) is captured but does not perturb
the variant's mutator chain.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ..core.variant import Message, Variant
from ..grading.matcher import ProbeResult
from .carrier import render_via_carrier

_SESSION_BODY_KEYS = ("conversation_id", "session_id", "thread_id")
_SESSION_HEADER_KEYS = ("X-Session-Id", "X-Conversation-Id", "X-Thread-Id")


@dataclass(slots=True)
class _SessionPin:
    """Locked session-threading strategy for one multi-call conversation."""

    cookies: dict[str, str]
    header_key: str
    header_value: str
    body_key: str
    body_value: str

    @property
    def strategy(self) -> str:
        if self.cookies:
            return "cookie"
        if self.header_key:
            return "header"
        if self.body_key:
            return "body"
        return "none"


class ArgtTransport:
    """HTTP/JSON transport for ARGT-family targets.

    Parameters
    ----------
    target:
        Full URL of the agent endpoint (e.g.
        ``https://argus-targets.andrebyrd87.workers.dev/agent/05/triage``).
    api_key:
        Bearer token sent in ``Authorization`` if non-empty.
    session_mode:
        ``"single-call"`` (default) or ``"multi-call"``.
    prompt_field:
        Body field that carries the user content. Most ARGT agents
        accept ``message``; some accept ``prompt`` or ``input``. The
        transport does not auto-probe field names — that's recon's
        job. Default ``"message"``.
    response_field:
        Body field the assistant reply lives under. Default
        ``"response"``; falls back to ``"message"`` / ``"output"`` /
        the raw body if the configured field is absent.
    timeout:
        Per-request timeout in seconds. Default 30.
    """

    name = "argt"

    def __init__(
        self,
        *,
        target: str,
        api_key: str | None = None,
        session_mode: str = "single-call",
        prompt_field: str = "message",
        response_field: str = "response",
        timeout: float = 30.0,
    ) -> None:
        if session_mode not in ("single-call", "multi-call"):
            raise ValueError(f"session_mode must be 'single-call' or 'multi-call', got {session_mode!r}")
        self._target = target
        self._api_key = api_key or ""
        self._session_mode = session_mode
        self._prompt_field = prompt_field
        self._response_field = response_field
        self._timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(
                max_keepalive_connections=32,
                max_connections=64,
            ),
        )

    @property
    def session_mode(self) -> str:
        return self._session_mode

    @property
    def supported_surfaces(self) -> frozenset[str]:
        if self._session_mode == "multi-call":
            return frozenset({"chat", "session_state"})
        return frozenset({"chat"})

    async def aclose(self) -> None:
        await self._client.aclose()

    async def probe(self, variant: Variant) -> ProbeResult:
        try:
            if self._session_mode == "multi-call":
                return await self._probe_multi_call(variant)
            return await self._probe_single_call(variant)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                variant_id=variant.variant_id,
                seed_id=variant.seed_id,
                attack_class=variant.attack_class,
                error=f"{type(exc).__name__}: {exc}",
            )

    async def _probe_single_call(self, variant: Variant) -> ProbeResult:
        """One POST. ``variant.messages`` flattened by role.

        Phase P — when the variant declares a non-canonical carrier
        surface (``tool_result`` / ``rag_document`` / ``roleplay_persona``
        / ``system_reflection``), the variant is first rendered through
        :func:`render_via_carrier` so the payload is delivered through
        the requested trust surface rather than a plain user turn.
        Variants whose ``carrier_surface`` is the default ``user_turn``
        are untouched — pre-Phase-P wire bodies are bit-for-bit
        identical (AGENTS.md rule #7).
        """
        carrier = getattr(variant, "carrier_surface", "user_turn") or "user_turn"
        if carrier != "user_turn":
            variant = render_via_carrier(variant, carrier)
        prompt = _flatten_messages(variant.messages)
        headers = self._headers()
        # Suppress the shared client's auto-jar so cookies set by other
        # variants running concurrently never reach this request.
        headers["Cookie"] = ""
        body = {self._prompt_field: prompt}
        start = time.monotonic()
        resp = await self._client.post(self._target, json=body, headers=headers)
        resp.raise_for_status()
        text = self._extract_response_text(resp)
        return ProbeResult(
            variant_id=variant.variant_id,
            seed_id=variant.seed_id,
            attack_class=variant.attack_class,
            response_text=text,
            streaming_timings=((time.monotonic() - start, text),),
            raw_response={
                "session_mode": "single-call",
                "status_code": resp.status_code,
            },
        )

    async def _probe_multi_call(self, variant: Variant) -> ProbeResult:
        """One POST per user-role message; thread session across turns.

        ``assistant``-role messages in ``variant.messages`` are
        treated as forged history and skipped — the real server
        decides what assistant turns it remembers. ``system``-role
        messages prepend the first user turn (most ARGT agents do not
        accept a separate system field).
        """
        turns = _split_user_turns(variant.messages)
        if not turns:
            return ProbeResult(
                variant_id=variant.variant_id,
                seed_id=variant.seed_id,
                attack_class=variant.attack_class,
                error="multi-call: variant has no user-role messages",
            )

        pin: _SessionPin | None = None
        all_assistant_text: list[str] = []
        timings: list[tuple[float, str]] = []
        turn_log: list[dict[str, Any]] = []
        rotations: list[dict[str, Any]] = []
        start = time.monotonic()
        partial_error: str | None = None

        for i, content in enumerate(turns):
            body: dict[str, Any] = {self._prompt_field: content}
            headers = self._headers()
            # Always set Cookie explicitly — empty when no pin, formatted
            # when a cookie pin is locked. This overrides httpx's shared
            # auto-jar, which would otherwise smear cookies between
            # concurrent variants (AGENTS.md rule #7 — determinism).
            headers["Cookie"] = (
                "; ".join(f"{k}={v}" for k, v in sorted(pin.cookies.items())) if pin is not None and pin.cookies else ""
            )
            if pin is not None:
                if pin.header_key:
                    headers[pin.header_key] = pin.header_value
                if pin.body_key:
                    body[pin.body_key] = pin.body_value

            try:
                resp = await self._client.post(self._target, json=body, headers=headers)
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                # AGENTS.md rule #9: no silent failures. Capture which turn
                # failed and bail with the partial transcript intact so the
                # caller can still diagnose.
                partial_error = f"multi-call: turn {i + 1}/{len(turns)} failed: {type(exc).__name__}: {exc}"
                turn_log.append(
                    {
                        "turn": i,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                break

            text = self._extract_response_text(resp)
            all_assistant_text.append(text)
            timings.append((time.monotonic() - start, text))
            turn_log.append(
                {
                    "turn": i,
                    "status_code": resp.status_code,
                    "response_chars": len(text),
                }
            )

            if pin is None:
                pin = _detect_session_pin(resp)
            else:
                rotation = _refresh_session_pin(pin, resp)
                if rotation is not None:
                    rotation["turn"] = i
                    rotations.append(rotation)

        # AGENTS.md rule #4: canary check runs on the FINAL assistant turn
        # only. Joining all turns would let an intermediate echo land even
        # when the final turn is a refusal — that's a false positive.
        final_text = all_assistant_text[-1] if all_assistant_text else ""

        raw: dict[str, Any] = {
            "session_mode": "multi-call",
            "turns": turn_log,
            "transcript": tuple(all_assistant_text),
            "session_strategy": pin.strategy if pin else "none",
        }
        if pin is not None:
            raw["session_pin"] = _pin_snapshot(pin)
        if rotations:
            raw["session_rotations"] = tuple(rotations)

        return ProbeResult(
            variant_id=variant.variant_id,
            seed_id=variant.seed_id,
            attack_class=variant.attack_class,
            response_text=final_text,
            streaming_timings=tuple(timings),
            raw_response=raw,
            error=partial_error,
        )

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _extract_response_text(self, resp: httpx.Response) -> str:
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return resp.text or ""
        if isinstance(data, dict):
            for key in (self._response_field, "response", "message", "output", "text"):
                if key in data and isinstance(data[key], str):
                    return data[key]
            for key in ("choices",):
                choices = data.get(key)
                if isinstance(choices, list) and choices:
                    first = choices[0]
                    if isinstance(first, dict):
                        msg = first.get("message")
                        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                            return msg["content"]
                        if isinstance(first.get("text"), str):
                            return first["text"]
            return json.dumps(data)
        if isinstance(data, str):
            return data
        return json.dumps(data)


def _flatten_messages(messages: tuple[Message, ...]) -> str:
    """Render messages into a single prompt for single-call mode."""
    parts: list[str] = []
    for m in messages:
        if not m.content:
            continue
        if m.role == "system":
            parts.append(f"[SYSTEM]\n{m.content}")
        elif m.role == "assistant":
            parts.append(f"[ASSISTANT]\n{m.content}")
        elif m.role == "tool":
            parts.append(f"[TOOL]\n{m.content}")
        else:
            parts.append(m.content)
    return "\n\n".join(parts)


def _split_user_turns(messages: tuple[Message, ...]) -> list[str]:
    """Pull user-role turns in order; fold any preceding system prelude.

    Assistant-role messages are skipped — the server emits the real
    assistant turn we observe over the wire. System-role messages
    prepend the *next* user turn (ARGT agents typically don't accept
    a separate system field).
    """
    turns: list[str] = []
    pending_system: list[str] = []
    for m in messages:
        if m.role == "system" and m.content:
            pending_system.append(m.content)
            continue
        if m.role == "user":
            content = m.content or ""
            if pending_system:
                content = "\n\n".join([*pending_system, content])
                pending_system = []
            turns.append(content)
    return turns


def _refresh_session_pin(pin: _SessionPin, resp: httpx.Response) -> dict[str, Any] | None:
    """Update a locked pin's *values* from a subsequent response.

    Returns a small dict describing what (if anything) rotated, or
    ``None`` if the response did not carry a refreshed value. The
    locked **strategy** (cookie / header / body) is never changed —
    only the values it carries.

    Cookies merge additively (response wins on key collisions).
    Header / body values replace only if the server emitted a
    non-empty value; an absent value is treated as "keep the previous
    pin" rather than "clear the session".
    """
    strategy = pin.strategy
    if strategy == "cookie":
        new_cookies = dict(resp.cookies)
        if not new_cookies:
            return None
        before = dict(pin.cookies)
        merged = {**before, **new_cookies}
        if merged == before:
            return None
        pin.cookies = merged
        return {"strategy": "cookie", "cookies": merged}
    if strategy == "header":
        new_value = resp.headers.get(pin.header_key)
        if not new_value or new_value == pin.header_value:
            return None
        before = pin.header_value
        pin.header_value = new_value
        return {
            "strategy": "header",
            "header_key": pin.header_key,
            "old": before,
            "new": new_value,
        }
    if strategy == "body":
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        new_value = data.get(pin.body_key)
        if not isinstance(new_value, str) or not new_value:
            return None
        if new_value == pin.body_value:
            return None
        before = pin.body_value
        pin.body_value = new_value
        return {
            "strategy": "body",
            "body_key": pin.body_key,
            "old": before,
            "new": new_value,
        }
    return None


def _pin_snapshot(pin: _SessionPin) -> dict[str, Any]:
    """Forensic snapshot of the final pin state. Recorded in ``raw_response``
    so a downstream auditor can reproduce which session id the engine
    actually carried on the wire (AGENTS.md rule #6).
    """
    snap: dict[str, Any] = {"strategy": pin.strategy}
    if pin.cookies:
        snap["cookies"] = dict(pin.cookies)
    if pin.header_key:
        snap["header_key"] = pin.header_key
        snap["header_value"] = pin.header_value
    if pin.body_key:
        snap["body_key"] = pin.body_key
        snap["body_value"] = pin.body_value
    return snap


def _detect_session_pin(resp: httpx.Response) -> _SessionPin | None:
    """Inspect the first response and lock a session-threading strategy.

    Cookie wins over header wins over body — Cookie because it is the
    most common stateful pattern and the cheapest to thread; header
    next because it survives proxies; body last because it requires
    the server to read its own field name.
    """
    cookies = dict(resp.cookies)
    if cookies:
        return _SessionPin(
            cookies=cookies,
            header_key="",
            header_value="",
            body_key="",
            body_value="",
        )

    for key in _SESSION_HEADER_KEYS:
        value = resp.headers.get(key)
        if value:
            return _SessionPin(
                cookies={},
                header_key=key,
                header_value=value,
                body_key="",
                body_value="",
            )

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict):
        for key in _SESSION_BODY_KEYS:
            value = data.get(key)
            if isinstance(value, str) and value:
                return _SessionPin(
                    cookies={},
                    header_key="",
                    header_value="",
                    body_key=key,
                    body_value=value,
                )
    return None
