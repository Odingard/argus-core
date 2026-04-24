"""
argus/adapter/http_agent.py — HTTP agent adapter with route discovery
and auth flow.

For targets exposed as plain HTTP agents / chat APIs / web apps
(FastAPI, Flask, Next.js, Vercel AI SDK deploys, custom internal
services). Three capabilities operators actually need against real
deployments:

  1. Route discovery — crawl the landing page, parse forms, sniff
     JS-embedded API paths, probe candidate endpoints for chat-
     shaped responses. Without this, operators have to hand-map
     every target's ``chat_path`` — the same labor we promised to
     eliminate.

  2. Auth flow — form-login + session cookie, bearer token, or
     custom auth-header. Most real agent deployments have auth in
     front of the LLM endpoint; unauthenticated probes bounce off
     the login wall with zero signal.

  3. Chat-shape probing — distinguish "endpoint accepts free text
     and returns a substantive response" (a chat surface worth
     attacking) from "endpoint serves HTML / 404 / auth redirect."

Backwards compatible: explicit ``chat_path`` still pins the adapter
to a single endpoint (existing tests + labrats unchanged).
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Response, Surface,
)


# ── Auth specification ──────────────────────────────────────────────────

@dataclass
class AuthSpec:
    """How to authenticate against an HTTP target.

    One of ``form_login`` / ``bearer_token`` / ``auth_header`` must
    be set. Each is an independent auth mode — the adapter applies
    them in order of precedence (form > bearer > header) but a real
    config uses exactly one.
    """
    # Form-based login (classic username/password web app).
    form_login_url: str = ""        # e.g. "/login"
    username:       str = ""
    password:       str = ""
    username_field: str = "username"
    password_field: str = "password"
    # Bearer token — set "Authorization: Bearer <token>" on every request.
    bearer_token:   str = ""
    # Arbitrary auth header set per request.
    auth_header:    dict = field(default_factory=dict)

    def is_configured(self) -> bool:
        return bool(
            self.bearer_token
            or (self.username and self.password)
            or self.auth_header
        )


# ── Route discovery ────────────────────────────────────────────────────

class _FormParser(HTMLParser):
    """Tiny HTML parser that extracts <form action>/<input name>
    pairs from a landing page. Good enough to find login forms and
    chat forms on Flask/Jinja apps without pulling in BeautifulSoup."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._current: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag.lower() == "form":
            self._current = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "POST").upper(),
                "inputs": [],
            }
            self.forms.append(self._current)
        elif tag.lower() in ("input", "textarea") and self._current is not None:
            name = a.get("name") or a.get("id")
            if name:
                self._current["inputs"].append({
                    "name": name,
                    "type": (a.get("type") or "text").lower(),
                    "value": a.get("value", ""),
                })

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._current = None


# Heuristic patterns for chat/agent endpoints in JS / HTML.
_JS_ROUTE_PATTERNS = (
    re.compile(
        r"""(?:fetch|axios\.(?:post|get)|url\s*[:=])\s*['"]"""
        r"""(/[^'"?\s]+)""",
        re.IGNORECASE,
    ),
    # fetch("/api/chat", { ... })
    re.compile(r"""['"](/api/[^'"?\s]+)['"]""", re.IGNORECASE),
)

# Route-name heuristics — the path NAME hints it accepts prompts.
_CHAT_ROUTE_HINTS = re.compile(
    r"(?i)(/chat|/ask|/message|/query|/generate|/complet|/llm|/ai|/prompt|"
    r"/order|/assist|/agent|/bot|/respond|/conversation)"
)


def _sniff_routes_from_html(html: str, base_url: str) -> list[str]:
    """Extract candidate chat-endpoint paths from a landing page."""
    out: set[str] = set()
    # Forms
    p = _FormParser()
    try:
        p.feed(html)
    except Exception:
        pass
    for f in p.forms:
        if f["action"]:
            out.add(f["action"])
    # JS routes
    for pat in _JS_ROUTE_PATTERNS:
        for m in pat.finditer(html):
            path = m.group(1)
            if path and path.startswith("/"):
                out.add(path)
    # Normalize to absolute paths (no query) within same host.
    results: list[str] = []
    base = urlparse(base_url)
    for raw in out:
        u = urljoin(base_url, raw)
        parsed = urlparse(u)
        if parsed.netloc and parsed.netloc != base.netloc:
            continue
        path = parsed.path or "/"
        if path not in results:
            results.append(path)
    return results


# ── Adapter ────────────────────────────────────────────────────────────

class HTTPAgentAdapter(BaseAdapter):
    """HTTP agent/chat-API adapter with optional route-discovery +
    auth-flow.

    Explicit mode (one endpoint):

        HTTPAgentAdapter(
            base_url="https://api.example.com",
            chat_path="/v1/chat",
            message_key="input",
        )

    Discovery mode (find endpoints):

        HTTPAgentAdapter(
            base_url="http://localhost:8080",
            # chat_path unset → discover
            discover=True,
            auth_spec=AuthSpec(
                form_login_url="/login",
                username="alice", password="alice",
            ),
        )

    Discovery fetches ``base_url``, parses forms + JS routes, probes
    each candidate, and adds every chat-shaped endpoint as a surface.
    Auth (when configured) logs in FIRST so authenticated endpoints
    are reachable.
    """

    DEFAULT_SURFACES = ("chat",)

    def __init__(
        self,
        *,
        base_url:        str,
        chat_path:       Optional[str] = None,
        method:          str = "POST",
        auth_header:     Optional[dict] = None,    # legacy; auth_spec preferred
        message_key:     str = "message",
        response_key:    Optional[str] = None,
        connect_timeout: float = 10.0,
        request_timeout: float = 30.0,
        verify_tls:      bool = True,
        discover:        Optional[bool] = None,
        auth_spec:       Optional[AuthSpec] = None,
    ) -> None:
        # When chat_path unset, default behavior is: discover if
        # discover wasn't explicitly disabled; otherwise fall back to
        # "/chat" so bare-URL engagements still have a target.
        effective_path = chat_path or "/chat"
        if discover is None:
            discover = (chat_path is None)
        super().__init__(
            target_id=f"{base_url.rstrip('/')}{effective_path}",
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        self.base_url     = base_url.rstrip("/")
        self.chat_path    = effective_path
        self.method       = method.upper()
        # Merge legacy auth_header into auth_spec for a single code path.
        _spec = auth_spec or AuthSpec()
        if auth_header:
            _spec.auth_header.update(auth_header)
        self.auth_spec    = _spec
        self.message_key  = message_key
        self.response_key = response_key
        self.verify_tls   = verify_tls
        self.discover     = bool(discover)
        self._client: Optional[httpx.AsyncClient] = None
        # Populated by _enumerate when discover=True.
        self._discovered_surfaces: list[Surface] = []

    # ── Transport ─────────────────────────────────────────────────────

    async def _connect(self) -> None:
        headers: dict = {}
        if self.auth_spec.bearer_token:
            headers["Authorization"] = f"Bearer {self.auth_spec.bearer_token}"
        headers.update(self.auth_spec.auth_header)

        self._client = httpx.AsyncClient(
            timeout=self.request_timeout,
            verify=self.verify_tls,
            headers=headers,
            follow_redirects=True,
        )
        # Sanity: reach the base URL (not chat_path — the landing).
        try:
            await self._client.get(
                self.base_url,
                timeout=self.connect_timeout,
            )
        except httpx.RequestError as e:
            await self._client.aclose()
            self._client = None
            raise AdapterError(f"HTTPAgentAdapter: {e}") from e

        # Auth flow: form-login if configured.
        if (self.auth_spec.form_login_url
                and self.auth_spec.username
                and self.auth_spec.password):
            await self._form_login()

    async def _disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None

    # ── Auth ─────────────────────────────────────────────────────────

    async def _form_login(self) -> None:
        """POST the configured credentials to form_login_url; keep
        the session cookie via the httpx client's cookie jar."""
        if self._client is None:
            return
        url = urljoin(self.base_url + "/", self.auth_spec.form_login_url)
        data = {
            self.auth_spec.username_field: self.auth_spec.username,
            self.auth_spec.password_field: self.auth_spec.password,
        }
        try:
            # First GET the login page so any CSRF token gets into
            # the cookie jar before we POST.
            await self._client.get(url, timeout=self.connect_timeout)
            resp = await self._client.post(
                url, data=data, timeout=self.connect_timeout,
            )
            # Non-fatal: login may return 200 regardless of success.
            # Surface logs carry auth-state for downstream probes to
            # reason about.
            self._last_login_status = resp.status_code
        except httpx.RequestError:
            # Don't abort — proceed unauthenticated; enumeration will
            # show what surfaces are reachable.
            self._last_login_status = -1

    # ── Enumeration + route discovery ────────────────────────────────

    async def _enumerate(self) -> list[Surface]:
        explicit = [
            Surface(
                kind="chat", name="chat",
                description=f"{self.method} {self.base_url}{self.chat_path}",
                meta={"path": self.chat_path,
                      "message_key": self.message_key,
                      "response_key": self.response_key},
            )
        ]
        if not self.discover:
            return explicit

        # Crawl landing + probe candidate routes.
        self._discovered_surfaces = await self._discover_chat_surfaces()
        if self._discovered_surfaces:
            return self._discovered_surfaces
        # Fall back to the explicit default so zero-discovery doesn't
        # leave us with zero surfaces.
        return explicit

    async def _discover_chat_surfaces(self) -> list[Surface]:
        """Fetch base_url, parse HTML for form/JS routes, probe each
        with a benign string, keep any that accept free text and
        return substantive responses."""
        if self._client is None:
            return []
        try:
            resp = await self._client.get(
                self.base_url, timeout=self.connect_timeout,
            )
            html = resp.text or ""
        except httpx.RequestError:
            return []

        candidates = _sniff_routes_from_html(html, self.base_url)
        # Prioritise paths whose NAMES suggest chat/LLM endpoints.
        candidates.sort(
            key=lambda p: (0 if _CHAT_ROUTE_HINTS.search(p) else 1, p),
        )
        # Cap to avoid spamming the target.
        candidates = candidates[:20]

        out: list[Surface] = []
        # Probe each with a benign string. A chat-shape endpoint:
        #   • accepts POST / GET with text input
        #   • returns 2xx
        #   • response body length > 20 bytes and not pure HTML page
        benign_payloads = ("hello", {"message": "hello"},
                           {"prompt": "hello"}, {"input": "hello"},
                           {"query": "hello"})
        for path in candidates:
            probed = await self._probe_route(path, benign_payloads)
            if probed is not None:
                out.append(probed)
        return out

    async def _probe_route(
        self, path: str, benign_payloads: tuple,
    ) -> Optional[Surface]:
        """Return a Surface if ``path`` looks like a chat endpoint;
        None if it's HTML / 404 / non-chatty."""
        if self._client is None:
            return None
        url = urljoin(self.base_url + "/", path)
        # Try POST with each canonical shape until one returns 2xx.
        for payload in benign_payloads:
            try:
                if isinstance(payload, str):
                    resp = await self._client.post(url, data=payload)
                else:
                    resp = await self._client.post(url, json=payload)
            except httpx.RequestError:
                continue
            ct = resp.headers.get("content-type", "")
            body = resp.text or ""
            if resp.status_code >= 400:
                continue
            # Reject pages that are obviously HTML landing.
            if "html" in ct.lower() and len(body) > 2000:
                continue
            if len(body) < 10:
                continue
            # Looks chat-shaped.
            msg_key = (payload.keys().__iter__().__next__()
                       if isinstance(payload, dict) else "message")
            return Surface(
                kind="chat", name=f"chat:{path}",
                description=f"POST {url}",
                meta={"path": path, "message_key": msg_key,
                      "content_type": ct, "probe_bytes": len(body)},
            )
        return None

    # ── Interaction ───────────────────────────────────────────────────

    async def _interact(self, request: Request) -> AdapterObservation:
        if self._client is None:
            raise AdapterError("HTTPAgentAdapter._client is None")
        # Route based on the surface meta if present — supports
        # discovered surfaces with per-endpoint paths + message keys.
        path = self.chat_path
        msg_key = self.message_key
        for s in self._discovered_surfaces:
            if s.name == request.surface:
                path = s.meta.get("path", path)
                msg_key = s.meta.get("message_key", msg_key)
                break
        url = self.base_url + path
        body = self._shape_payload(request, msg_key)
        t0 = time.monotonic()
        try:
            resp = await self._client.request(self.method, url, json=body)
        except httpx.RequestError as e:
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="error",
                                  body=f"{type(e).__name__}: {e}",
                                  elapsed_ms=int((time.monotonic() - t0) * 1000)),
            )

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        try:
            parsed = resp.json()
        except (json.JSONDecodeError, ValueError):
            parsed = resp.text

        extracted = parsed
        if self.response_key and isinstance(parsed, dict):
            extracted = parsed.get(self.response_key, parsed)

        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(
                status=("ok" if resp.is_success else "error"),
                body=extracted,
                headers=dict(resp.headers),
                elapsed_ms=elapsed_ms,
                raw=parsed,
            ),
        )

    # ── Extension point ──────────────────────────────────────────────

    def _shape_payload(self, request: Request, msg_key: Optional[str] = None) -> dict:
        """Default: put the payload under ``message_key``. Override as needed."""
        key = msg_key or self.message_key
        if isinstance(request.payload, dict):
            return request.payload
        return {key: request.payload}
