"""ConversationSession — stateful multi-turn HTTP transport for attack agents.

Used by Phase 2+ agents that need to drive a sequence of requests against a
target AI system and observe state changes across turns. Memory Poisoning,
Identity Spoof, Context Window, and Cross-Agent Exfiltration agents are all
built on top of CONDUCTOR.

Security notes:
  - Bound to a single base URL at construction. All TurnSpec paths are
    resolved relative to that base. This prevents per-turn SSRF where an
    attacker (or upstream LLM) could redirect ARGUS at an arbitrary host.
  - Response bodies truncated at 50KB by default to prevent memory exhaustion.
  - httpx event hooks explicitly disabled to prevent credential logging.
  - No automatic redirects — many attacks rely on observing 302/3xx behavior.
  - Cookie persistence available via csrf_mode — when enabled the session
    GETs the target page first, extracts a CSRF token from
    ``<meta name="csrf-token">``, and injects it as ``X-CSRF-Token`` on
    subsequent POSTs.  Cookies are persisted across turns.

T7: Connection Pooling
  - ``ConnectionPool`` provides shared ``httpx.AsyncClient`` instances keyed
    by (host, timeout) so multiple agents attacking the same target reuse
    TCP connections instead of opening new ones for every session.
  - Pass ``pool=ConnectionPool.shared()`` to ``ConversationSession`` to opt in.
  - The pool is scan-scoped: call ``await pool.close_all()`` at scan end.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Bound the size of any single response body we hold in memory
_MAX_RESPONSE_BYTES = 50_000


# ---------------------------------------------------------------------------
# T7: Connection Pooling — shared HTTP clients keyed by (host, timeout)
# ---------------------------------------------------------------------------


class ConnectionPool:
    """Shared pool of ``httpx.AsyncClient`` instances keyed by (host, timeout).

    Multiple ``ConversationSession`` objects targeting the same host reuse
    a single underlying TCP connection pool, reducing handshake overhead
    when many agents attack the same target simultaneously.

    Usage::

        pool = ConnectionPool.shared()  # singleton per process
        session = ConversationSession(base_url, pool=pool)
        async with session:
            ...
        # At scan end:
        await pool.close_all()
    """

    _instance: ConnectionPool | None = None

    def __init__(self) -> None:
        self._clients: dict[tuple[str, float, bool], httpx.AsyncClient] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def shared(cls) -> ConnectionPool:
        """Return the process-wide singleton pool."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def get_client(
        self,
        host: str,
        timeout: float,
        *,
        csrf_mode: bool = False,
    ) -> httpx.AsyncClient:
        """Return (or create) a pooled client for *host* with *timeout*.

        Pooled clients share TCP connections but **not** cookie state.
        Cookies are disabled at the client level (``cookies=False``) so
        each ``ConversationSession`` manages its own cookie jar when
        CSRF mode is needed.
        """
        key = (host, timeout, csrf_mode)
        async with self._lock:
            if key not in self._clients:
                kwargs: dict[str, Any] = {
                    "timeout": timeout,
                    "event_hooks": {"request": [], "response": []},
                    "follow_redirects": False,
                    "cookies": False,  # prevent cross-session cookie leakage
                }
                self._clients[key] = httpx.AsyncClient(**kwargs)
                logger.debug("T7: created pooled client for %s (timeout=%.1f)", host, timeout)
            return self._clients[key]

    async def close_all(self) -> None:
        """Close every pooled client. Call at scan teardown."""
        async with self._lock:
            for client in self._clients.values():
                try:
                    await client.aclose()
                except Exception as exc:
                    logger.debug("T7: error closing pooled client: %s", type(exc).__name__)
            count = len(self._clients)
            self._clients.clear()
        if count:
            logger.debug("T7: closed %d pooled client(s)", count)

    @classmethod
    async def shutdown(cls) -> None:
        """Close the singleton pool (if any). Safe to call multiple times."""
        if cls._instance is not None:
            await cls._instance.close_all()
            cls._instance = None


class TurnSpec(BaseModel):
    """A single request in an attack sequence."""

    name: str = Field(description="Human-readable name for this turn (used in finding evidence)")
    method: str = Field(default="POST", description="HTTP method")
    path: str = Field(description="Path relative to session base_url (e.g. '/chat')")
    body: dict[str, Any] | None = Field(default=None, description="JSON body to send")
    headers: dict[str, str] = Field(default_factory=dict, description="Per-turn headers (merged with session headers)")
    expect_status: int | None = Field(default=None, description="Optional expected HTTP status (None = any 2xx-5xx)")
    # T4: multipart/form-data support for file-upload attack surfaces.
    # When set, body is ignored and files are sent as multipart form fields.
    # Format: {field_name: (filename, content_bytes, content_type)}
    multipart_files: dict[str, tuple[str, bytes, str]] | None = Field(
        default=None,
        description="Multipart file fields (T4). Overrides body when set.",
    )
    # Extra form fields to include alongside the file upload
    multipart_data: dict[str, str] | None = Field(
        default=None,
        description="Multipart text form fields to send alongside files (T4).",
    )


class TurnResult(BaseModel):
    """Structured result of a single turn."""

    turn_name: str
    request_method: str
    request_url: str
    request_body: dict[str, Any] | None = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    status_code: int | None = None
    response_text: str = ""
    response_json: dict[str, Any] | None = None
    latency_ms: float = 0.0
    error: str | None = None

    def ok(self) -> bool:
        """True if the request completed successfully with no errors.

        Returns False when:
        - The request failed with an HTTP error (error set by except block)
        - The response was an HTML catch-all / SPA shell (T1: error='html_response')
        - No status code was recorded
        - The status code is outside 2xx range
        """
        if self.error is not None:
            return False
        return self.status_code is not None and 200 <= self.status_code < 300

    def field(self, *path: str) -> Any:
        """Walk the JSON response by key path. Returns None if any key missing.

        Example: result.field("data", "canary_extracted")
        """
        cur: Any = self.response_json
        for key in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
        return cur


class ConversationSession:
    """Stateful HTTP transport for a single attack session against one target.

    Bind to a single base URL — all subsequent turns are sent to paths
    resolved against that base. SSRF-safe: paths starting with `http://` or
    `https://` that point at a different host are rejected.
    """

    def __init__(
        self,
        base_url: str,
        session_id: str | None = None,
        default_headers: dict[str, str] | None = None,
        timeout_seconds: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        auth_token: str | None = None,
        csrf_mode: bool = False,
        pool: ConnectionPool | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"ConversationSession base_url must be http(s): {base_url}")
        self._allowed_host = parsed.netloc
        self.session_id = session_id
        self.default_headers = default_headers or {}
        if auth_token:
            self.default_headers.setdefault("Authorization", f"Bearer {auth_token}")
        self.timeout_seconds = timeout_seconds
        self._transport = transport
        self.history: list[TurnResult] = []
        self._client: httpx.AsyncClient | None = None
        # T3: CSRF token handling
        self._csrf_mode = csrf_mode
        self._csrf_token: str | None = None
        self._csrf_fetched = False
        # T7: Connection pooling — when a pool is provided, __aenter__
        # borrows a shared client instead of creating a private one.
        self._pool = pool
        self._owns_client = True  # False when using pooled client

    async def __aenter__(self) -> ConversationSession:
        # T7: prefer pooled client when a pool is provided
        if self._pool is not None and self._transport is None:
            self._client = await self._pool.get_client(
                self._allowed_host,
                self.timeout_seconds,
                csrf_mode=self._csrf_mode,
            )
            self._owns_client = False
        else:
            kwargs: dict[str, Any] = {
                "timeout": self.timeout_seconds,
                "event_hooks": {"request": [], "response": []},
                "follow_redirects": False,
            }
            if self._transport is not None:
                kwargs["transport"] = self._transport
            # T3: enable cookie persistence when CSRF mode is on
            if self._csrf_mode:
                kwargs["cookies"] = httpx.Cookies()
            self._client = httpx.AsyncClient(**kwargs)
            self._owns_client = True
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
        self._client = None

    def _resolve(self, path: str) -> str:
        """Resolve a turn path against the session base_url.

        Rejects paths that point at a different host than the bound base.
        Defense-in-depth: even after urljoin we re-parse the result and
        verify the netloc matches the allowed host, since urljoin can
        produce surprising results for paths like ``//evil.com/x`` or
        ``..//@evil.com``.
        """
        # Allow absolute paths (e.g. "/chat") and absolute URLs that match base host
        if path.startswith(("http://", "https://")):
            parsed = urlparse(path)
            if parsed.netloc != self._allowed_host:
                raise ValueError(f"ConversationSession path host {parsed.netloc} != allowed host {self._allowed_host}")
            return path
        # Relative path — join against base, then verify the result hasn't
        # been redirected to a different host through urljoin oddities.
        resolved = urljoin(self.base_url, path.lstrip("/"))
        resolved_host = urlparse(resolved).netloc
        if resolved_host != self._allowed_host:
            raise ValueError(f"ConversationSession resolved host {resolved_host} != allowed host {self._allowed_host}")
        return resolved

    async def _fetch_csrf_token(self, path: str) -> None:
        """T3: GET the page and extract CSRF token from <meta name="csrf-token">.

        Only attempts once per session — sets ``_csrf_fetched`` to avoid
        repeated GETs on targets that don't use CSRF tokens.
        """
        if self._csrf_fetched or self._client is None:
            return
        self._csrf_fetched = True
        try:
            url = self._resolve(path)
            resp = await self._client.get(url, headers=self.default_headers)
            # Look for <meta name="csrf-token" content="..."> in HTML response
            match = re.search(
                r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\'>]+)',
                resp.text,
                re.IGNORECASE,
            )
            if match:
                self._csrf_token = match.group(1)
                logger.info("T3: extracted CSRF token (%d chars)", len(self._csrf_token))
            else:
                logger.debug("T3: no csrf-token meta tag found at %s", path)
        except Exception as exc:
            logger.debug("T3: CSRF token fetch failed: %s", type(exc).__name__)

    async def turn(self, spec: TurnSpec) -> TurnResult:
        """Execute a single turn and record the result in history."""
        if self._client is None:
            raise RuntimeError("ConversationSession must be used as an async context manager")

        # T3: Fetch CSRF token before the first mutating request
        if self._csrf_mode and not self._csrf_fetched and spec.method.upper() != "GET":
            await self._fetch_csrf_token(spec.path)

        url = self._resolve(spec.path)
        headers = {**self.default_headers, **spec.headers}
        # T3: Inject CSRF token header on mutating requests
        if self._csrf_token and spec.method.upper() != "GET":
            headers.setdefault("X-CSRF-Token", self._csrf_token)
        result = TurnResult(
            turn_name=spec.name,
            request_method=spec.method,
            request_url=url,
            request_body=spec.body
            if spec.multipart_files is None
            else {"_multipart": True, **(spec.multipart_data or {})},
            request_headers=headers,
        )
        start = time.monotonic()
        try:
            # T4: multipart/form-data for file-upload surfaces
            if spec.multipart_files is not None:
                response = await self._client.request(
                    spec.method,
                    url,
                    files=spec.multipart_files,
                    data=spec.multipart_data or {},
                    headers=headers,
                )
            else:
                response = await self._client.request(
                    spec.method,
                    url,
                    json=spec.body,
                    headers=headers,
                )
            result.status_code = response.status_code
            content_type = response.headers.get("content-type", "")
            raw_text = response.text[:_MAX_RESPONSE_BYTES]

            # T2: SSE — reassemble streamed frames into coherent text
            if "text/event-stream" in content_type:
                from argus.survey.prober import _parse_sse_to_text

                text = _parse_sse_to_text(raw_text)
            # T3: NDJSON — reassemble newline-delimited JSON streams
            elif (
                "application/x-ndjson" in content_type
                or "application/jsonlines" in content_type
                or (content_type == "" and raw_text.lstrip().startswith("{") and "\n{" in raw_text)
            ):
                from argus.survey.prober import _parse_ndjson_to_text

                text = _parse_ndjson_to_text(raw_text)
            else:
                text = raw_text

            # T1: HTML catch-all filter — flag but still store the text
            from argus.survey.prober import _is_html_catchall

            if _is_html_catchall(content_type, text):
                result.error = "html_response"

            result.response_text = text
            if "application/json" in content_type or text.lstrip().startswith("{"):
                try:
                    parsed = response.json()
                    if isinstance(parsed, dict):
                        result.response_json = parsed
                except Exception as exc:
                    logger.debug("Failed to parse JSON from %s: %s", url, type(exc).__name__)
        except httpx.HTTPError as exc:
            # Only store the exception class name. httpx exceptions often
            # repr() with the full request URL — which can include bearer
            # tokens in query strings or basic-auth credentials in netloc.
            # Keep the dashboard / SSE stream clean.
            result.error = type(exc).__name__
            logger.debug(
                "ConversationSession turn '%s' failed: %s",
                spec.name,
                type(exc).__name__,
            )
        finally:
            result.latency_ms = round((time.monotonic() - start) * 1000, 2)

        self.history.append(result)
        return result


class AttackSequence:
    """An ordered sequence of TurnSpecs to run against a session.

    Sequences are intentionally simple — just a list of turns. Conditional
    branching is the agent's job: read the TurnResult, decide the next move,
    construct a follow-up TurnSpec, and call session.turn() again.
    """

    def __init__(self, name: str, turns: list[TurnSpec]) -> None:
        self.name = name
        self.turns = list(turns)

    async def run(self, session: ConversationSession) -> list[TurnResult]:
        """Run all turns in order against the session."""
        results: list[TurnResult] = []
        for spec in self.turns:
            result = await session.turn(spec)
            results.append(result)
        return results


class ResponseMatcher:
    """Pattern matchers for analyzing target responses.

    These are generic — they look for evidence of behavior change without
    hardcoding any specific target's canary token or scenario ID. The
    sensitive marker patterns are the same generic regex set used by the
    Tool Poisoning agent.
    """

    # Generic patterns for detecting leaked sensitive content from any AI agent.
    # Per the no-benchmark-gaming rule: NO scenario-specific tokens hardcoded.
    SENSITIVE_MARKER_PATTERNS: list[str] = [
        r"[A-Z][A-Z0-9_]+-CANARY-\d+",
        r"[A-Z][A-Z0-9_]+_CANARY_[A-Z0-9]+",
        r"CONFIDENTIAL[-_:]\s*\S+",
        r"SECRET[-_]\w+",
        r"PRIVATE_KEY[-_:]",
        r"BEGIN [A-Z ]*PRIVATE KEY",
        r"prod[-_]key[-_]\w+",
        r"ORCH[-_]SECRET[-_]\w+",
        r"sk[-_][A-Za-z0-9]{20,}",
        r"AKIA[0-9A-Z]{16}",
    ]

    PRIVILEGE_INDICATORS: list[str] = [
        "elevated",
        "admin",
        "trust_granted",
        "unauthorized_command_executed",
        "privilege_escalation",
        "canary_extracted",
        "leaked_system_prompt",
    ]

    @classmethod
    def find_sensitive_markers(cls, text: str) -> list[str]:
        """Return all sensitive marker matches found in text. Empty list = none."""
        if not text:
            return []
        hits: list[str] = []
        for pattern in cls.SENSITIVE_MARKER_PATTERNS:
            try:
                hits.extend(re.findall(pattern, text))
            except re.error:
                continue
        # De-dupe while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for h in hits:
            if h not in seen:
                seen.add(h)
                unique.append(h)
        return unique

    @classmethod
    def find_privilege_indicators(cls, text: str) -> list[str]:
        """Return privilege-escalation field names that appear in the text."""
        if not text:
            return []
        lower = text.lower()
        return [ind for ind in cls.PRIVILEGE_INDICATORS if ind.lower() in lower]

    @classmethod
    def has_truth_field(cls, result: TurnResult, key: str, expected: Any = True) -> bool:
        """True if result.response_json contains key=expected at the top level."""
        if result.response_json is None:
            return False
        return result.response_json.get(key) == expected
