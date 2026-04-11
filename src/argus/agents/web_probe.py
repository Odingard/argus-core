"""Web Target Probe Client.

When ARGUS scans a regular website (not an AI agent API or MCP server),
agents use this module to make real HTTP requests against the target.

The probe:
1. Fetches the target URL and inspects the response
2. Discovers AI-related endpoints (chatbot widgets, /api/chat, etc.)
3. Sends attack payloads to discovered endpoints and the base URL
4. Returns structured results agents can analyze for findings

This is the bridge between ARGUS's agent architecture (designed for AI
agent APIs) and real-world web targets.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Common AI chatbot / assistant endpoint paths to probe
AI_ENDPOINT_PATHS = [
    "/api/chat",
    "/api/v1/chat",
    "/api/v1/chat/completions",
    "/api/assistant",
    "/api/ai",
    "/api/ask",
    "/api/query",
    "/api/message",
    "/api/conversation",
    "/api/bot",
    "/chat",
    "/chatbot",
    "/assistant",
    "/api/v1/completions",
    "/api/completions",
    "/api/generate",
    "/v1/chat/completions",
    "/.well-known/ai-plugin.json",
    "/openapi.json",
    "/api/openapi.json",
]

# Patterns in HTML that indicate AI chatbot presence
AI_WIDGET_PATTERNS = [
    r"intercom",
    r"drift\.com",
    r"crisp\.chat",
    r"tidio",
    r"zendesk",
    r"livechat",
    r"chatbot",
    r"chat-widget",
    r"chat-container",
    r"ai-assistant",
    r"openai",
    r"anthropic",
    r"langchain",
    r"bot-frame",
    r"virtual-agent",
    r"ada\.support",
    r"watson-assistant",
    r"dialogflow",
]

# HTTP headers that indicate AI/ML backends
AI_RESPONSE_HEADERS = [
    "x-openai",
    "x-anthropic",
    "x-ai-",
    "x-model",
    "x-inference",
    "x-langchain",
    "x-chatbot",
    "x-bot-",
]


class WebProbeResult:
    """Result from probing a web target."""

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url
        self.reachable = False
        self.status_code: int | None = None
        self.headers: dict[str, str] = {}
        self.body_preview: str = ""
        self.server: str = ""
        self.content_type: str = ""
        self.ai_indicators: list[str] = []
        self.discovered_endpoints: list[str] = []
        self.security_headers: dict[str, str] = {}
        self.technologies: list[str] = []
        self.response_time_ms: float = 0
        self.error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "server": self.server,
            "content_type": self.content_type,
            "ai_indicators": self.ai_indicators,
            "discovered_endpoints": self.discovered_endpoints,
            "security_headers": self.security_headers,
            "technologies": self.technologies,
            "response_time_ms": self.response_time_ms,
            "error": self.error,
        }


class WebProbeClient:
    """Probes web targets with real HTTP requests.

    Used by ARGUS agents when the target is a regular website rather
    than a dedicated AI agent API endpoint.
    """

    def __init__(self, target_url: str, *, non_destructive: bool = True) -> None:
        self.target_url = target_url.rstrip("/")
        self.non_destructive = non_destructive
        self._parsed = urlparse(self.target_url)
        self._base_url = f"{self._parsed.scheme}://{self._parsed.netloc}"

    async def probe(self) -> WebProbeResult:
        """Full probe of the target: fetch, analyze, discover endpoints."""
        import time

        import httpx

        result = WebProbeResult(self.target_url)

        try:
            start = time.monotonic()
            async with httpx.AsyncClient(
                timeout=30,
                follow_redirects=True,
                verify=False,  # noqa: S501 — intentional for security testing tool
                event_hooks={"request": [], "response": []},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
            ) as client:
                # Step 1: Fetch the target URL
                response = await client.get(self.target_url)
                elapsed = time.monotonic() - start

                result.reachable = True
                result.status_code = response.status_code
                result.response_time_ms = elapsed * 1000
                result.headers = dict(response.headers)
                result.server = response.headers.get("server", "")
                result.content_type = response.headers.get("content-type", "")
                result.body_preview = response.text[:50_000]

                # Step 2: Analyze security headers
                result.security_headers = self._analyze_security_headers(response.headers)

                # Step 3: Detect technologies
                result.technologies = self._detect_technologies(response)

                # Step 4: Find AI indicators in the page
                result.ai_indicators = self._find_ai_indicators(response.text)

                # Step 5: Discover AI endpoints
                result.discovered_endpoints = await self._discover_ai_endpoints(client)

        except Exception as exc:
            result.error = f"{type(exc).__name__}: {str(exc)[:500]}"
            logger.debug("Web probe failed for %s: %s", self.target_url, result.error)

        return result

    async def send_payload(
        self,
        payload: str,
        *,
        method: str = "POST",
        path: str = "",
        content_type: str = "application/json",
    ) -> dict[str, Any] | None:
        """Send an attack payload to the target and return the response.

        This is the main method agents use to send injection payloads.
        It tries multiple delivery methods:
        1. POST JSON body to the target/path
        2. GET with payload as query parameter
        3. POST as form data
        """
        import httpx

        url = urljoin(self._base_url, path) if path else self.target_url
        results: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(
                timeout=30,
                follow_redirects=True,
                verify=False,  # noqa: S501 — intentional for security testing tool
                event_hooks={"request": [], "response": []},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            ) as client:
                # Method 1: POST JSON
                if method == "POST":
                    try:
                        resp = await client.post(
                            url,
                            json={"message": payload, "query": payload, "input": payload},
                            headers={"Content-Type": "application/json"},
                        )
                        results.append(
                            {
                                "method": "POST_JSON",
                                "url": url,
                                "status_code": resp.status_code,
                                "response": resp.text[:10_000],
                                "headers": dict(resp.headers),
                                "content_type": resp.headers.get("content-type", ""),
                            }
                        )
                    except Exception as exc:
                        logger.debug("POST JSON failed: %s", exc)

                    # Method 2: POST form data
                    try:
                        resp = await client.post(
                            url,
                            data={"message": payload, "q": payload, "search": payload},
                        )
                        results.append(
                            {
                                "method": "POST_FORM",
                                "url": url,
                                "status_code": resp.status_code,
                                "response": resp.text[:10_000],
                                "headers": dict(resp.headers),
                                "content_type": resp.headers.get("content-type", ""),
                            }
                        )
                    except Exception as exc:
                        logger.debug("POST form failed: %s", exc)

                # Method 3: GET with query param (always try this)
                try:
                    resp = await client.get(url, params={"q": payload[:500], "search": payload[:500]})
                    results.append(
                        {
                            "method": "GET_QUERY",
                            "url": url,
                            "status_code": resp.status_code,
                            "response": resp.text[:10_000],
                            "headers": dict(resp.headers),
                            "content_type": resp.headers.get("content-type", ""),
                        }
                    )
                except Exception as exc:
                    logger.debug("GET query failed: %s", exc)

        except Exception as exc:
            logger.debug("send_payload failed for %s: %s", url, exc)
            return None

        if not results:
            return None

        # Return the most interesting result (prefer non-error JSON responses)
        best = results[0]
        for r in results:
            if 200 <= r["status_code"] < 400 and "json" in r.get("content_type", ""):
                best = r
                break
            if 200 <= r["status_code"] < 400:
                best = r

        return {
            "response": best["response"],
            "status_code": best["status_code"],
            "method": best["method"],
            "url": best["url"],
            "all_attempts": results,
        }

    async def fetch_page(self, path: str = "") -> dict[str, Any] | None:
        """Fetch a page from the target. Used for reconnaissance."""
        import httpx

        url = urljoin(self._base_url, path) if path else self.target_url

        try:
            async with httpx.AsyncClient(
                timeout=20,
                follow_redirects=True,
                verify=False,  # noqa: S501 — intentional for security testing tool
                event_hooks={"request": [], "response": []},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            ) as client:
                resp = await client.get(url)
                return {
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "body": resp.text[:50_000],
                    "headers": dict(resp.headers),
                    "content_type": resp.headers.get("content-type", ""),
                }
        except Exception as exc:
            logger.debug("fetch_page failed for %s: %s", url, exc)
            return None

    def _analyze_security_headers(self, headers: Any) -> dict[str, str]:
        """Extract and analyze security-relevant headers."""
        security_headers = {}
        check_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "cross-origin-embedder-policy",
            "x-permitted-cross-domain-policies",
        ]
        for h in check_headers:
            val = headers.get(h)
            if val:
                security_headers[h] = val
        return security_headers

    def _detect_technologies(self, response: Any) -> list[str]:
        """Detect technologies from response headers and body."""
        techs = []
        headers = response.headers
        body = response.text[:20_000].lower()

        # Server header
        server = headers.get("server", "").lower()
        if "nginx" in server:
            techs.append("nginx")
        if "apache" in server:
            techs.append("apache")
        if "cloudflare" in server:
            techs.append("cloudflare")
        if "microsoft" in server or "iis" in server:
            techs.append("iis")

        # X-Powered-By
        powered = headers.get("x-powered-by", "").lower()
        if powered:
            techs.append(f"x-powered-by:{powered}")

        # Framework detection from body
        if "react" in body or "reactdom" in body or "__NEXT_DATA__" in response.text:
            techs.append("react")
        if "angular" in body or "ng-app" in body:
            techs.append("angular")
        if "vue" in body or "__VUE__" in response.text:
            techs.append("vue")
        if "wordpress" in body or "wp-content" in body:
            techs.append("wordpress")

        # CDN/WAF detection
        if headers.get("cf-ray"):
            techs.append("cloudflare-cdn")
        if headers.get("x-amz-cf-id"):
            techs.append("aws-cloudfront")
        if "akamai" in str(headers).lower():
            techs.append("akamai")

        return techs

    def _find_ai_indicators(self, html: str) -> list[str]:
        """Find indicators of AI/chatbot presence in the HTML."""
        indicators = []
        html_lower = html.lower()

        for pattern in AI_WIDGET_PATTERNS:
            if re.search(pattern, html_lower):
                indicators.append(f"widget:{pattern}")

        # Check for common AI-related script tags
        script_patterns = [
            (r'src="[^"]*openai[^"]*"', "openai-sdk"),
            (r'src="[^"]*anthropic[^"]*"', "anthropic-sdk"),
            (r'src="[^"]*chat[^"]*\.js"', "chat-script"),
            (r'src="[^"]*bot[^"]*\.js"', "bot-script"),
            (r'src="[^"]*assistant[^"]*\.js"', "assistant-script"),
        ]
        for pat, name in script_patterns:
            if re.search(pat, html_lower):
                indicators.append(f"script:{name}")

        # Check for AI-related meta tags or comments
        if "ai" in html_lower and "chat" in html_lower:
            indicators.append("content:ai-chat-reference")

        return indicators

    async def _discover_ai_endpoints(self, client: Any) -> list[str]:
        """Probe common AI endpoint paths and return those that respond."""
        discovered = []

        for path in AI_ENDPOINT_PATHS:
            url = urljoin(self._base_url, path)
            try:
                resp = await client.get(url, timeout=10)
                # Consider it discovered if it doesn't 404
                if resp.status_code != 404:
                    discovered.append(f"{path} ({resp.status_code})")
            except Exception:  # noqa: S112
                continue

        return discovered
