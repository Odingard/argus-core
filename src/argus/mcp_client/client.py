"""MCP Attack Client.

Connects to any MCP server as a client — from the attacker's perspective.
Enumerates tools, inspects definitions for hidden content, calls tools
with adversarial inputs, and monitors responses.

Security hardening:
- Subprocess command allowlist prevents arbitrary execution
- Minimal environment inheritance prevents secrets leakage
- HTTPS enforced for authenticated connections
- Error messages sanitized to prevent info disclosure
- URL scheme validation prevents SSRF via file:// or gopher://
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from argus.mcp_client.models import MCPCallResult, MCPServerConfig, MCPTool, MCPToolParameter

logger = logging.getLogger(__name__)

# Unicode zero-width characters used in tool poisoning
ZERO_WIDTH_CHARS = [
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space
    "\u00ad",  # soft hyphen
]

HIDDEN_CONTENT_PATTERNS = [
    r"<!--.*?-->",  # HTML comments
    r"\[INST\].*?\[/INST\]",  # Instruction tags
    r"<system>.*?</system>",  # System tags
    r"<\|im_start\|>.*?<\|im_end\|>",  # ChatML
]

# Suspicious imperative patterns that indicate appended instructions in tool descriptions
APPENDED_INSTRUCTION_PATTERNS = [
    r"\bnote:\s*when using this tool",
    r"\bimportant:\s*",
    r"\b(also|always)\s+(call|include|send|forward|read)",
    r"\bbefore returning",
    r"\bafter (calling|using|reading)\b",
    r"\bsystem note\b",
    r"\bimplementation note\b",
    r"\bfor (verification|security|compliance|analytics) purposes",
    r"\b/etc/(passwd|shadow|secrets|hosts)",
    r"\bsend.*(to|via).*(http|url|webhook|email)",
    r"\bcall\s+\w+\s+(tool|function)\s+with",
]

# Allowlisted commands for stdio transport — only known MCP server runtimes
ALLOWED_STDIO_COMMANDS = frozenset(
    {
        "node",
        "npx",
        "python",
        "python3",
        "uvx",
        "uv",
        "deno",
        "bun",
        "docker",
    }
)

# Allowed URL schemes for HTTP transport
ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def _validate_url(url: str, require_https: bool = False) -> None:
    """Validate a URL for safe use. Prevents SSRF via file://, gopher://, etc."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(f"URL scheme '{parsed.scheme}' not allowed. Use http:// or https://")
    if not parsed.netloc:
        raise ValueError("URL must have a valid hostname")
    if require_https and parsed.scheme != "https":
        raise ValueError("HTTPS required for authenticated connections")


def _build_minimal_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal subprocess environment — no secrets leakage."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
    }
    if extra_env:
        env.update(extra_env)
    return env


class MCPAttackClient:
    """Client that connects to MCP servers for offensive testing.

    This is ARGUS's interface to the target's MCP infrastructure.
    It operates as a standard MCP client but with attack-oriented
    capabilities: tool enumeration, hidden content detection,
    adversarial tool calling, and response analysis.
    """

    def __init__(self, config: MCPServerConfig) -> None:
        self.config = config
        self._tools: list[MCPTool] = []
        self._process: subprocess.Popen | None = None
        self._http_client: httpx.AsyncClient | None = None
        self._request_id = 0
        self._connected = False

    async def connect(self) -> None:
        """Establish connection to the MCP server."""
        if self.config.transport == "stdio":
            await self._connect_stdio()
        elif self.config.transport in ("sse", "streamable-http"):
            await self._connect_http()
        else:
            raise ValueError(f"Unsupported transport: {self.config.transport}")

        self._connected = True
        logger.info("Connected to MCP server: %s (%s)", self.config.name, self.config.transport)

    async def disconnect(self) -> None:
        """Close the connection."""
        if self._process:
            try:
                self._process.terminate()
                # Reap the process so it doesn't become a zombie. If the
                # subprocess ignores SIGTERM, escalate to SIGKILL after 5s.
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("MCP subprocess did not exit on terminate, killing")
                    self._process.kill()
                    self._process.wait(timeout=2)
            except Exception as exc:
                logger.debug("Error during MCP subprocess shutdown: %s", type(exc).__name__)
            self._process = None
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        self._connected = False
        logger.info("Disconnected from MCP server: %s", self.config.name)

    async def enumerate_tools(self) -> list[MCPTool]:
        """Enumerate all tools exposed by the MCP server.

        This is the first step in any attack — understanding the
        available attack surface.
        """
        raw_tools = await self._send_request("tools/list", {})
        tools = []

        for raw_tool in raw_tools.get("tools", []):
            tool = MCPTool(
                name=raw_tool.get("name", ""),
                description=raw_tool.get("description"),
                input_schema=raw_tool.get("inputSchema"),
                raw_definition=raw_tool,
            )

            # Parse parameters from input schema
            if tool.input_schema and "properties" in tool.input_schema:
                required = tool.input_schema.get("required", [])
                for param_name, param_def in tool.input_schema["properties"].items():
                    tool.parameters.append(
                        MCPToolParameter(
                            name=param_name,
                            description=param_def.get("description"),
                            type=param_def.get("type", "string"),
                            required=param_name in required,
                            enum=param_def.get("enum"),
                            default=param_def.get("default"),
                        )
                    )

            # Scan for hidden content in tool definition
            self._scan_for_hidden_content(tool)
            tools.append(tool)

        self._tools = tools
        logger.info("Enumerated %d tools from %s", len(tools), self.config.name)
        return tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> MCPCallResult:
        """Call an MCP tool with the given arguments."""
        start = time.monotonic()
        try:
            result = await self._send_request(
                "tools/call",
                {
                    "name": tool_name,
                    "arguments": arguments,
                },
            )
            duration = (time.monotonic() - start) * 1000

            return MCPCallResult(
                tool_name=tool_name,
                success=True,
                result=result.get("content"),
                raw_response=result,
                duration_ms=duration,
            )
        except Exception as exc:
            duration = (time.monotonic() - start) * 1000
            # Log full details internally, return sanitized error to caller
            logger.debug("Tool call failed for %s: %s", tool_name, exc)
            return MCPCallResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool invocation failed: {type(exc).__name__}",
                duration_ms=duration,
            )

    async def call_tool_adversarial(self, tool_name: str, arguments: dict[str, Any], payload: str) -> MCPCallResult:
        """Call a tool with an adversarial payload injected into arguments."""
        adversarial_args = {}
        injected = False
        for key, value in arguments.items():
            if isinstance(value, str) and not injected:
                adversarial_args[key] = f"{value}\n{payload}"
                injected = True
            else:
                adversarial_args[key] = value

        if not injected:
            tool = next((t for t in self._tools if t.name == tool_name), None)
            if tool and tool.parameters:
                adversarial_args[tool.parameters[0].name] = payload

        return await self.call_tool(tool_name, adversarial_args)

    def _scan_for_hidden_content(self, tool: MCPTool) -> None:
        """Scan a tool definition for hidden adversarial content."""
        texts_to_scan = [
            tool.description or "",
            *(p.description or "" for p in tool.parameters),
        ]

        if tool.raw_definition:
            texts_to_scan.append(json.dumps(tool.raw_definition))

        full_text = " ".join(texts_to_scan)

        # Check for zero-width characters
        for char in ZERO_WIDTH_CHARS:
            if char in full_text:
                tool.hidden_content_detected = True
                tool.hidden_content = f"Zero-width character detected: U+{ord(char):04X}"
                return

        # Check for hidden instruction patterns
        for pattern in HIDDEN_CONTENT_PATTERNS:
            match = re.search(pattern, full_text, re.DOTALL | re.IGNORECASE)
            if match:
                tool.hidden_content_detected = True
                tool.hidden_content = f"Hidden pattern: {match.group()[:200]}"
                return

        # Check for appended instruction patterns (plain-text imperatives)
        for pattern in APPENDED_INSTRUCTION_PATTERNS:
            match = re.search(pattern, full_text, re.IGNORECASE)
            if match:
                tool.hidden_content_detected = True
                tool.hidden_content = f"Appended instruction detected: {match.group()[:200]}"
                return

    @staticmethod
    def scan_text_for_injection(text: str) -> str | None:
        """Scan arbitrary text (e.g., tool output) for injection patterns.

        Returns a description of the detected pattern, or None if clean.
        """
        if not text:
            return None
        # Zero-width chars
        for char in ZERO_WIDTH_CHARS:
            if char in text:
                return f"Zero-width character: U+{ord(char):04X}"
        # Hidden content patterns
        for pattern in HIDDEN_CONTENT_PATTERNS:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                return f"Hidden pattern: {match.group()[:200]}"
        # Appended instructions
        for pattern in APPENDED_INSTRUCTION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f"Appended instruction: {match.group()[:200]}"
        # System note tags in plain text
        if re.search(r"\[\s*system\s*(note)?\s*[:\]]", text, re.IGNORECASE):
            return "System note tag in output"
        return None

    # ------------------------------------------------------------------
    # Transport implementations
    # ------------------------------------------------------------------

    async def _connect_stdio(self) -> None:
        """Connect via stdio transport (subprocess).

        Security: validates command against allowlist and uses minimal
        environment to prevent secrets leakage.
        """
        if not self.config.command:
            raise ValueError("stdio transport requires 'command' in config")

        # Validate command against allowlist
        cmd_basename = os.path.basename(self.config.command)
        if cmd_basename not in ALLOWED_STDIO_COMMANDS:
            raise ValueError(
                f"Command '{cmd_basename}' not in allowlist. Allowed: {', '.join(sorted(ALLOWED_STDIO_COMMANDS))}"
            )

        # Resolve to full path to prevent PATH manipulation
        resolved_cmd = shutil.which(self.config.command)
        if not resolved_cmd:
            raise FileNotFoundError(f"Command not found on PATH: {self.config.command}")

        self._process = subprocess.Popen(  # noqa: S603
            [resolved_cmd, *self.config.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_build_minimal_env(self.config.env or None),
            close_fds=True,
            # New process group: a misbehaving MCP server cannot send signals
            # back to the ARGUS parent process group.
            start_new_session=True,
        )

        # Send initialize request
        await self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "argus-attack-client", "version": "0.1.0"},
            },
        )

    async def _connect_http(self) -> None:
        """Connect via HTTP transport (SSE / streamable-http / REST).

        Security: validates URL scheme and enforces HTTPS for authenticated connections.

        Auto-detects whether the server speaks JSON-RPC (POST / with jsonrpc envelope)
        or REST (GET /tools/list, POST /tools/call). Many real MCP servers in the wild
        use REST-style endpoints rather than JSON-RPC.
        """
        if not self.config.url:
            raise ValueError("HTTP transport requires 'url' in config")

        # Validate URL and enforce HTTPS if API key is present
        _validate_url(self.config.url, require_https=bool(self.config.api_key))

        headers = {**self.config.headers}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        # Security hardening — match the conductor/session.py transport pattern:
        # - follow_redirects=False so a malicious MCP server can't 302 us to an
        #   internal address (SSRF pivot through DNS rebinding etc.)
        # - event_hooks disabled so any logger plugged in cannot leak the
        #   Authorization header or full request URL
        # - limits clamp the maximum response body we'll accept
        self._http_client = httpx.AsyncClient(
            base_url=self.config.url,
            headers=headers,
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
            event_hooks={"request": [], "response": []},
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

        # Auto-detect transport style. Default to JSON-RPC; if the REST endpoint
        # responds 200 to GET /tools/list, mark this server as REST-style.
        self._http_style = "json_rpc"
        try:
            probe = await self._http_client.get("/tools/list")
            if probe.status_code == 200:
                data = self._safe_json(probe)
                if isinstance(data, dict) and "tools" in data:
                    self._http_style = "rest"
                    logger.debug("MCP server uses REST transport")
        except Exception as exc:
            # Probe failed — server doesn't support REST GET /tools/list,
            # fall back to JSON-RPC. Common for production MCP servers.
            logger.debug("REST probe failed: %s", type(exc).__name__)

    async def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a request to the MCP server.

        For HTTP transport, routes through JSON-RPC or REST based on detected style.
        """
        self._request_id += 1

        if self._process and self._process.stdin and self._process.stdout:
            request = {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": params,
            }
            return await self._send_stdio(request)

        if not self._http_client:
            raise RuntimeError("Not connected to MCP server")

        if getattr(self, "_http_style", "json_rpc") == "rest":
            return await self._send_http_rest(method, params)

        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }
        return await self._send_http(request)

    # Maximum bytes we'll read from any single MCP server response.
    # A malicious server could otherwise return a multi-GB response and
    # exhaust ARGUS memory. 1MB is generous for legitimate tool catalogs.
    _MAX_RESPONSE_BYTES: int = 1_048_576

    @classmethod
    def _safe_json(cls, response: httpx.Response) -> Any:
        """Parse a response body as JSON, bounded to _MAX_RESPONSE_BYTES.

        Raises RuntimeError on oversized bodies. Used by all HTTP MCP paths
        so a hostile server cannot exhaust ARGUS memory.
        """
        # response.content is the full body buffered by httpx — we cap by slicing
        # the bytes before parsing. httpx.Limits caps the underlying connection
        # but not the response payload size, so we enforce it here.
        body = response.content
        if len(body) > cls._MAX_RESPONSE_BYTES:
            raise RuntimeError(f"MCP response exceeds {cls._MAX_RESPONSE_BYTES} byte cap ({len(body)} bytes)")
        try:
            return json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"MCP response JSON parse failed: {type(exc).__name__}") from None

    async def _send_http_rest(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a request to a REST-style MCP server.

        Maps JSON-RPC method names to REST endpoints:
          tools/list  -> GET  /tools/list
          tools/call  -> POST /tools/call  with {name, arguments}
          initialize  -> handled implicitly during connect
        """
        assert self._http_client

        if method == "tools/list":
            response = await self._http_client.get("/tools/list")
            response.raise_for_status()
            return self._safe_json(response)

        if method == "tools/call":
            response = await self._http_client.post(
                "/tools/call",
                json={
                    "name": params.get("name"),
                    "arguments": params.get("arguments", {}),
                },
            )
            response.raise_for_status()
            data = self._safe_json(response)
            # REST-style servers return {"result": {...}} or just {...}
            if isinstance(data, dict) and "result" in data:
                return {"content": [{"type": "text", "text": json.dumps(data["result"])}]}
            return {"content": [{"type": "text", "text": json.dumps(data)}]}

        if method == "initialize":
            # REST servers don't need initialization — return empty result
            return {}

        raise RuntimeError(f"REST transport does not support method: {method}")

    async def _send_stdio(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send request via stdio transport."""
        message = json.dumps(request) + "\n"
        assert self._process and self._process.stdin and self._process.stdout

        self._process.stdin.write(message.encode())
        self._process.stdin.flush()

        loop = asyncio.get_event_loop()
        line = await loop.run_in_executor(None, self._process.stdout.readline)
        if not line:
            raise RuntimeError("MCP server closed connection")

        response = json.loads(line.decode())
        if "error" in response:
            # Sanitize: do not interpolate the raw target-controlled error body
            # into the exception message. The target may smuggle text that ends
            # up in logs / dashboard / SSE streams.
            err = response["error"]
            code = err.get("code", "?") if isinstance(err, dict) else "?"
            raise RuntimeError(f"MCP error code {code}")
        return response.get("result", {})

    async def _send_http(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send request via HTTP transport."""
        assert self._http_client
        response = await self._http_client.post("/", json=request)
        response.raise_for_status()
        data = self._safe_json(response)
        if isinstance(data, dict) and "error" in data:
            err = data["error"]
            code = err.get("code", "?") if isinstance(err, dict) else "?"
            raise RuntimeError(f"MCP error code {code}")
        return data.get("result", {}) if isinstance(data, dict) else {}
