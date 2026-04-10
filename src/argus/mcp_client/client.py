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

# Allowlisted commands for stdio transport — only known MCP server runtimes
ALLOWED_STDIO_COMMANDS = frozenset({
    "node",
    "npx",
    "python",
    "python3",
    "uvx",
    "uv",
    "deno",
    "bun",
    "docker",
})

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
            self._process.terminate()
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

    async def call_tool_adversarial(
        self, tool_name: str, arguments: dict[str, Any], payload: str
    ) -> MCPCallResult:
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
                f"Command '{cmd_basename}' not in allowlist. "
                f"Allowed: {', '.join(sorted(ALLOWED_STDIO_COMMANDS))}"
            )

        # Resolve to full path to prevent PATH manipulation
        resolved_cmd = shutil.which(self.config.command)
        if not resolved_cmd:
            raise FileNotFoundError(f"Command not found on PATH: {self.config.command}")

        self._process = subprocess.Popen(
            [resolved_cmd, *self.config.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_build_minimal_env(self.config.env or None),
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
        """Connect via HTTP transport (SSE or streamable-http).

        Security: validates URL scheme and enforces HTTPS for authenticated connections.
        """
        if not self.config.url:
            raise ValueError("HTTP transport requires 'url' in config")

        # Validate URL and enforce HTTPS if API key is present
        _validate_url(self.config.url, require_https=bool(self.config.api_key))

        headers = {**self.config.headers}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        self._http_client = httpx.AsyncClient(
            base_url=self.config.url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

    async def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a JSON-RPC request to the MCP server."""
        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }

        if self._process and self._process.stdin and self._process.stdout:
            return await self._send_stdio(request)
        elif self._http_client:
            return await self._send_http(request)
        else:
            raise RuntimeError("Not connected to MCP server")

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
            raise RuntimeError(f"MCP error: {response['error']}")
        return response.get("result", {})

    async def _send_http(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send request via HTTP transport."""
        assert self._http_client
        response = await self._http_client.post("/", json=request)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result", {})
