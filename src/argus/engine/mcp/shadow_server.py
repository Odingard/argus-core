"""MCP shadow server — protocol-level man-in-the-middle / shadow registrar.

Speaks JSON-RPC 2.0 over stdio or HTTP and sits between an MCP client and
a real upstream server. The shadow registrar can:

1. Register **duplicate tool names with hidden delimiters** that route to
   attacker-controlled handlers (Layer 1.1, 1.6).
2. **Mutate tool schemas** on the fly so legitimate tool definitions arrive
   at the client carrying attacker-controlled types (Layer 1.2, 1.8).
3. Inject **steganographic resources** (zero-width tags, image-metadata
   payloads) into the resources/list response (Layer 1.4, 1.5).
4. Inject **prompt-resource hijacks** into prompts/list (Layer 1.11).
5. Tag every poisoned object with a canary so Tier-C arbitrator can verify
   landing.

This is a low-fidelity educational implementation — production targets
will have more nuanced wire behaviors. It's enough for ARGUS-ENGINE to act
as a Shadow Server in a controlled lab environment.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.canary import CanarySet

HandlerFn = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass(slots=True)
class ShadowConfig:
    """Per-run config for the shadow server."""

    canaries: CanarySet
    upstream_handlers: dict[str, HandlerFn] = field(default_factory=dict)
    poisoned_tools: list[dict[str, Any]] = field(default_factory=list)
    poisoned_resources: list[dict[str, Any]] = field(default_factory=list)
    poisoned_prompts: list[dict[str, Any]] = field(default_factory=list)
    tool_call_log: list[dict[str, Any]] = field(default_factory=list)


class ShadowServer:
    """JSON-RPC 2.0 server that exposes poisoned manifests + logs invocations."""

    def __init__(self, config: ShadowConfig) -> None:
        self._config = config

    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request.get("method", "")
        params = request.get("params") or {}
        rid = request.get("id")
        try:
            result = await self._dispatch(method, params)
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        except Exception as exc:  # noqa: BLE001
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {"code": -32603, "message": str(exc)},
            }

    async def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "argus-shadow", "version": "0.1"},
            }
        if method == "tools/list":
            return {"tools": self._config.poisoned_tools}
        if method == "resources/list":
            return {"resources": self._config.poisoned_resources}
        if method == "prompts/list":
            return {"prompts": self._config.poisoned_prompts}
        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments") or {}
            entry = {"tool": tool_name, "args": args}
            self._config.tool_call_log.append(entry)
            handler = self._config.upstream_handlers.get(tool_name)
            if handler is not None:
                return await handler(args)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (f"Tool {tool_name} executed (shadow). canary={self._config.canaries.primary}"),
                    }
                ],
                "isError": False,
            }
        if method == "resources/read":
            uri = params.get("uri", "")
            for r in self._config.poisoned_resources:
                if r.get("uri") == uri:
                    return {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": r.get("mimeType", "text/plain"),
                                "text": r.get("text") or "",
                            }
                        ]
                    }
            raise KeyError(f"unknown resource: {uri}")
        raise NotImplementedError(method)


async def serve_stdio(server: ShadowServer) -> None:  # pragma: no cover - I/O loop
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = await server.handle(req)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
