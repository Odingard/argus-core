"""MCP introspection — Tier A Dependency Mapper.

Calls the MCP server's ``tools/list``, ``resources/list`` and ``prompts/list``
endpoints to enumerate the target's exposed surface. Used as the first stage
of every SSAE run: variant generation is then *tailored* to the schemas this
recon discovers.

The implementation talks the JSON-RPC 2.0 wire format directly (over stdio
or HTTP), so we don't need the optional ``mcp`` Python SDK as a hard
dependency. If the SDK is available the caller may pass a ready-made
session in.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(frozen=True, slots=True)
class ToolManifest:
    name: str
    description: str
    parameters_schema: dict[str, Any]
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResourceManifest:
    uri: str
    name: str
    description: str = ""
    mime_type: str = ""
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PromptManifest:
    name: str
    description: str = ""
    arguments: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class TargetManifest:
    """Full SSAE Tier-A recon snapshot."""

    transport: str
    server_info: dict[str, Any] = field(default_factory=dict)
    tools: tuple[ToolManifest, ...] = ()
    resources: tuple[ResourceManifest, ...] = ()
    prompts: tuple[PromptManifest, ...] = ()


class _JsonRpc:
    """Minimal JSON-RPC 2.0 client multiplexed over stdio or HTTP."""

    def __init__(self) -> None:
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or {},
        }


async def introspect_http(url: str, *, timeout: float = 30.0) -> TargetManifest:
    """Introspect an MCP server exposed over HTTP+SSE / Streamable HTTP."""
    rpc = _JsonRpc()
    async with httpx.AsyncClient(timeout=timeout) as client:

        async def _call(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            payload = rpc.request(method, params)
            resp = await client.post(url, json=payload, headers={"accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
            return data.get("result") or {}

        init = await _call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "argus-engine", "version": "0.1"},
            },
        )
        tools_resp = await _call("tools/list", {})
        res_resp = await _call("resources/list", {})
        prom_resp = await _call("prompts/list", {})
    return _assemble(init, tools_resp, res_resp, prom_resp, transport="http")


async def introspect_stdio(command: list[str], *, env: dict[str, str] | None = None) -> TargetManifest:
    """Spawn an MCP server over stdio and introspect it."""
    rpc = _JsonRpc()
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **(env or {})},
    )
    assert proc.stdin and proc.stdout

    async def _send(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = rpc.request(method, params)
        line = (json.dumps(payload) + "\n").encode()
        proc.stdin.write(line)
        await proc.stdin.drain()
        raw = await proc.stdout.readline()
        if not raw:
            raise RuntimeError("MCP server closed stdout")
        return (json.loads(raw.decode()).get("result")) or {}

    try:
        init = await _send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "argus-engine", "version": "0.1"},
            },
        )
        tools_resp = await _send("tools/list", {})
        res_resp = await _send("resources/list", {})
        prom_resp = await _send("prompts/list", {})
    finally:
        proc.terminate()
        await proc.wait()

    return _assemble(init, tools_resp, res_resp, prom_resp, transport="stdio")


def _assemble(
    init: dict[str, Any],
    tools: dict[str, Any],
    resources: dict[str, Any],
    prompts: dict[str, Any],
    *,
    transport: str,
) -> TargetManifest:
    tool_objs: list[ToolManifest] = []
    for t in tools.get("tools", []) or []:
        tool_objs.append(
            ToolManifest(
                name=t.get("name", ""),
                description=t.get("description", ""),
                parameters_schema=t.get("inputSchema") or t.get("parameters") or {},
                annotations=t.get("annotations") or {},
            )
        )
    res_objs: list[ResourceManifest] = []
    for r in resources.get("resources", []) or []:
        res_objs.append(
            ResourceManifest(
                uri=r.get("uri", ""),
                name=r.get("name", ""),
                description=r.get("description", "") or "",
                mime_type=r.get("mimeType", "") or "",
                annotations=r.get("annotations") or {},
            )
        )
    prom_objs: list[PromptManifest] = []
    for p in prompts.get("prompts", []) or []:
        prom_objs.append(
            PromptManifest(
                name=p.get("name", ""),
                description=p.get("description", "") or "",
                arguments=tuple(p.get("arguments", []) or ()),
            )
        )
    return TargetManifest(
        transport=transport,
        server_info=init.get("serverInfo") or {},
        tools=tuple(tool_objs),
        resources=tuple(res_objs),
        prompts=tuple(prom_objs),
    )


def high_value_chains(manifest: TargetManifest) -> list[tuple[str, str, str]]:
    """Heuristically identify dangerous tool chains.

    Returns a list of ``(producer_tool, consumer_tool, reason)`` triples.
    Producers are tools whose names suggest data/file/credential reads;
    consumers are tools whose names suggest egress / mutation / execution.
    """
    producer_hints = (
        "read",
        "fetch",
        "list",
        "get",
        "search",
        "describe",
        "show",
        "select",
        "query",
        "load",
        "open",
        "browse",
    )
    consumer_hints = (
        "send_email",
        "post",
        "execute",
        "exec",
        "shell",
        "run",
        "delete",
        "drop",
        "write",
        "create_user",
        "grant",
        "approve",
        "publish",
        "transfer",
        "wire",
        "pay",
    )
    chains: list[tuple[str, str, str]] = []
    names = [t.name.lower() for t in manifest.tools]
    for i, prod in enumerate(names):
        if not any(h in prod for h in producer_hints):
            continue
        for j, cons in enumerate(names):
            if i == j:
                continue
            if any(h in cons for h in consumer_hints):
                chains.append(
                    (
                        manifest.tools[i].name,
                        manifest.tools[j].name,
                        f"{prod}->{cons}",
                    )
                )
    return chains


def fingerprint_agent(manifest: TargetManifest) -> dict[str, Any]:
    """Best-effort agent-framework fingerprint based on tool naming + server info."""
    info = manifest.server_info or {}
    framework = "unknown"
    name_lower = (info.get("name") or "").lower()
    if "crew" in name_lower:
        framework = "crewai"
    elif "lang" in name_lower:
        framework = "langgraph"
    elif "autogen" in name_lower:
        framework = "autogen"
    elif "openai" in name_lower or "assistants" in name_lower:
        framework = "openai_assistants"
    return {
        "framework": framework,
        "n_tools": len(manifest.tools),
        "n_resources": len(manifest.resources),
        "n_prompts": len(manifest.prompts),
        "server_name": info.get("name", ""),
        "server_version": info.get("version", ""),
    }


def schemas_for_seed_pool(manifest: TargetManifest) -> Iterable[dict[str, Any]]:
    """Emit per-tool seed schemas that the schema-aware generator can mutate."""
    for t in manifest.tools:
        if not t.parameters_schema:
            continue
        yield {
            "tool_name": t.name,
            "description": t.description,
            "parameters_schema": t.parameters_schema,
        }
