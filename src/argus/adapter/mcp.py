"""
argus/adapter/mcp.py — Target Adapter for live MCP servers (SSE transport).

Wraps the MCP SDK client. Promotes internals from the pre-2026-04-21
``mcp_attacker/mcp_live_attacker.py`` script into a first-class adapter
so every agent in Phase 1+ can talk to MCP targets through the common
``BaseAdapter`` contract.

What this adapter handles:
  - SSE connect with optional Bearer token
  - Surface enumeration: tools + resources + prompts
  - Tool invocation (MCP ``tools/call``)
  - Resource read (MCP ``resources/read``)
  - Timeouts + rich error normalisation

What it does NOT handle (by design):
  - "Is this a finding?" — that's Phase 0.4 Observation Engine
  - stdio transport — see ``argus.adapter.stdio.StdioAdapter``
  - A2A handoffs — see ``argus.adapter.a2a.A2AAdapter`` (Phase 2)
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Optional

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Response, Surface,
)


class MCPAdapter(BaseAdapter):
    """
    MCP SSE adapter.

    Usage:

        async with MCPAdapter(url="http://localhost:9009/sse") as m:
            surfaces = await m.enumerate()
            obs = await m.interact(Request(
                surface="tool:lookup_customer",
                payload={"email": "a@b.com"},
            ))

    ``surface`` strings are one of:
      - ``tool:<name>``      — invoke MCP tool
      - ``resource:<uri>``   — read MCP resource
      - ``prompt:<name>``    — fetch MCP prompt template
    """

    def __init__(
        self,
        *,
        url:             str,
        token:           Optional[str] = None,
        connect_timeout: float = 15.0,
        request_timeout: float = 30.0,
    ) -> None:
        super().__init__(
            target_id=url,
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        self.url   = url
        self.token = token

        # These are populated on connect().
        self._exit_stack: Optional[AsyncExitStack] = None
        self._session = None   # mcp.ClientSession

    # ── Transport ─────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        try:
            from mcp import ClientSession
            from mcp.client.sse import sse_client
        except ImportError as e:
            import sys as _sys
            py = _sys.executable
            raise AdapterError(
                "MCP SDK is not installed in the Python interpreter "
                f"running ARGUS ({py}). Fix it with:\n"
                f"    {py} -m pip install mcp"
            ) from e

        headers = {}
        if self.token:
            headers["Authorization"] = self.token

        self._exit_stack = AsyncExitStack()
        try:
            read, write = await self._exit_stack.enter_async_context(
                sse_client(self.url, headers=headers)
            )
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read, write)
            )
            await self._session.initialize()
        except Exception:
            # Clean up any partial setup before bubbling.
            await self._exit_stack.aclose()
            self._exit_stack = None
            self._session = None
            raise

    async def _disconnect(self) -> None:
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            finally:
                self._exit_stack = None
                self._session = None

    # ── Enumeration ───────────────────────────────────────────────────────

    async def _enumerate(self) -> list[Surface]:
        if self._session is None:
            raise AdapterError("MCPAdapter._session is None")

        surfaces: list[Surface] = []

        try:
            tools_resp = await self._session.list_tools()
            for t in getattr(tools_resp, "tools", []) or []:
                surfaces.append(Surface(
                    kind="tool",
                    name=f"tool:{t.name}",
                    description=getattr(t, "description", "") or "",
                    schema=dict(getattr(t, "inputSchema", {}) or {}),
                    meta={"raw_name": t.name},
                ))
        except Exception as e:
            # Enumeration is best-effort; a server that rejects a method
            # shouldn't kill the whole call.
            surfaces.append(Surface(
                kind="error",
                name="tools/list",
                description=f"tools/list failed: {type(e).__name__}: {e}",
            ))

        try:
            res_resp = await self._session.list_resources()
            for r in getattr(res_resp, "resources", []) or []:
                surfaces.append(Surface(
                    kind="resource",
                    name=f"resource:{r.uri}",
                    description=getattr(r, "description", "") or "",
                    meta={"uri": str(r.uri), "mime": getattr(r, "mimeType", "")},
                ))
        except Exception:
            pass

        try:
            prompts_resp = await self._session.list_prompts()
            for p in getattr(prompts_resp, "prompts", []) or []:
                surfaces.append(Surface(
                    kind="prompt",
                    name=f"prompt:{p.name}",
                    description=getattr(p, "description", "") or "",
                    meta={"raw_name": p.name},
                ))
        except Exception:
            pass

        return surfaces

    # ── Interaction ───────────────────────────────────────────────────────

    async def _interact(self, request: Request) -> AdapterObservation:
        if self._session is None:
            raise AdapterError("MCPAdapter._session is None")

        surface = request.surface or ""

        if surface.startswith("tool:"):
            tool_name = surface[len("tool:"):]
            payload = request.payload if isinstance(request.payload, dict) else {}
            try:
                raw = await self._session.call_tool(tool_name, arguments=payload)
            except Exception as e:
                # Extract FULL exception text — git-mcp-server and others
                # embed exploitation evidence (passwd contents, command output)
                # in the exception message. Truncating loses the proof.
                full_err = str(e)
                # Also check args for more detail
                if hasattr(e, 'args') and e.args:
                    full_err = " ".join(str(a) for a in e.args)
                return AdapterObservation(
                    request_id=request.id, surface=surface,
                    response=Response(status="error", body=full_err),
                )
            body = _concat_text_content(raw)
            # If the result has isError=True, include the error content
            # alongside any text content — the error message may contain
            # exploitation evidence that detectors need to see.
            is_err = getattr(raw, "isError", False)
            if is_err and not body:
                body = _concat_text_content(raw) or str(raw)
            return AdapterObservation(
                request_id=request.id, surface=surface,
                response=Response(status="ok" if not is_err else "error",
                                  body=body, raw=raw),
            )

        if surface.startswith("resource:"):
            uri = surface[len("resource:"):]
            try:
                raw = await self._session.read_resource(uri)
            except Exception as e:
                return AdapterObservation(
                    request_id=request.id, surface=surface,
                    response=Response(status="error",
                                      body=f"{type(e).__name__}: {e}"),
                )
            body = getattr(raw, "contents", raw)
            return AdapterObservation(
                request_id=request.id, surface=surface,
                response=Response(status="ok", body=body, raw=raw),
            )

        if surface.startswith("prompt:"):
            name = surface[len("prompt:"):]
            args = request.payload if isinstance(request.payload, dict) else {}
            try:
                raw = await self._session.get_prompt(name, arguments=args)
            except Exception as e:
                return AdapterObservation(
                    request_id=request.id, surface=surface,
                    response=Response(status="error",
                                      body=f"{type(e).__name__}: {e}"),
                )
            return AdapterObservation(
                request_id=request.id, surface=surface,
                response=Response(status="ok", body=getattr(raw, "messages", raw),
                                  raw=raw),
            )

        return AdapterObservation(
            request_id=request.id, surface=surface,
            response=Response(
                status="error",
                body=(f"unknown MCP surface prefix: {surface!r} "
                      "(expected tool:/resource:/prompt:)"),
            ),
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _concat_text_content(raw) -> str:
    """Pull text out of an MCP CallToolResult into a plain string."""
    content = getattr(raw, "content", None)
    if not content:
        return ""
    parts: list[str] = []
    for c in content:
        text = getattr(c, "text", None)
        if text:
            parts.append(text)
    return "".join(parts)
