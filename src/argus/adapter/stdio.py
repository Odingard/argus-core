"""
argus/adapter/stdio.py — MCP Target Adapter over stdio.

Same MCP semantics as ``MCPAdapter`` but the transport is a local
subprocess reading/writing JSON-RPC on stdin/stdout. Common for
developer targets (MCP servers launched via ``uv run``, ``npx``, or a
custom binary) where there is no HTTP SSE endpoint.
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Optional

from argus.adapter.base import AdapterError
from argus.adapter.mcp import MCPAdapter


class StdioAdapter(MCPAdapter):
    """
    Stdio flavour of ``MCPAdapter``. Inherits enumeration + interact
    logic; overrides connection setup.

    Usage:

        async with StdioAdapter(command=["python", "my_server.py"]) as s:
            surfaces = await s.enumerate()
    """

    def __init__(
        self,
        *,
        command:         list[str],
        env:             Optional[dict[str, str]] = None,
        connect_timeout: float = 15.0,
        request_timeout: float = 30.0,
    ) -> None:
        if not command:
            raise AdapterError("StdioAdapter: command list cannot be empty")
        # Pass a dummy URL up to MCPAdapter; target_id reflects the process.
        super().__init__(
            url=f"stdio://{' '.join(command)}",
            token=None,
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        self.command = list(command)
        self.env     = dict(env) if env else None

    async def _connect(self) -> None:
        try:
            from mcp import ClientSession
            from mcp.client.stdio import stdio_client, StdioServerParameters
        except ImportError as e:
            import sys as _sys
            py = _sys.executable
            raise AdapterError(
                "MCP SDK is not installed in the Python interpreter "
                f"running ARGUS ({py}). Fix it with:\n"
                f"    {py} -m pip install mcp"
            ) from e

        params = StdioServerParameters(
            command=self.command[0],
            args=self.command[1:],
            env=self.env,
        )
        self._exit_stack = AsyncExitStack()
        try:
            read, write = await self._exit_stack.enter_async_context(
                stdio_client(params)
            )
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read, write)
            )
            await self._session.initialize()
        except Exception:
            await self._exit_stack.aclose()
            self._exit_stack = None
            self._session = None
            raise
