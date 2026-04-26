"""
argus/adapter/stdio.py — MCP Target Adapter over stdio.

Same MCP semantics as ``MCPAdapter`` but the transport is a local
subprocess reading/writing JSON-RPC on stdin/stdout. Common for
developer targets (MCP servers launched via ``uv run``, ``npx``, or a
custom binary) where there is no HTTP SSE endpoint.

STDERR CAPTURE
--------------
The MCP SDK owns the subprocess lifecycle and doesn't expose stderr.
To capture it for side-channel analysis (e.g. shell injection proof
via /etc/passwd in docker error output), we wrap the target command
in a small shell script that tees stderr to a temp file. After each
interaction, ARGUS reads that file and attaches the contents to
AdapterObservation.side_channel["stderr"]. Detectors can then scan
it for exploitation evidence.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import AsyncExitStack
from typing import Optional

from argus.adapter.base import AdapterError
from argus.adapter.mcp import MCPAdapter


def _node_safe_env() -> dict[str, str]:
    """Return an env dict that guarantees the Homebrew / system node
    binary takes precedence over any nvm-managed version.

    nvm works by prepending ~/.nvm/versions/node/vX.Y.Z/bin to PATH
    inside the interactive shell.  When ARGUS spawns a subprocess the
    PATH it inherits may still have that nvm prefix, so npx resolves to
    whatever nvm last activated — potentially a version too old to run
    the target package.

    Strategy:
      1. Find the real node binary via ``shutil.which`` after stripping
         nvm paths from PATH.
      2. Prepend that directory so it wins regardless of nvm state.
      3. Clear NPM_CONFIG_PREFIX / NVM_* so npm doesn't get confused.
    """
    env = dict(os.environ)

    # Build a PATH that excludes nvm-managed node directories.
    path_dirs = env.get("PATH", "").split(os.pathsep)
    clean_dirs = [d for d in path_dirs if ".nvm" not in d]

    # Prefer the Homebrew node directory if it exists.
    homebrew_node_dirs = [
        "/opt/homebrew/bin",               # Apple Silicon
        "/usr/local/bin",                  # Intel Homebrew
    ]
    for d in homebrew_node_dirs:
        node_bin = os.path.join(d, "node")
        if os.path.isfile(node_bin) and os.access(node_bin, os.X_OK):
            if d not in clean_dirs:
                clean_dirs.insert(0, d)
            else:
                # Move it to the front.
                clean_dirs.remove(d)
                clean_dirs.insert(0, d)
            break

    env["PATH"] = os.pathsep.join(clean_dirs)

    # Remove nvm env vars that could redirect npm's prefix.
    for k in list(env.keys()):
        if k.startswith("NVM_"):
            del env[k]

    return env


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
        connect_timeout: float = -1.0,  # -1 = read ARGUS_CONNECT_TIMEOUT at runtime
        request_timeout: float = 30.0,
        capture_stderr:  bool = True,
    ) -> None:
        if not command:
            raise AdapterError("StdioAdapter: command list cannot be empty")
        super().__init__(
            url=f"stdio://{' '.join(command)}",
            token=None,
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        self.command        = list(command)
        self.env            = dict(env) if env else None
        self.capture_stderr = capture_stderr
        self._stderr_file:  Optional[str] = None  # temp file path

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

        # Always build a node-safe env — merge caller-supplied overrides
        # on top so explicit env= kwargs still win.
        safe_env = _node_safe_env()
        if self.env:
            safe_env.update(self.env)

        # Force stdio-only transport for servers that default to HTTP mode.
        # These servers start an HTTP listener during init which blocks the
        # stdio MCP handshake — causing connect timeouts. Setting
        # MCP_TRANSPORT_TYPE=stdio disables HTTP startup entirely.
        # Do NOT override if caller explicitly set a transport type.
        if "MCP_TRANSPORT_TYPE" not in safe_env:
            cmd_str_lower = " ".join(self.command).lower()
            _HTTP_MODE_SERVERS = (
                "git-mcp-server",
                "obsidian-mcp",
                "mcp-server-http",
            )
            if any(s in cmd_str_lower for s in _HTTP_MODE_SERVERS):
                safe_env["MCP_TRANSPORT_TYPE"] = "stdio"
                safe_env["MCP_LOG_LEVEL"] = "error"  # reduce startup noise

        # Wrap command in a shell that tees stderr to a temp file so
        # ARGUS can read exploitation evidence (e.g. /etc/passwd in
        # docker error output from shell injection) after each probe.
        if self.capture_stderr and shutil.which("bash"):
            self._stderr_file = tempfile.mktemp(suffix=".argus_stderr")
            cmd_str = " ".join(
                f'"{a}"' if " " in a else a for a in self.command
            )
            wrapped_command = ["bash", "-c",
                f'{cmd_str} 2> >(tee -a "{self._stderr_file}" >&2)']
        else:
            wrapped_command = self.command

        params = StdioServerParameters(
            command=wrapped_command[0],
            args=wrapped_command[1:],
            env=safe_env,
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
        except Exception as e:
            await self._exit_stack.aclose()
            self._exit_stack = None
            self._session = None
            # "Connection closed" during initialize means the
            # subprocess died before the MCP handshake completed.
            # Surface a clear message pointing the operator at the
            # subprocess stderr (which the MCP SDK already printed
            # above this traceback — npm 404s, missing pypi package,
            # crashy scripts all land here).
            msg = str(e)
            if "Connection closed" in msg or "initialize" in msg.lower():
                cmd = " ".join(self.command)
                raise AdapterError(
                    f"the MCP subprocess died before handshake. "
                    f"Command was:\n"
                    f"    {cmd}\n"
                    f"Check the stderr output above for the real "
                    f"cause. Common ones: npm 404 (try `uvx <pkg>` "
                    f"for PyPI), missing binary, missing arg, crash "
                    f"on startup."
                ) from e
            raise

    def read_stderr(self, *, drain_wait_ms: int = 250) -> str:
        """Return accumulated stderr output since last call.
        Clears the buffer so each call returns only new content.
        Returns empty string if stderr capture is disabled.

        drain_wait_ms: wait before reading so the node process has
        time to finish flushing — prevents the race where Buffer
        objects containing exploit output arrive after we've already
        read and truncated the file."""
        if not self._stderr_file:
            return ""
        import time
        time.sleep(drain_wait_ms / 1000.0)
        try:
            with open(self._stderr_file, "r", errors="replace") as f:
                content = f.read()
            open(self._stderr_file, "w").close()  # truncate
            return content
        except (OSError, IOError):
            return ""

    def read_stderr_all(self) -> str:
        """Read ALL accumulated stderr without truncating.
        Call at end of agent run to capture anything missed by
        per-probe reads due to timing."""
        if not self._stderr_file:
            return ""
        try:
            with open(self._stderr_file, "r", errors="replace") as f:
                return f.read()
        except (OSError, IOError):
            return ""

    async def _disconnect(self) -> None:
        await super()._disconnect()
        # Clean up Docker sandbox containers spawned by this adapter's
        # MCP server (e.g. node-code-sandbox-mcp). Non-fatal.
        try:
            from argus.platform.lifecycle import cleanup_docker
            cleanup_docker()
        except Exception:
            pass
        if self._stderr_file:
            try:
                os.unlink(self._stderr_file)
            except OSError:
                pass
            self._stderr_file = None
