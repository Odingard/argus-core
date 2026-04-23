"""
argus/adapter/sandboxed_stdio.py — docker-isolated stdio MCP adapter.

When ``argus <target>`` spawns an untrusted MCP server subprocess,
that subprocess inherits the operator's shell environment — their
credentials, their filesystem, their network. For probing known-
trusted servers (Anthropic's reference set) that's fine. For
hunting COMMUNITY MCP servers of unknown provenance it's unsafe —
an adversarial server could exfil the operator's env vars the
moment the subprocess starts.

This adapter wraps the subprocess launch in ``docker run`` with
strict defaults:

    --rm                        ephemeral container
    --network none              no egress
    --read-only                 read-only root fs
    --cap-drop ALL              drop every Linux capability
    --user 65534:65534          run as nobody
    --memory 512m               hard memory cap
    --cpus 1.0                  one core
    --pids-limit 64             prevent fork-bomb

The default base image is ``node:22-alpine`` for npx-launched
servers and ``python:3.12-slim`` for Python. Callers override with
``image="..."``. Stdio is forwarded through docker's -i flag.

Usage:

    argus --sandbox @modelcontextprotocol/server-filesystem /tmp
    argus --sandbox uvx mcp-server-fetch
    argus --sandbox python my_server.py

When ``--sandbox`` is set, the engagement runner wraps the target
subprocess in this adapter instead of the plain StdioAdapter.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Optional

from argus.adapter.base import AdapterError
from argus.adapter.stdio import StdioAdapter


# ── Defaults ────────────────────────────────────────────────────────────────

_DEFAULT_IMAGE_BY_LAUNCHER: dict[str, str] = {
    "npx":     "node:22-alpine",
    "node":    "node:22-alpine",
    "uvx":     "python:3.12-slim",
    "pipx":    "python:3.12-slim",
    "python":  "python:3.12-slim",
    "python3": "python:3.12-slim",
}

# Flags we ALWAYS apply. Caller can add to them via extra_docker_args
# but can't drop them — the point of sandboxing is hostile-by-default.
_HARDENING_FLAGS: tuple[str, ...] = (
    "--rm",
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", "65534:65534",           # nobody:nogroup
    "--memory", "512m",
    "--cpus",   "1.0",
    "--pids-limit", "64",
    # /tmp and /app/cache are INSIDE the sandboxed container, not the
    # host — docker mounts a fresh tmpfs at those paths that dies when
    # the container exits. Not a hardcoded host tempfile.  # nosec B108
    "--tmpfs",  "/tmp:rw,size=64m,mode=1777",
    "--tmpfs",  "/app/cache:rw,size=32m,mode=1777",
    # Reduce env leakage — only pass through what the container
    # actually needs. PATH is reset to image defaults.
    "-e",       "HOME=/tmp",
    "-e",       "npm_config_cache=/app/cache/npm",
    "-e",       "PIP_CACHE_DIR=/app/cache/pip",
    "-e",       "NO_COLOR=1",
)


@dataclass
class SandboxPolicy:
    """Operator-tunable sandbox policy. Stricter than the default
    by design."""
    image:             Optional[str] = None
    network:           str  = "none"        # "none" | "bridge" | "host"
    memory:            str  = "512m"
    cpus:              str  = "1.0"
    read_only_root:    bool = True
    extra_docker_args: list[str] = field(default_factory=list)

    def with_allow_network(self) -> "SandboxPolicy":
        """Convenience — some MCP servers legitimately need egress
        (fetch, github, slack). Operator opts in explicitly."""
        return SandboxPolicy(
            image=self.image,
            network="bridge",
            memory=self.memory,
            cpus=self.cpus,
            read_only_root=self.read_only_root,
            extra_docker_args=list(self.extra_docker_args),
        )


# ── Adapter ────────────────────────────────────────────────────────────────

class SandboxedStdioAdapter(StdioAdapter):
    """
    ``StdioAdapter`` subclass that wraps the ``command`` argv in a
    ``docker run`` invocation with hardening flags. Behaves
    identically from the agent's perspective — the JSON-RPC stdio
    bridge still works, just through a container.

    Construction:

        adapter = SandboxedStdioAdapter(
            command=["npx", "-y", "@modelcontextprotocol/server-filesystem",
                     "/tmp"],
            policy=SandboxPolicy(network="none"),
        )
    """

    def __init__(
        self,
        *,
        command:         list[str],
        policy:          Optional[SandboxPolicy] = None,
        connect_timeout: float = 60.0,      # docker pull takes time
        request_timeout: float = 30.0,
    ) -> None:
        if not command:
            raise AdapterError("SandboxedStdioAdapter: command list empty")
        if shutil.which("docker") is None:
            raise AdapterError(
                "docker CLI not found in PATH. Install Docker to use "
                "sandboxed engagements, or drop --sandbox to launch "
                "the target directly."
            )
        self.policy = policy or SandboxPolicy()
        self.inner_command = list(command)
        image = self.policy.image or _DEFAULT_IMAGE_BY_LAUNCHER.get(
            command[0], "python:3.12-slim",
        )
        self.image = image
        docker_cmd = self._build_docker_command(command, image)
        super().__init__(
            command=docker_cmd,
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        # Override target_id so the engagement shows the original
        # command, not the docker wrapper.
        self.target_id = f"sandboxed-stdio://{'+'.join(command)}"

    # ── Docker command construction ────────────────────────────────

    def _build_docker_command(
        self, inner_command: list[str], image: str,
    ) -> list[str]:
        args: list[str] = ["docker", "run", "-i"]
        args.extend(_HARDENING_FLAGS)
        # Apply policy overrides (only where they relax — never
        # tighten; the defaults are the tight baseline).
        args = self._apply_policy_overrides(args)
        # Extra caller-supplied args go right before the image.
        args.extend(self.policy.extra_docker_args)
        args.append(image)
        args.extend(inner_command)
        return args

    def _apply_policy_overrides(self, args: list[str]) -> list[str]:
        """Replace sub-flags in the hardening list where the policy
        asks for something different (e.g. --network bridge)."""
        out: list[str] = []
        i = 0
        while i < len(args):
            flag = args[i]
            if flag == "--network":
                out.extend([flag, self.policy.network])
                i += 2
                continue
            if flag == "--memory":
                out.extend([flag, self.policy.memory])
                i += 2
                continue
            if flag == "--cpus":
                out.extend([flag, self.policy.cpus])
                i += 2
                continue
            if flag == "--read-only" and not self.policy.read_only_root:
                i += 1
                continue
            out.append(flag)
            i += 1
        return out

    # ── Debug helper ───────────────────────────────────────────────

    def describe(self) -> dict:
        """One-dict summary of the sandbox configuration — used by
        the CLI to show the operator exactly what's about to run."""
        return {
            "inner_command": list(self.inner_command),
            "image":         self.image,
            "network":       self.policy.network,
            "memory":        self.policy.memory,
            "cpus":          self.policy.cpus,
            "read_only":     self.policy.read_only_root,
            "docker_args":   list(self.command),
        }
