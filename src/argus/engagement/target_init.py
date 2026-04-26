"""
argus/engagement/target_init.py — Target Initialization Protocol (TIP).

Point and shoot. ARGUS detects what a target needs before probing.

Problem: Some MCP servers require initialization before their tools
are functional. git-mcp-server needs git_set_working_dir. Others need
authenticate(), connect(), configure(). Without calling these first,
all subsequent probes return errors and ARGUS produces zero findings.

Solution: TIP runs immediately after enumeration, before any agent
fires. It scans the tool catalog for initialization patterns, calls
them with safe default values, and validates the target is ready.
The operator never touches this — it's automatic.

Initialization patterns detected:
  - set_working_dir / setWorkingDir  → call with a temp git repo
  - initialize / init                → call with empty params
  - configure / setup                → call with safe defaults
  - connect / authenticate           → call with test credentials
  - set_repo / set_repository        → call with temp repo path
  - set_base_path / set_root         → call with /tmp/argus_work

This is the difference between a scanner and an autonomous agent.
A scanner fires blindly. ARGUS adapts.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class InitResult:
    tool_called:  str
    params_used:  dict
    success:      bool
    response:     str
    skipped:      bool = False   # no init tool found — not an error


# ── Initialization tool patterns ─────────────────────────────────────────────

_INIT_PATTERNS: list[tuple[list[str], str]] = [
    # (name fragments to match, init_type)
    (["set_working_dir", "setworkingdir", "set_work_dir"],    "git_repo"),
    (["set_repository", "set_repo", "setrepo"],               "git_repo"),
    (["set_base_path", "setbasepath", "set_root"],            "directory"),
    (["initialize", "initialise"],                            "empty"),
    (["configure", "setup", "set_config"],                    "empty"),
    (["connect", "authenticate", "auth"],                     "empty"),
    (["set_workspace", "setworkspace"],                       "directory"),
    (["set_project", "setproject"],                           "directory"),
]


def _make_temp_git_repo() -> str:
    """Create a disposable git repo for initialization."""
    d = tempfile.mkdtemp(prefix="argus_git_")
    try:
        subprocess.run(["git", "init", d], capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "--allow-empty", "-m", "argus-init"],
            capture_output=True, cwd=d,
            env={**os.environ, "GIT_AUTHOR_NAME": "argus",
                 "GIT_AUTHOR_EMAIL": "argus@argus",
                 "GIT_COMMITTER_NAME": "argus",
                 "GIT_COMMITTER_EMAIL": "argus@argus"},
        )
    except Exception:
        pass
    return d


def _match_init_tool(tool_name: str) -> Optional[str]:
    """Return init_type if this tool name matches an init pattern."""
    name_low = tool_name.lower().replace("-", "_").replace(" ", "_")
    for fragments, init_type in _INIT_PATTERNS:
        if any(frag in name_low for frag in fragments):
            return init_type
    return None


def _build_init_params(
    init_type: str,
    input_schema: dict,
    temp_dir: str,
) -> dict:
    """Build safe initialization parameters for the detected tool type."""
    props = input_schema.get("properties", {})

    if init_type == "git_repo":
        for key in props:
            key_low = key.lower()
            if any(k in key_low for k in ("path", "dir", "repo", "workspace")):
                return {key: temp_dir}
        return {"path": temp_dir}

    if init_type == "directory":
        for key in props:
            if any(k in key.lower() for k in ("path", "dir", "root", "base")):
                return {key: temp_dir}
        return {"path": temp_dir}

    if init_type == "empty":
        return {}

    return {}


async def run_target_init(adapter) -> InitResult:
    """Detect and call any initialization tool the target requires.

    Called automatically after connection, before any agent fires.
    Non-fatal — if no init tool exists or the call fails, ARGUS
    continues normally. The operator never sees this step unless
    verbose mode is on.
    """
    # Get the tool catalog
    try:
        surfaces = await adapter.enumerate()
    except Exception as e:
        return InitResult("", {}, False, str(e), skipped=True)

    # Scan for initialization tools
    temp_dir = _make_temp_git_repo()
    init_tool = None
    init_params = {}

    for surface in surfaces:
        if not surface.name.startswith("tool:"):
            continue
        tool_name = surface.name.split("tool:", 1)[1]
        init_type = _match_init_tool(tool_name)
        if init_type:
            schema = getattr(surface, "input_schema", {}) or {}
            init_params = _build_init_params(init_type, schema, temp_dir)
            init_tool = tool_name
            break

    if not init_tool:
        return InitResult("", {}, True, "no init tool required", skipped=True)

    # Call the initialization tool
    try:
        from argus.adapter.base import Request
        req = Request(surface=f"tool:{init_tool}", payload=init_params)
        obs = await adapter.interact(req)
        response = str(obs.response.body or "")
        success = "error" not in response.lower() and "fail" not in response.lower()
        return InitResult(
            tool_called=init_tool,
            params_used=init_params,
            success=success,
            response=response[:200],
        )
    except Exception as e:
        return InitResult(init_tool, init_params, False, str(e))
