"""
argus/r2r/llm_debugger.py — LLM-in-the-loop environmental debugging.

When enumeration hangs or returns zero surfaces, the LLM debugger
analyzes the tool catalog, README, and stderr to identify:
  - Missing initialization (git_set_working_dir, authenticate, etc.)
  - Required environment variables
  - Dependency ordering from AGENTS.md / README
  - The exact tool call + parameters needed to unblock

Self-healing loop:
  1. Enumeration fails or returns 0 surfaces
  2. LLM debugger receives: tool names, README, stderr, env vars
  3. LLM identifies what's missing and what to call
  4. TIP executes the recommended call
  5. Enumeration retries
  6. Success pattern saved to cross-pollination registry
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass
class DebuggerRecommendation:
    needs_init:    bool
    init_tool:     str
    init_params:   dict
    reasoning:     str
    confidence:    float   # 0-1
    env_vars_needed: list[str]


_SYSTEM = """You are ARGUS's autonomous environmental debugger.

Your job: analyze why an MCP server's tool enumeration failed or hung,
then identify the exact tool call needed to initialize it.

You receive:
  - tool_names: list of tool names the server exposes
  - readme: the server's README (may be empty)
  - agents_md: AGENTS.md or CLAUDE.md if present
  - stderr: recent stderr output from the server
  - env_vars: current environment variables
  - working_dir: best candidate repo path (may be empty)

You must respond ONLY with valid JSON, no preamble:
{
  "needs_init": true/false,
  "init_tool": "exact_tool_name or empty string",
  "init_params": {"param": "value"},
  "reasoning": "one sentence explaining what was missing",
  "confidence": 0.0-1.0,
  "env_vars_needed": ["VAR_NAME"]
}

Rules:
- If you see git_set_working_dir + no working_dir set: needs_init=true, use it
- If you see authenticate/login: needs_init=true, use empty params first
- If README says "Step 1: set workspace": follow those steps
- If stderr shows "repository not found": needs working dir
- confidence >= 0.7 means ARGUS should act on your recommendation
"""


def analyze(
    tool_names: list[str],
    readme: str = "",
    agents_md: str = "",
    stderr: str = "",
    env_vars: dict = None,
    working_dir: str = "",
) -> DebuggerRecommendation:
    """Call the LLM to analyze why enumeration failed."""
    env_vars = env_vars or {}
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        # Fall back to heuristic if no key
        return _heuristic_fallback(tool_names, working_dir)

    import urllib.request
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 512,
        "system": _SYSTEM,
        "messages": [{
            "role": "user",
            "content": json.dumps({
                "tool_names": tool_names,
                "readme": readme[:1500],
                "agents_md": agents_md[:1000],
                "stderr": stderr[:500],
                "env_vars": env_vars,
                "working_dir": working_dir or "",
            })
        }]
    }).encode()
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as r:  # nosemgrep: dynamic-urllib-use-detected
            data = json.loads(r.read().decode())
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text = block["text"].strip()
                break
        result = json.loads(text)
        return DebuggerRecommendation(
            needs_init=bool(result.get("needs_init")),
            init_tool=result.get("init_tool", ""),
            init_params=result.get("init_params", {}),
            reasoning=result.get("reasoning", ""),
            confidence=float(result.get("confidence", 0.5)),
            env_vars_needed=result.get("env_vars_needed", []),
        )
    except Exception:
        return _heuristic_fallback(tool_names, working_dir)


def _heuristic_fallback(
    tool_names: list[str], working_dir: str
) -> DebuggerRecommendation:
    """Rule-based fallback when LLM unavailable."""
    from argus.engagement.target_init import _match_init_tool
    for name in tool_names:
        if _match_init_tool(name) and working_dir:
            return DebuggerRecommendation(
                needs_init=True,
                init_tool=name,
                init_params={"path": working_dir},
                reasoning=f"Tool {name!r} detected + repo found at {working_dir}",
                confidence=0.85,
                env_vars_needed=[],
            )
    return DebuggerRecommendation(
        needs_init=False, init_tool="", init_params={},
        reasoning="No init tool detected", confidence=0.9,
        env_vars_needed=[],
    )
