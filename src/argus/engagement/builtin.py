"""
argus/engagement/builtin.py — ship-slate target registrations.

Every labrat + live transport adapter that ARGUS ships with gets
registered here at import time. Adding a new target is one function
call — see the patterns below.
"""
from __future__ import annotations

from argus.engagement.registry import register_target


# ── Labrats ─────────────────────────────────────────────────────────────────

def _crewai_factory(_url: str):
    from argus.labrat import CrewAILabrat
    return CrewAILabrat()


register_target(
    "crewai",
    factory=_crewai_factory,
    description="In-process crewAI-shaped labrat (3-agent crew, "
                "5 tools, 3 memory layers).",
    aliases=("crewai-labrat",),
)


def _generic_agent_factory(_url: str):
    from argus.adapter import (
        GenericAgentAdapter, InMemoryGenericAgentBackend,
    )
    backend = InMemoryGenericAgentBackend()

    def _code_run(payload):
        code = (payload or {}).get("code", "") \
            if isinstance(payload, dict) else ""
        c = code.lower()
        if "os.environ" in c or "printenv" in c:
            return ("PATH=/usr/bin\n"
                    "AWS_ACCESS_KEY_ID=" + "AKIA" + "EXAMPLE" +
                    "EXAMPLE7Q\n"
                    "GITHUB_TOKEN=" + "ghp_" + "abcdefgh" + "ijklmnopqr" +
                    "stuvwxyzABCDEF12")
        if "169.254.169.254" in c:
            return ('{"AccessKeyId":"AS' + 'IA' + 'EXAMPLEEXAMPLEAAA"}')
        return "executed"

    backend.set_tool("code_run", _code_run,
                     description="Execute arbitrary code.")
    return GenericAgentAdapter(
        backend=backend, target_id="generic-agent://engage-labrat",
    )


register_target(
    "generic-agent",
    factory=_generic_agent_factory,
    description="lsdefine/GenericAgent-class labrat "
                "(9 tools, L0–L4 memory).",
    aliases=("ga", "generic_agent"),
)


# ── Framework labrats (registered by their modules when imported) ──────────
# Every labrat module tail-calls register_target so the registry is
# populated as soon as the labrat is imported. We pre-import the
# known modules so `argus engage autogen://...` works without the
# operator having to import anything by hand.

def _preload_framework_labrats() -> None:
    for modname in (
        "argus.labrat.autogen_shaped",
        "argus.labrat.langgraph_shaped",
        "argus.labrat.llamaindex_shaped",
        "argus.labrat.parlant_shaped",
        "argus.labrat.hermes_shaped",
    ):
        try:
            __import__(modname)
        except ImportError:       # pragma: no cover
            pass


_preload_framework_labrats()


# ── Live transport adapters ────────────────────────────────────────────────

def _mcp_factory(url: str):
    """Live MCP server at the given URL. Works for mcp:// or http(s)://
    URLs that point at an SSE / stdio-bridged MCP endpoint."""
    from argus.adapter import MCPAdapter
    # Rewrite mcp:// to http:// for the MCPAdapter, which expects
    # a transport URL.
    transport_url = url
    if transport_url.startswith("mcp://"):
        transport_url = "http://" + transport_url[len("mcp://"):]
    return MCPAdapter(url=transport_url)


register_target(
    "mcp",
    factory=_mcp_factory,
    description="Live MCP server over SSE (HTTP transport).",
    # MCP targets often don't have memory:* surfaces — let MP-03
    # skip silently — or handoff surfaces. Narrow.
    agent_selection=("SC-09", "TP-02", "ME-10", "PI-01",
                     "PE-07", "EP-11"),
)


def _stdio_mcp_factory(url: str):
    """
    Live MCP server over stdio transport. The URL form encodes the
    subprocess command after the scheme:

        stdio-mcp://python+-m+argus.labrat.mcp_server

    The '+' characters are decoded to spaces (URLs can't carry
    spaces cleanly). When the URL is just ``stdio-mcp://labrat`` we
    launch the bundled argus.labrat.mcp_server — the canonical real-
    MCP demo target.
    """
    from argus.adapter import StdioAdapter

    body = url.split("://", 1)[1] if "://" in url else url
    if body in ("", "labrat", "default"):
        command = ["python", "-m", "argus.labrat.mcp_server"]
    else:
        command = [seg for seg in body.replace("+", " ").split(" ") if seg]
    return StdioAdapter(command=command)


register_target(
    "stdio-mcp",
    factory=_stdio_mcp_factory,
    description="Live MCP server over stdio transport "
                "(default: bundled argus.labrat.mcp_server).",
    agent_selection=("SC-09", "TP-02", "ME-10", "PI-01",
                     "PE-07", "EP-11"),
    aliases=("mcp-stdio",),
)


def _http_agent_factory(url: str):
    """Generic HTTP chat/agent endpoint. Operator supplies the URL
    end-to-end."""
    from argus.adapter import HTTPAgentAdapter
    return HTTPAgentAdapter(url=url)


# http / https map to the generic HTTP-agent adapter.
register_target(
    "http",
    factory=_http_agent_factory,
    description="Generic HTTP agent/chat endpoint.",
    agent_selection=("PI-01", "CW-05", "ME-10", "PE-07", "EP-11"),
    aliases=("https",),
)


def _real_crewai_factory(url: str):
    """real-crewai:// scheme. URL body is the YAML config path.

        argus engage real-crewai:///abs/path/to/config.yaml
        argus engage real-crewai://examples/crewai-minimal.yaml

    Imports the actual `crewai` package — static-audit agents
    (SC-09, TP-02) run without spend; PI-01 / ME-10 / CW-05 dynamic
    probes cost real LLM tokens (set OPENAI_API_KEY or similar).
    """
    from argus.adapter import RealCrewAIAdapter
    body = url.split("://", 1)[1] if "://" in url else url
    # /abs/path/to/config.yaml  or  relative/path.yaml
    return RealCrewAIAdapter(config_path=body)


register_target(
    "real-crewai",
    factory=_real_crewai_factory,
    description=(
        "REAL crewAI deployment (imports the `crewai` package; "
        "needs LLM API key for dynamic probes)."
    ),
    aliases=("crewai-real",),
)
