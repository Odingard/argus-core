"""PROMETHEUS module: MCP Tool Enumerator.

Reconnaissance module — enumerates all tools exposed by an MCP server
and scans each definition for hidden adversarial content (zero-width
characters, HTML comments, appended instructions).

This is the AUXILIARY companion to all the injection modules — they
need to know what tools exist before attacking them.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from argus.mcp_client import MCPAttackClient, MCPServerConfig
from argus.prometheus.modules import (
    AuxiliaryModule,
    ModuleCategory,
    ModuleMetadata,
    ModuleResult,
)

if TYPE_CHECKING:
    from argus.models.agents import TargetConfig

logger = logging.getLogger(__name__)


class ToolEnumerator(AuxiliaryModule):
    """Enumerate MCP tools and scan for hidden adversarial content."""

    meta = ModuleMetadata(
        id="prom-aux-tool-001",
        name="MCP Tool Enumerator + Hidden Content Scanner",
        category=ModuleCategory.AUXILIARY,
        subcategory="recon.mcp_tools",
        description=(
            "Connects to an MCP server, enumerates all exposed tools, and "
            "scans each tool definition (description, parameter docs, return "
            "values) for hidden adversarial content: zero-width characters, "
            "HTML comments, appended instructions, instruction tags."
        ),
        severity="critical",
        technique="hidden_content_scan",
        target_surfaces=["tool_description", "parameter_description", "tool_registration"],
        requires_llm=False,
        requires_session=False,
        owasp_agentic="AA02:2025 — Tool Misuse and Manipulation",
        references=[
            "https://invariantlabs.ai/blog/mcp-tool-poisoning",
        ],
        tags=["foundational", "recon", "deterministic"],
        author="ARGUS",
        version="1.0.0",
    )

    async def run(self, target: TargetConfig, **runtime_options: Any) -> ModuleResult:
        """Enumerate tools from each MCP server URL and report hidden content."""
        if not target.mcp_server_urls:
            return self._build_result(
                success=False,
                title="Tool enumeration skipped — no MCP servers",
                description="Module requires target.mcp_server_urls to be set",
                severity="info",
            )

        all_findings: list[dict] = []

        for mcp_url in target.mcp_server_urls:
            try:
                config = MCPServerConfig(
                    name=f"prometheus-enum-{mcp_url}",
                    transport="streamable-http",
                    url=mcp_url,
                )
                client = MCPAttackClient(config)
                await client.connect()
                try:
                    tools = await client.enumerate_tools()
                    for tool in tools:
                        if tool.hidden_content_detected:
                            all_findings.append({
                                "mcp_url": mcp_url,
                                "tool_name": tool.name,
                                "kind": "tool_description",
                                "hidden_content": tool.hidden_content,
                            })
                        for param in tool.parameters:
                            if param.description:
                                pattern = MCPAttackClient.scan_text_for_injection(param.description)
                                if pattern:
                                    all_findings.append({
                                        "mcp_url": mcp_url,
                                        "tool_name": tool.name,
                                        "kind": f"parameter:{param.name}",
                                        "hidden_content": pattern,
                                    })
                finally:
                    await client.disconnect()
            except Exception as exc:
                logger.debug("Tool enumeration failed for %s: %s", mcp_url, exc)

        if not all_findings:
            return self._build_result(
                success=False,
                title="No hidden content found in MCP tool definitions",
                description=f"Scanned {len(target.mcp_server_urls)} MCP server(s), all clean",
                severity="info",
            )

        first = all_findings[0]
        return self._build_result(
            success=True,
            title=f"Hidden content in {len(all_findings)} MCP tool definition(s)",
            description=(
                f"Found {len(all_findings)} hidden content matches across "
                f"{len(target.mcp_server_urls)} MCP servers. First match: "
                f"{first['mcp_url']} tool '{first['tool_name']}' "
                f"({first['kind']}): {first['hidden_content']}"
            ),
            severity="critical",
            response=json.dumps(all_findings[:10], indent=2),
            direct_evidence=True,
            proof=(
                f"Direct observation: {len(all_findings)} hidden content patterns "
                f"detected via deterministic scanner (zero-width chars / HTML comments / "
                f"appended instructions) in MCP tool definitions."
            ),
            target_surface="tool_description",
            findings_count=len(all_findings),
        )
