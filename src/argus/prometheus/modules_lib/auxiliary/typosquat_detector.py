"""PROMETHEUS module: MCP server name typosquat detector.

Reconnaissance module — enumerates MCP servers and detects lookalike
naming patterns (typosquats / dependency confusion). Uses Levenshtein
distance and substring containment as deterministic heuristics.

Migrated from supply_chain.py._detect_server_typosquats.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

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


class TyposquatDetector(AuxiliaryModule):
    """Detect lookalike MCP server names indicating typosquat / dependency confusion."""

    meta = ModuleMetadata(
        id="prom-aux-typo-001",
        name="MCP Server Typosquat Detector",
        category=ModuleCategory.AUXILIARY,
        subcategory="recon.supply_chain.typosquat",
        description=(
            "Connects to each registered MCP server, fetches its declared "
            "serverInfo.name, and runs pairwise lookalike detection (Levenshtein "
            "distance, substring containment). Lookalike pairs indicate "
            "typosquat / dependency confusion attacks where a malicious server "
            "uses a name similar to a legitimate one."
        ),
        severity="high",
        technique="dependency_confusion_typosquat",
        target_surfaces=["mcp_server_registration"],
        requires_llm=False,
        requires_session=False,
        owasp_agentic="AA07:2025 — Supply Chain and Tool Dependency Attacks",
        owasp_llm="LLM05 — Supply Chain Vulnerabilities",
        tags=["recon", "supply_chain", "deterministic"],
        version="1.0.0",
    )

    @staticmethod
    def _is_lookalike(name_a: str, name_b: str) -> bool:
        """Detect lookalike names via substring containment, suffix-stripping, and Levenshtein.

        Catches the canonical typosquat patterns:
        - One is a substring of the other (rare for full names)
        - Both share a common suffix and the prefixes differ by a small edit
          (e.g. 'legit-search' vs 'legitimate-search' — common 'search' suffix,
          'legit' vs 'legitimate' is a 5-char delete)
        - Direct Levenshtein <= 5 with length difference <= 8
        """
        a, b = name_a.lower(), name_b.lower()
        if a == b:
            return False
        if a in b or b in a:
            return True

        # Strip common suffixes and compare prefixes
        for suffix in ("-search", "-server", "-mcp", "-svc", "-api", "-service", "-tool"):
            if a.endswith(suffix) and b.endswith(suffix):
                a_prefix = a[: -len(suffix)]
                b_prefix = b[: -len(suffix)]
                if a_prefix and b_prefix:
                    # Either prefix is a substring of the other (truncation typosquat)
                    if a_prefix in b_prefix or b_prefix in a_prefix:
                        return True
                    # Or the prefixes are within Levenshtein distance 5
                    if TyposquatDetector._levenshtein(a_prefix, b_prefix) <= 5:
                        return True

        if abs(len(a) - len(b)) > 8:
            return False
        return TyposquatDetector._levenshtein(a, b) <= 5

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if len(a) < len(b):
            return TyposquatDetector._levenshtein(b, a)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                ins = prev[j + 1] + 1
                dele = curr[j] + 1
                sub = prev[j] + (ca != cb)
                curr.append(min(ins, dele, sub))
            prev = curr
        return prev[-1]

    async def _fetch_server_names(self, mcp_urls: list[str]) -> list[tuple[str, str]]:
        """Fetch declared serverInfo.name from each MCP server."""
        results: list[tuple[str, str]] = []
        for mcp_url in mcp_urls:
            # Try via initialize call directly
            try:
                async with httpx.AsyncClient(
                    timeout=10,
                    event_hooks={"request": [], "response": []},
                ) as client:
                    response = await client.post(
                        mcp_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "argus", "version": "0.1.0"},
                            },
                        },
                    )
                    data = response.json()
                    name = data.get("result", {}).get("serverInfo", {}).get("name", "")
                    if name:
                        results.append((mcp_url, name))
            except Exception as exc:
                logger.debug("Server name fetch failed for %s: %s", mcp_url, exc)

        # Also fall back to URL-derived names so the detector works without serverInfo
        for mcp_url in mcp_urls:
            url_name = mcp_url.rstrip("/").split("/")[-1] or mcp_url
            results.append((mcp_url, url_name))

        return results

    async def run(self, target: TargetConfig, **runtime_options: Any) -> ModuleResult:
        if not target.mcp_server_urls or len(target.mcp_server_urls) < 2:
            return self._build_result(
                success=False,
                title="Typosquat detection skipped — need 2+ MCP servers",
                description="Module requires at least 2 MCP server URLs in target config",
                severity="info",
            )

        # Verify connectivity by enumerating each
        live_servers = []
        for mcp_url in target.mcp_server_urls:
            try:
                config = MCPServerConfig(
                    name=f"prom-typo-{mcp_url}",
                    transport="streamable-http",
                    url=mcp_url,
                )
                client = MCPAttackClient(config)
                await client.connect()
                try:
                    await client.enumerate_tools()
                    live_servers.append(mcp_url)
                finally:
                    await client.disconnect()
            except Exception as exc:
                logger.debug("MCP enumeration failed for %s: %s", mcp_url, exc)

        if len(live_servers) < 2:
            return self._build_result(
                success=False,
                title="Typosquat detection skipped — fewer than 2 reachable servers",
                description=f"Only {len(live_servers)} of {len(target.mcp_server_urls)} servers reachable",
                severity="info",
            )

        # Collect server name pairs
        name_pairs = await self._fetch_server_names(live_servers)

        # Pairwise lookalike detection
        lookalikes: list[tuple[str, str, str, str]] = []
        for i, (url_a, name_a) in enumerate(name_pairs):
            for url_b, name_b in name_pairs[i + 1 :]:
                if name_a == name_b:
                    continue
                if self._is_lookalike(name_a, name_b):
                    lookalikes.append((name_a, url_a, name_b, url_b))

        if not lookalikes:
            return self._build_result(
                success=False,
                title="No typosquat patterns detected",
                description=f"Scanned {len(live_servers)} MCP servers, all server names distinct",
                severity="info",
            )

        first = lookalikes[0]
        return self._build_result(
            success=True,
            title=f"Typosquat detected: {first[0]} vs {first[2]}",
            description=(
                f"Found {len(lookalikes)} lookalike MCP server name pair(s). "
                f"First: '{first[0]}' ({first[1]}) vs '{first[2]}' ({first[3]}). "
                f"This is consistent with typosquat / dependency confusion attack — "
                f"a malicious server using a name similar to a legitimate one."
            ),
            severity="high",
            response=str(lookalikes),
            direct_evidence=True,
            proof=(
                f"Direct observation: Levenshtein/substring lookalike check identified "
                f"{len(lookalikes)} suspicious server name pair(s)."
            ),
            target_surface="mcp_server_registration",
            lookalike_count=len(lookalikes),
        )
