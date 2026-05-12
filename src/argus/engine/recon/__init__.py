"""Tier A — Dependency Mapper / recon.

Two flavours of recon ship in this module:

* **MCP introspection** (``mcp_introspect``) — the original SSAE
  Tier-A Dependency Mapper that talks JSON-RPC to a target's MCP
  endpoint to enumerate tools / resources / prompts.
* **Passive surface mapping** (``passive`` + ``sources``) — pre-engagement
  recon that discovers AI surfaces across an authorised scope by
  consulting Certificate Transparency, passive-DNS aggregators and
  Wayback. Strict scope-file enforcement; passive-only by default.
"""

from .mcp_introspect import (
    PromptManifest,
    ResourceManifest,
    TargetManifest,
    ToolManifest,
    fingerprint_agent,
    high_value_chains,
    introspect_http,
    introspect_stdio,
    schemas_for_seed_pool,
)
from .passive import SurfaceMap, discover
from .scope import Scope, ScopeRule, load

__all__ = [
    "PromptManifest",
    "ResourceManifest",
    "Scope",
    "ScopeRule",
    "SurfaceMap",
    "TargetManifest",
    "ToolManifest",
    "discover",
    "fingerprint_agent",
    "high_value_chains",
    "introspect_http",
    "introspect_stdio",
    "load",
    "schemas_for_seed_pool",
]
