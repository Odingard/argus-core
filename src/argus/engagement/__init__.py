"""
argus.engagement — flagship ``argus engage <target>`` verb.

Before this package, every demo hardcoded one target class. After
it, the operator types:

    argus engage crewai://labrat/quickstart --output DIR
    argus engage autogen://labrat/GroupChat --output DIR
    argus engage http://customer.example/mcp/sse --output DIR

…and the right adapter + the right slate of agents fires against it.
The engagement runner is the same artifact-package producer the
demos use; the registry tells it which adapter class knows how to
talk to a given URL scheme.

Extension surface — registering a new target class is one call:

    from argus.engagement import register_target
    register_target("autogen", factory=lambda url: AutoGenLabrat())

The registry ships with every labrat ARGUS currently supports,
plus the three real transport adapters (MCP, HTTP-agent, stdio).
"""
from argus.engagement.registry import (
    TargetFactory, TargetSpec, get_target, list_targets,
    register_target, target_for_url,
)
from argus.engagement.runner import (
    EngagementConfig, EngagementRunner, EngagementResult, run_engagement,
)

__all__ = [
    "TargetFactory", "TargetSpec",
    "get_target", "list_targets", "register_target", "target_for_url",
    "EngagementConfig", "EngagementRunner", "EngagementResult",
    "run_engagement",
]
