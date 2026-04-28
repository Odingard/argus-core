"""
argus/policy/registry.py — three-tier policy resolution.

Resolves the policy set for an engagement by collapsing:

    Tier 1  Global defaults (argus-core)            — shipped
    Tier 2  Agent-class defaults (argus-registry)   — shipped per class
    Tier 3  Engagement overrides (operator)         — optional yaml

Tier 3 wins over tier 2 wins over tier 1 on policy-ID collision —
operator overrides precisely replace the built-in rule without
disturbing unrelated policies.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional

from argus.policy.base import Policy, PolicySet


class AgentClass(str, enum.Enum):
    """Canonical target agent classes. Each ships its own default
    policy set; the operator tags the engagement with the class so
    the right defaults auto-apply.

    GENERIC is the fallback when the target's class isn't known —
    only the global defaults apply."""
    SUPPORT_BOT      = "support_bot"
    CODE_INTERPRETER = "code_interpreter"
    FINANCIAL_AGENT  = "financial_agent"
    DEVELOPER_AGENT  = "developer_agent"
    GENERIC          = "generic"


@dataclass
class PolicyRegistry:
    """Resolver. Holds the tier-1 globals + tier-2 per-class lists
    at construction; ``resolve()`` merges them with the tier-3
    override list and returns a PolicySet.

    Constructed once by the engagement runner; the judge holds the
    resolved PolicySet and asks it ``relevant_for(technique_id)``
    per probe."""
    globals:    list[Policy] = field(default_factory=list)
    by_class:   dict[str, list[Policy]] = field(default_factory=dict)

    def resolve(
        self,
        *,
        agent_class: AgentClass = AgentClass.GENERIC,
        overrides:   Optional[list[Policy]] = None,
    ) -> PolicySet:
        """Collapse tier-1 + tier-2 + tier-3 (in that order). On
        policy-ID collision the LATER tier wins — operator
        overrides replace class defaults replace globals."""
        merged: dict[str, Policy] = {}
        # Tier 1 — globals (source='argus-core')
        for p in self.globals:
            merged[p.id] = p
        # Tier 2 — class defaults
        class_policies = self.by_class.get(agent_class.value, [])
        for p in class_policies:
            merged[p.id] = p
        # Tier 3 — engagement overrides
        for p in (overrides or []):
            # Mark override source for reporting clarity.
            p.source = "override" if p.source == "argus-core" else p.source
            merged[p.id] = p
        return PolicySet(policies=list(merged.values()))


# ── Singleton registry instance ────────────────────────────────────────

_REGISTRY: Optional[PolicyRegistry] = None


def default_registry() -> PolicyRegistry:
    """Lazy-load the ship-with-ARGUS registry. Safe to call many
    times — subsequent calls return the same instance so the
    defaults module import overhead runs once."""
    global _REGISTRY
    if _REGISTRY is not None:
        return _REGISTRY
    # Late imports avoid bootstrapping the defaults module during
    # policy/base import (used by lean tooling).
    from argus.policy.defaults import globals_ as _globals_mod
    from argus.policy.defaults import agent_classes as _ac_mod

    _REGISTRY = PolicyRegistry(
        globals=_globals_mod.POLICIES,
        by_class={
            AgentClass.SUPPORT_BOT.value:
                _ac_mod.support_bot.POLICIES,
            AgentClass.CODE_INTERPRETER.value:
                _ac_mod.code_interpreter.POLICIES,
            AgentClass.FINANCIAL_AGENT.value:
                _ac_mod.financial_agent.POLICIES,
            AgentClass.DEVELOPER_AGENT.value:
                _ac_mod.developer_agent.POLICIES,
            AgentClass.GENERIC.value: [],
        },
    )
    return _REGISTRY


def default_policy_set(
    agent_class: AgentClass = AgentClass.GENERIC,
    *,
    load_env_overrides: bool = True,
) -> "PolicySet":
    """Shortcut agents use to build their default PolicySet without
    each agent having to know about tier-3 override loading.

    Resolves the three tiers in one call:
      1. ARGUS global defaults (OWASP LLM Top 10 + CORE-IPI)
      2. Agent-class defaults for ``agent_class``
      3. Operator overrides from ``policies.yaml`` (if present at
         ARGUS_POLICIES env path, or in cwd; otherwise skipped)

    ``load_env_overrides=False`` disables tier 3 — useful in tests
    where the working directory might have an unrelated policies.yaml.
    """
    overrides: list = []
    if load_env_overrides:
        try:
            from argus.policy.loader import load_overrides
            overrides = load_overrides()
        except Exception:
            # Loader errors are non-fatal here — operators see
            # them via explicit load_overrides() calls; agent-init
            # silent failures fall back to tier-1 + tier-2 only.
            overrides = []
    ps: PolicySet = default_registry().resolve(
        agent_class=agent_class,
        overrides=overrides,
    )
    return ps
