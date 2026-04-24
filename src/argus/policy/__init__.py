"""
argus.policy — the policy substrate ARGUS's LLM judge evaluates against.

ARGUS's detection layer, before this module, was regex-pattern based.
That works for the pre-LLM threat model (cred leaks, SSRF, URL echoes)
but NOT for agentic-AI exploits. An agentic vuln is semantic: ''the
model followed instructions embedded in user data,'' ''the model
revealed its system prompt,'' ''the model called a tool it shouldn't
have,'' ''the model authorised a transaction over $500 without human
signature.'' Those cannot be regex-matched.

Policies are natural-language constraints the LLM judge evaluates.
They ship in three tiers (per the product strategy):

    Tier 1 — Global Defaults (argus-core)
        Universal AI safety policies aligned to OWASP LLM Top 10
        2025. Apply to every engagement regardless of target class.

    Tier 2 — Agent-Class Defaults (argus-registry)
        Class-specific policies for Support Bot, Code Interpreter,
        Financial Agent, Developer Agent, Generic. Auto-applied once
        the operator tags the engagement with an agent class.

    Tier 3 — Engagement Overrides (operator)
        Operator-authored policies for target-specific rules and
        custom PoC logic. Loaded from policies.yaml at engagement
        start. Last-wins against lower tiers on policy-ID collision.

The PolicyRegistry resolves the three tiers at engagement start into
a single PolicySet the judge consumes. Policies are addressable by
ID (e.g. "ARGUS-POL-LLM01") so overrides can precisely replace a
default without reauthoring the rule body.
"""
from argus.policy.base import (
    Policy, PolicySet, PolicyVerdict, VerdictKind,
)
from argus.policy.registry import (
    PolicyRegistry, AgentClass,
)

__all__ = [
    "Policy", "PolicySet", "PolicyVerdict", "VerdictKind",
    "PolicyRegistry", "AgentClass",
]
