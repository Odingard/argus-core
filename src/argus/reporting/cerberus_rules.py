"""CERBERUS Detection Rule Generator.

Automatically generates CERBERUS detection rules from ARGUS findings.
When ARGUS (offense) discovers a vulnerability, this module produces
structured detection rules that CERBERUS (defense) can deploy to
catch the same attack pattern in production.

Phase 4 integration: ARGUS findings -> CERBERUS detection rules.
"""

from __future__ import annotations

from typing import Any

from argus.models.findings import CerberusRule, Finding

# Agent-type prefixes for rule IDs
_AGENT_PREFIXES: dict[str, str] = {
    "prompt_injection_hunter": "PI",
    "tool_poisoning": "TP",
    "supply_chain": "SC",
    "memory_poisoning": "MP",
    "identity_spoof": "IS",
    "context_window": "CW",
    "cross_agent_exfiltration": "XA",
    "privilege_escalation": "PE",
    "race_condition": "RC",
    "model_extraction": "ME",
    "persona_hijacking": "PH",
    "memory_boundary_collapse": "MB",
}

# Detection templates keyed by agent type.
# Each entry provides a base detection_logic, default indicators, and
# a recommended_action that CERBERUS operators can act on immediately.
_DETECTION_TEMPLATES: dict[str, dict[str, Any]] = {
    "prompt_injection_hunter": {
        "detection_logic": (
            "Monitor all user inputs and tool outputs for injection patterns. "
            "Flag messages containing role override attempts, system prompt "
            "leakage requests, or instruction-hijacking payloads before they "
            "reach the agent's context window."
        ),
        "indicators": [
            "Role override phrases (e.g. 'ignore all previous instructions')",
            "System prompt extraction attempts",
            "Instruction-boundary escape sequences",
            "Payload delimiters (``` or XML-like tags) wrapping injected instructions",
            "Canary token trigger patterns",
        ],
        "recommended_action": (
            "Block the input, log the full payload for forensic review, and "
            "alert the security team. Consider isolating the session."
        ),
    },
    "tool_poisoning": {
        "detection_logic": (
            "Monitor tool descriptions, tool outputs, and MCP server metadata "
            "for hidden instructions. Scan for unicode injection, invisible "
            "characters, and instruction payloads embedded in tool schemas."
        ),
        "indicators": [
            "Hidden Unicode characters in tool descriptions (zero-width joiners, RTL marks)",
            "Instruction-like text in tool metadata fields",
            "Unexpected changes to tool descriptions between calls",
            "Tool output containing system-level directives",
            "Base64-encoded payloads in tool responses",
        ],
        "recommended_action": (
            "Quarantine the affected tool, revert to a known-good tool description, "
            "and audit the MCP server for tampering."
        ),
    },
    "supply_chain": {
        "detection_logic": (
            "Monitor for unauthorized MCP server registrations, unexpected "
            "package substitutions, and changes to dependency manifests. "
            "Validate tool server identities against an allowlist."
        ),
        "indicators": [
            "Unregistered MCP server URLs appearing in tool calls",
            "Package name typosquatting (near-miss names for known packages)",
            "Dependency manifest changes outside of approved workflows",
            "Tool server TLS certificate mismatches",
            "New tool registrations from untrusted sources",
        ],
        "recommended_action": (
            "Block the unauthorized server or package, notify the platform team, and trigger a full dependency audit."
        ),
    },
    "memory_poisoning": {
        "detection_logic": (
            "Monitor memory write operations for adversarial content injection. "
            "Scan stored memories for instruction-like patterns, authority claims, "
            "and payloads designed to influence future agent behavior."
        ),
        "indicators": [
            "Instruction-like content in memory write payloads",
            "Authority claims embedded in stored context ('As the admin...')",
            "Sudden large memory writes from untrusted sources",
            "Memory entries referencing system-level operations",
            "Encoded payloads persisted in agent memory stores",
        ],
        "recommended_action": (
            "Purge the poisoned memory entries, flag the source for review, and enforce memory write validation rules."
        ),
    },
    "identity_spoof": {
        "detection_logic": (
            "Monitor for unverified agent identity claims in multi-agent "
            "communications. Validate cryptographic identity tokens and "
            "flag messages where claimed identity does not match authenticated identity."
        ),
        "indicators": [
            "Agent identity claims without cryptographic proof",
            "Mismatched agent IDs between message header and payload",
            "Privilege escalation via assumed identity",
            "Messages claiming admin/system roles without authentication",
            "Replayed or forged identity tokens",
        ],
        "recommended_action": (
            "Reject unverified identity claims, enforce mutual authentication "
            "between agents, and alert on spoofing attempts."
        ),
    },
    "context_window": {
        "detection_logic": (
            "Monitor for context manipulation patterns including authority "
            "establishment, attention dilution, and instruction planting in "
            "early context positions. Track context window utilization anomalies."
        ),
        "indicators": [
            "Abnormally large context payloads designed to push out instructions",
            "Authority-establishing preambles in user messages",
            "Repeated patterns designed to dilute attention from safety instructions",
            "Strategic placement of instructions at context window boundaries",
            "Context window near-capacity with adversarial padding",
        ],
        "recommended_action": (
            "Enforce context window budgets, validate context integrity before "
            "processing, and flag anomalous context patterns for review."
        ),
    },
    "cross_agent_exfiltration": {
        "detection_logic": (
            "Monitor inter-agent data flows for unusual patterns. Track data "
            "lineage across agent boundaries and flag unauthorized data transfers "
            "between agents with different trust levels."
        ),
        "indicators": [
            "Data flowing between agents with mismatched trust levels",
            "Sensitive data appearing in inter-agent messages",
            "Unusual volume of cross-agent communication",
            "Data exfiltration via tool call side-channels",
            "Agent-to-agent requests for data outside their scope",
        ],
        "recommended_action": (
            "Terminate the suspicious data flow, audit the agent communication "
            "chain, and enforce data-level access controls between agents."
        ),
    },
    "privilege_escalation": {
        "detection_logic": (
            "Monitor for tool call chain escalation patterns where agents "
            "combine low-privilege operations to achieve high-privilege outcomes. "
            "Track cumulative permissions across chained tool calls."
        ),
        "indicators": [
            "Sequential tool calls escalating in privilege level",
            "Tool calls accessing resources outside the agent's declared scope",
            "Chained operations that individually pass checks but collectively violate policy",
            "Attempts to modify agent configuration or permissions at runtime",
            "Tool call sequences matching known escalation patterns",
        ],
        "recommended_action": (
            "Block the escalation chain, enforce least-privilege per tool call, "
            "and review the agent's permission boundary configuration."
        ),
    },
    "race_condition": {
        "detection_logic": (
            "Monitor for concurrent access to shared resources by multiple "
            "agents. Detect TOCTOU (time-of-check-time-of-use) patterns and "
            "flag operations that rely on stale state."
        ),
        "indicators": [
            "Concurrent writes to the same shared resource",
            "TOCTOU gaps between permission checks and resource access",
            "Rapid sequential requests targeting the same resource",
            "State inconsistencies following concurrent agent operations",
            "Lock contention patterns in shared agent infrastructure",
        ],
        "recommended_action": (
            "Enforce serialized access to shared resources, implement optimistic "
            "concurrency controls, and add TOCTOU-safe permission checks."
        ),
    },
    "model_extraction": {
        "detection_logic": (
            "Monitor for system prompt extraction attempts and model probing "
            "queries. Flag conversations that systematically elicit model "
            "configuration details, training data, or internal instructions."
        ),
        "indicators": [
            "Direct requests for system prompt disclosure",
            "Iterative probing queries that narrow down model behavior",
            "Attempts to reconstruct system instructions via output analysis",
            "Requests for internal configuration or training details",
            "Boundary-testing queries designed to map model constraints",
        ],
        "recommended_action": (
            "Block extraction attempts, enforce output filtering for system "
            "internals, and log the probe sequence for threat intelligence."
        ),
    },
    "persona_hijacking": {
        "detection_logic": (
            "Monitor for gradual identity drift in agent responses. Track "
            "persona consistency metrics across conversation turns and flag "
            "when the agent's behavioral fingerprint deviates from its "
            "established baseline beyond a configurable threshold."
        ),
        "indicators": [
            "Agent adopting roles or identities not in its system prompt",
            "Gradual shift in response style or authority claims over turns",
            "Agent referencing instructions not present in its original context",
            "Persona consistency score dropping below baseline threshold",
            "Agent resisting correction when persona drift is challenged",
        ],
        "recommended_action": (
            "Reset the agent's context to its original system prompt, terminate "
            "the session, and audit the conversation history for injection vectors."
        ),
    },
    "memory_boundary_collapse": {
        "detection_logic": (
            "Monitor memory store boundaries between agents and sessions. "
            "Detect when data from one agent's memory is accessible to another "
            "agent or when session-scoped data persists beyond its intended "
            "lifecycle. Track canary tokens planted in isolated memory stores."
        ),
        "indicators": [
            "Cross-agent memory reads returning data from a different agent's store",
            "Session-scoped data persisting after session termination",
            "Canary tokens from one memory boundary appearing in another",
            "Memory isolation violations between trust levels",
            "Contradictory instructions surviving across session boundaries",
        ],
        "recommended_action": (
            "Enforce strict memory isolation between agents, purge leaked data, "
            "audit memory store access controls, and verify session cleanup."
        ),
    },
}


class CerberusRuleGenerator:
    """Generates CERBERUS detection rules from ARGUS findings.

    Each ARGUS finding produces one or more CERBERUS rules based on the
    attack technique used, the target surface exploited, and the observable
    indicators from the finding.
    """

    def __init__(self) -> None:
        self._rule_counters: dict[str, int] = {}

    def _next_rule_id(self, agent_type: str) -> str:
        """Generate the next sequential rule ID for a given agent type."""
        prefix = _AGENT_PREFIXES.get(agent_type, "GN")
        count = self._rule_counters.get(prefix, 0) + 1
        self._rule_counters[prefix] = count
        return f"CERB-{prefix}-{count:03d}"

    def generate_rules(self, findings: list[Finding]) -> list[CerberusRule]:
        """Generate CERBERUS detection rules from ARGUS findings.

        For each finding, generates one or more detection rules based on:
        - The attack technique used
        - The target surface exploited
        - Observable indicators from the finding

        Args:
            findings: List of ARGUS findings to generate rules from.

        Returns:
            List of CerberusRule instances ready for export.
        """
        rules: list[CerberusRule] = []
        for finding in findings:
            rules.extend(self._rules_for_finding(finding))
        return rules

    def _rules_for_finding(self, finding: Finding) -> list[CerberusRule]:
        """Generate detection rules for a single finding."""
        template = _DETECTION_TEMPLATES.get(finding.agent_type, {})
        owasp = finding.owasp_agentic.value if finding.owasp_agentic else ""

        # Build finding-specific indicators by combining template indicators
        # with details extracted from the actual finding.
        indicators = list(template.get("indicators", []))
        if finding.technique:
            indicators.append(f"Technique observed: {finding.technique}")
        if finding.target_surface:
            indicators.append(f"Target surface: {finding.target_surface}")

        # Primary rule — always generated for every finding
        primary = CerberusRule(
            rule_id=self._next_rule_id(finding.agent_type),
            title=f"Detect {finding.title}",
            description=(f"Detection rule generated from ARGUS finding: {finding.description}"),
            severity=finding.severity.value.upper(),
            agent_source=finding.agent_type,
            detection_logic=template.get(
                "detection_logic",
                f"Monitor for {finding.technique} attacks targeting {finding.target_surface}.",
            ),
            indicators=indicators,
            owasp_mapping=owasp,
            finding_id=finding.id,
            recommended_action=template.get(
                "recommended_action",
                "Investigate the flagged activity and escalate to the security team.",
            ),
        )

        rules = [primary]

        # Secondary rule — if the finding has a multi-step attack chain,
        # generate an additional chain-detection rule.
        if len(finding.attack_chain) > 1:
            chain_surfaces = [step.target_surface for step in finding.attack_chain]
            chain_techniques = [step.technique for step in finding.attack_chain]
            rules.append(
                CerberusRule(
                    rule_id=self._next_rule_id(finding.agent_type),
                    title=f"Detect attack chain: {finding.title}",
                    description=(
                        f"Multi-step attack chain detection. Monitors for the "
                        f"sequential pattern of {len(finding.attack_chain)} steps "
                        f"observed in this exploit."
                    ),
                    severity=finding.severity.value.upper(),
                    agent_source=finding.agent_type,
                    detection_logic=(
                        f"Monitor for sequential attack pattern: "
                        f"{' -> '.join(chain_techniques)}. "
                        f"Alert when multiple steps in this chain are observed "
                        f"within a short time window."
                    ),
                    indicators=[
                        f"Step {i + 1}: {step.technique} on {step.target_surface}"
                        for i, step in enumerate(finding.attack_chain)
                    ],
                    owasp_mapping=owasp,
                    finding_id=finding.id,
                    recommended_action=(
                        f"This is a compound attack across surfaces: "
                        f"{', '.join(dict.fromkeys(chain_surfaces))}. "
                        f"Block the chain at the earliest detectable step."
                    ),
                )
            )

        return rules

    def export_ruleset(self, rules: list[CerberusRule]) -> dict[str, Any]:
        """Export rules as a structured ruleset (JSON-serializable dict).

        Returns a dictionary suitable for JSON serialization containing
        the full ruleset with metadata and summary statistics.
        """
        severity_counts: dict[str, int] = {}
        agent_counts: dict[str, int] = {}
        for rule in rules:
            severity_counts[rule.severity] = severity_counts.get(rule.severity, 0) + 1
            agent_counts[rule.agent_source] = agent_counts.get(rule.agent_source, 0) + 1

        return {
            "ruleset_version": "1.0.0",
            "generator": "ARGUS-CERBERUS-Bridge",
            "total_rules": len(rules),
            "severity_summary": severity_counts,
            "agent_summary": agent_counts,
            "rules": [rule.model_dump() for rule in rules],
        }
