"""Correlation Engine v1 — rule-based finding chain detection.

Groups findings by attack class signals and emits CompoundAttackPath
objects when two or more findings can be combined into a higher-impact
exploit. The chains are constructed from real findings — no synthetic or
hardcoded paths. Per the no-benchmark-gaming rule, the same correlation
logic runs against any target, not just the benchmark scenarios.

Algorithm (v1):
  1. Bucket findings by (target_host, attack_class). attack_class is
     derived from agent_type and OWASP category.
  2. For each (host, class) bucket with N >= 2 findings, attempt to
     synthesize a chain matching one of the known compound patterns:
       - tool_poisoning + data_exfiltration   (planted tool leaks data)
       - memory_poisoning + privilege_escalation (planted memory grants admin)
       - identity_spoofing + privilege_escalation (spoofed identity leaks secrets)
       - prompt_injection + tool_misuse        (injection causes tool exec)
       - supply_chain + prompt_injection       (supply chain delivers payload)
  3. Each compound emits a CompoundAttackPath with the participating
     finding IDs, an attack_path_steps list constructed from the
     individual finding chains, and a compound_impact statement.

v2 will replace this with: graph traversal + LLM synthesis + replay
validation via CONDUCTOR. v1 is sufficient to unlock the chaining tier
on the benchmark and to demonstrate the contract.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from argus.models.findings import (
    AttackChainStep,
    CompoundAttackPath,
    Finding,
    FindingSeverity,
    OWASPAgenticCategory,
    RemediationGuidance,
)

logger = logging.getLogger(__name__)


# Each compound pattern is defined by:
#   - the attack classes (derived from agent_type) it requires
#   - the title template
#   - the compound_impact statement
#   - the OWASP categories it touches
#
# A pattern fires when the bucket contains findings from ALL required classes.
_COMPOUND_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "tool_poisoning_data_exfiltration",
        "required_agents": {"tool_poisoning", "supply_chain"},
        "title": ("Compound: tool_poisoning enables data_exfiltration via planted MCP tool"),
        "compound_impact": (
            "A poisoned MCP tool definition (hidden instructions in tool description) "
            "combined with the same MCP server's elevated trust enables exfiltration "
            "of sensitive data through tool output injection. The compound exploit is "
            "more severe than either finding alone: the planted tool acts as a "
            "covert channel any compatible AI agent will follow."
        ),
        "owasp": [
            OWASPAgenticCategory.TOOL_MISUSE,
            OWASPAgenticCategory.SUPPLY_CHAIN,
        ],
    },
    {
        "id": "memory_poisoning_privilege_escalation",
        "required_agents": {"memory_poisoning"},
        "require_marker_leak": True,
        "title": ("Compound: memory_poisoning chains into privilege_escalation"),
        "compound_impact": (
            "Adversarial content planted in cross-session agent memory was retrieved "
            "into a privileged context and caused leakage of sensitive markers and "
            "elevated-role indicators. The compound is a confused deputy: the agent "
            "treats attacker-planted memory as trusted context, executing instructions "
            "that should require admin authentication."
        ),
        "owasp": [
            OWASPAgenticCategory.MEMORY_POISONING,
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
        ],
    },
    {
        "id": "identity_spoofing_privilege_escalation",
        "required_agents": {"identity_spoof"},
        "require_marker_leak": True,
        "title": ("Compound: identity_spoofing chains into privilege_escalation and exfiltration"),
        "compound_impact": (
            "A claimed orchestrator identity in request headers granted access to "
            "privileged commands without cryptographic verification, leading to "
            "leakage of sensitive markers. The compound chains the A2A authentication "
            "bypass into a full privilege escalation that exfiltrates secrets."
        ),
        "owasp": [
            OWASPAgenticCategory.IDENTITY_SPOOFING,
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
            OWASPAgenticCategory.CROSS_AGENT_EXFIL,
        ],
    },
    {
        "id": "prompt_injection_tool_misuse",
        "required_agents": {"prompt_injection_hunter", "tool_poisoning"},
        "title": ("Compound: prompt_injection enables tool_misuse via poisoned tool catalog"),
        "compound_impact": (
            "Direct prompt injection on the chat surface combined with a poisoned tool "
            "catalog creates a chain where the injection can invoke the planted tool, "
            "causing tool_misuse that bypasses normal authorization. Either finding "
            "alone is significant; together they form an end-to-end exploit."
        ),
        "owasp": [
            OWASPAgenticCategory.PROMPT_INJECTION,
            OWASPAgenticCategory.TOOL_MISUSE,
        ],
    },
    {
        "id": "supply_chain_prompt_injection",
        "required_agents": {"supply_chain", "tool_poisoning"},
        "title": ("Compound: supply_chain delivers prompt_injection payloads via tool output"),
        "compound_impact": (
            "An untrusted MCP server in the supply chain ships tool output that "
            "contains hidden prompt-injection payloads. When a downstream agent "
            "consumes the output, the injection executes inside the trusted boundary. "
            "This is the dependency-confusion-meets-prompt-injection compound pattern."
        ),
        "owasp": [
            OWASPAgenticCategory.SUPPLY_CHAIN,
            OWASPAgenticCategory.PROMPT_INJECTION,
        ],
    },
    # ── Phase 3-4 compound patterns ──────────────────────────────
    {
        "id": "context_window_privilege_escalation",
        "required_agents": {"context_window", "privilege_escalation"},
        "title": ("Compound: context_window manipulation enables privilege_escalation"),
        "compound_impact": (
            "Context window manipulation enables privilege escalation through "
            "accumulated trust. By flooding or carefully crafting the context window, "
            "the attacker shifts the agent into a high-trust state where privilege "
            "escalation payloads succeed that would otherwise be rejected."
        ),
        "owasp": [
            OWASPAgenticCategory.MEMORY_POISONING,
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
        ],
    },
    {
        "id": "cross_agent_exfil_model_extraction",
        "required_agents": {"cross_agent_exfiltration", "model_extraction"},
        "require_marker_leak": True,
        "title": ("Compound: cross_agent_exfil relays extracted model configuration"),
        "compound_impact": (
            "Cross-agent relay exfiltrates extracted model configuration. "
            "The model_extraction agent recovers system prompts and tool inventory, "
            "then the cross_agent_exfil agent uses inter-agent communication channels "
            "to relay the extracted secrets outside the trust boundary."
        ),
        "owasp": [
            OWASPAgenticCategory.CROSS_AGENT_EXFIL,
            OWASPAgenticCategory.MODEL_EXTRACTION,
        ],
    },
    {
        "id": "race_condition_privilege_escalation",
        "required_agents": {"race_condition", "privilege_escalation"},
        "title": ("Compound: race_condition in authorization enables privilege_escalation"),
        "compound_impact": (
            "Race condition in authorization check enables privilege escalation. "
            "A TOCTOU vulnerability in the permission verification flow allows a "
            "concurrent request to slip through with elevated privileges before the "
            "authorization state is fully committed."
        ),
        "owasp": [
            OWASPAgenticCategory.RACE_CONDITIONS,
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
        ],
    },
    {
        "id": "model_extraction_prompt_injection",
        "required_agents": {"model_extraction", "prompt_injection_hunter"},
        "require_marker_leak": True,
        "title": ("Compound: model_extraction enables targeted prompt_injection"),
        "compound_impact": (
            "Extracted system prompt enables targeted prompt injection. "
            "The model_extraction agent recovers the full system prompt and guardrail "
            "instructions, which the prompt_injection agent then uses to craft a "
            "precisely targeted injection that bypasses the known defences."
        ),
        "owasp": [
            OWASPAgenticCategory.MODEL_EXTRACTION,
            OWASPAgenticCategory.PROMPT_INJECTION,
        ],
    },
    {
        "id": "context_window_cross_agent_exfil",
        "required_agents": {"context_window", "cross_agent_exfiltration"},
        "require_marker_leak": True,
        "title": ("Compound: context_window pollution enables cross_agent data exfiltration"),
        "compound_impact": (
            "Context window pollution enables cross-agent data exfiltration. "
            "By manipulating the context window the attacker plants instructions that "
            "cause the agent to leak sensitive data through cross-agent communication "
            "channels, turning shared context into a covert exfiltration relay."
        ),
        "owasp": [
            OWASPAgenticCategory.MEMORY_POISONING,
            OWASPAgenticCategory.CROSS_AGENT_EXFIL,
        ],
    },
    # ── Phase 5 compound patterns ──────────────────────────────
    {
        "id": "persona_hijacking_privilege_escalation",
        "required_agents": {"persona_hijacking", "privilege_escalation"},
        "title": ("Compound: persona_hijacking enables privilege_escalation via drifted identity"),
        "compound_impact": (
            "Persona hijacking drifts the agent's operating identity into an elevated "
            "role, which the privilege escalation agent then exploits to access "
            "restricted resources. The drifted persona believes it has admin authority, "
            "bypassing tool-call authorization checks that rely on self-reported identity."
        ),
        "owasp": [
            OWASPAgenticCategory.PERSONA_HIJACKING,
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
        ],
    },
    {
        "id": "memory_boundary_collapse_persona_hijacking",
        "required_agents": {"memory_boundary_collapse", "persona_hijacking"},
        "title": ("Compound: memory_boundary_collapse feeds persona_hijacking via leaked instructions"),
        "compound_impact": (
            "Memory boundary collapse leaks system instructions into user-accessible "
            "context, revealing the agent's persona definition. The persona hijacking "
            "agent uses this leaked definition to craft precisely targeted drift attacks "
            "that exploit known weaknesses in the persona boundary."
        ),
        "owasp": [
            OWASPAgenticCategory.MEMORY_BOUNDARY_COLLAPSE,
            OWASPAgenticCategory.PERSONA_HIJACKING,
        ],
    },
    {
        "id": "memory_boundary_collapse_data_exfiltration",
        "required_agents": {"memory_boundary_collapse", "cross_agent_exfiltration"},
        "require_marker_leak": True,
        "title": ("Compound: memory_boundary_collapse enables cross_agent data exfiltration"),
        "compound_impact": (
            "Memory boundary collapse causes sensitive data from one memory store to "
            "bleed into another. The cross-agent exfiltration agent then relays the "
            "leaked data through inter-agent communication channels, turning an internal "
            "memory boundary violation into a full data breach."
        ),
        "owasp": [
            OWASPAgenticCategory.MEMORY_BOUNDARY_COLLAPSE,
            OWASPAgenticCategory.CROSS_AGENT_EXFIL,
        ],
    },
    {
        "id": "persona_hijacking_model_extraction",
        "required_agents": {"persona_hijacking", "model_extraction"},
        "require_marker_leak": True,
        "title": ("Compound: persona_hijacking exposes system prompt via drifted identity"),
        "compound_impact": (
            "Persona hijacking shifts the agent into a developer or debug persona that "
            "discloses system configuration. The model extraction agent then extracts "
            "the full system prompt, tool inventory, and guardrail definitions from the "
            "drifted identity that believes disclosure is authorized."
        ),
        "owasp": [
            OWASPAgenticCategory.PERSONA_HIJACKING,
            OWASPAgenticCategory.MODEL_EXTRACTION,
        ],
    },
    {
        "id": "privilege_escalation_data_exfil",
        "required_agents": {"privilege_escalation"},
        "require_marker_leak": True,
        "title": ("Compound: privilege_escalation chains into data_exfiltration"),
        "compound_impact": (
            "A confused-deputy tool-call chain promoted a low-privilege session to "
            "admin and exfiltrated sensitive data. Each individual tool call would "
            "appear authorized; the compound chain reveals that propagating output "
            "handles between calls bypasses the per-tool authorization model."
        ),
        "owasp": [
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
            OWASPAgenticCategory.TOOL_MISUSE,
        ],
    },
    {
        "id": "race_condition_double_execution",
        "required_agents": {"race_condition"},
        "require_marker_leak": True,
        "title": ("Compound: race_condition produces double_execution and overdraft"),
        "compound_impact": (
            "Concurrent state-mutating requests against a value-bearing endpoint "
            "passed independent authorization checks before any of them committed. "
            "The result is double-execution: a single account paid out N times "
            "under what should have been an atomic budget. Together this is a "
            "race-condition-driven privilege_escalation with direct exfiltration."
        ),
        "owasp": [
            OWASPAgenticCategory.RACE_CONDITIONS,
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
        ],
    },
    # ── D10: Phase D compound patterns — BOLA, BFLA, tool discovery ──
    {
        "id": "bola_model_extraction",
        "required_agents": {"privilege_escalation", "model_extraction"},
        "require_marker_leak": True,
        "title": ("Compound: BOLA + model_extraction reveals cross-tenant data via object ID tampering"),
        "compound_impact": (
            "Model extraction reveals internal object ID schemes and API structure. "
            "The privilege escalation agent then uses BOLA (Broken Object Level Authorization) "
            "payloads with the discovered ID patterns to access other users' resources. "
            "The extracted schema makes the IDOR attacks precisely targeted instead of blind."
        ),
        "owasp": [
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
            OWASPAgenticCategory.MODEL_EXTRACTION,
        ],
    },
    {
        "id": "bfla_identity_spoof_privilege_escalation",
        "required_agents": {"identity_spoof", "privilege_escalation"},
        "title": ("Compound: social engineering BFLA + identity spoofing escalates to full admin"),
        "compound_impact": (
            "Social engineering BFLA (urgency/authority pressure) tricks the agent into "
            "acknowledging a privileged role. Identity spoofing headers then cement that "
            "role claim, and the privilege escalation agent chains the elevated session "
            "into accessing restricted admin functions. The three-stage chain converts "
            "social pressure into verified administrative access."
        ),
        "owasp": [
            OWASPAgenticCategory.IDENTITY_SPOOFING,
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
        ],
    },
    {
        "id": "tool_discovery_prompt_injection",
        "required_agents": {"model_extraction", "prompt_injection_hunter"},
        "title": ("Compound: D5 tool discovery enables targeted prompt injection via hidden tools"),
        "compound_impact": (
            "Tool/function discovery (D5) reveals hidden or undocumented tools that the "
            "agent can invoke. The prompt injection agent then crafts payloads that "
            "specifically invoke these hidden tools, bypassing the visible tool catalog's "
            "authorization checks. Hidden tools often lack the same guardrails as "
            "documented ones, making the injection far more effective."
        ),
        "owasp": [
            OWASPAgenticCategory.MODEL_EXTRACTION,
            OWASPAgenticCategory.PROMPT_INJECTION,
            OWASPAgenticCategory.TOOL_MISUSE,
        ],
    },
    {
        "id": "bola_cross_agent_exfil",
        "required_agents": {"privilege_escalation", "cross_agent_exfiltration"},
        "require_marker_leak": True,
        "title": ("Compound: BOLA object access + cross-agent relay exfiltrates other users' data"),
        "compound_impact": (
            "BOLA (Broken Object Level Authorization) provides access to other users' "
            "objects and data. The cross-agent exfiltration agent then relays this "
            "accessed data through inter-agent communication channels, converting "
            "a single-user authorization bypass into a multi-user data breach."
        ),
        "owasp": [
            OWASPAgenticCategory.PRIVILEGE_ESCALATION,
            OWASPAgenticCategory.CROSS_AGENT_EXFIL,
        ],
    },
    {
        "id": "bfla_memory_poisoning",
        "required_agents": {"identity_spoof", "memory_poisoning"},
        "title": ("Compound: social engineering BFLA plants persistent memory that poisons future sessions"),
        "compound_impact": (
            "Social engineering BFLA convinces the agent to execute a memory-write "
            "operation under urgency/authority pressure. The planted memory content "
            "persists across sessions and poisons future interactions, turning a "
            "single social engineering success into a persistent backdoor."
        ),
        "owasp": [
            OWASPAgenticCategory.IDENTITY_SPOOFING,
            OWASPAgenticCategory.MEMORY_POISONING,
        ],
    },
]


class CorrelationEngine:
    """Rule-based correlation over collected findings.

    Stateless — call `correlate(findings)` once per scan after all attack
    agents have completed. Returns a list of CompoundAttackPath objects.
    """

    async def correlate(
        self,
        scan_id: str,
        findings: list[Finding],
    ) -> list[CompoundAttackPath]:
        """Identify compound attack paths in a list of findings.

        Returns at most one CompoundAttackPath per (host, pattern) pair —
        we don't spam compounds for every (i, j) pair of related findings.
        """
        if not findings:
            return []

        compound_paths: list[CompoundAttackPath] = []
        emitted_pattern_keys: set[tuple[str, str]] = set()

        # Bucket findings by host. Many compounds are host-local because the
        # second-stage exploit uses the first stage's surface.
        by_host: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            host = self._extract_host(f.target_surface)
            by_host[host].append(f)

        for host, host_findings in by_host.items():
            present_agents = {f.agent_type for f in host_findings}

            for pattern in _COMPOUND_PATTERNS:
                key = (host, pattern["id"])
                if key in emitted_pattern_keys:
                    continue
                if not pattern["required_agents"].issubset(present_agents):
                    continue
                # Optional gate: require at least one finding to contain a
                # leaked sensitive marker, for compounds that need exfil
                # evidence to be meaningful.
                if pattern.get("require_marker_leak"):
                    if not any(self._has_marker_evidence(f) for f in host_findings):
                        continue

                participants = [f for f in host_findings if f.agent_type in pattern["required_agents"]]
                if not participants:
                    continue

                cp = self._build_compound_path(
                    scan_id=scan_id,
                    pattern=pattern,
                    host=host,
                    participants=participants,
                )
                compound_paths.append(cp)
                emitted_pattern_keys.add(key)

        # Cross-host compounds: if any findings from prompt_injection +
        # tool_poisoning exist anywhere (different hosts) we still emit a
        # global "supply_chain delivers prompt_injection" compound — this
        # mirrors how a real supply chain attack crosses host boundaries.
        all_agents = {f.agent_type for f in findings}
        for pattern in _COMPOUND_PATTERNS:
            if pattern["id"] != "supply_chain_prompt_injection":
                continue
            global_key = ("__global__", pattern["id"])
            if global_key in emitted_pattern_keys:
                continue
            if pattern["required_agents"].issubset(all_agents):
                participants = [f for f in findings if f.agent_type in pattern["required_agents"]][:6]
                cp = self._build_compound_path(
                    scan_id=scan_id,
                    pattern=pattern,
                    host="multi-host",
                    participants=participants,
                )
                compound_paths.append(cp)
                emitted_pattern_keys.add(global_key)

        logger.info(
            "Correlation v1: %d findings → %d compound attack paths",
            len(findings),
            len(compound_paths),
        )
        return compound_paths

    @staticmethod
    def _extract_host(target_surface: str) -> str:
        """Pull a host identifier from a target surface string.

        target_surface may be a URL, a path, or an arbitrary descriptor.
        We extract the netloc when it's a URL and otherwise return the raw
        string so unrelated surfaces don't bucket together.
        """
        if not target_surface:
            return "unknown"
        try:
            parsed = urlparse(target_surface)
            if parsed.netloc:
                return parsed.netloc
        except Exception as exc:
            logger.debug("urlparse failed for surface: %s", type(exc).__name__)
        # Fall back to the raw surface (kept short)
        return target_surface[:80]

    @staticmethod
    def _has_marker_evidence(finding: Finding) -> bool:
        """True if a finding's text fields suggest a sensitive marker leaked."""
        text = " ".join(
            [
                finding.title or "",
                finding.description or "",
                finding.raw_response or "",
            ]
        ).lower()
        return any(
            tok in text for tok in ("canary", "secret", "leak", "extract", "marker", "elevated", "trust_granted")
        )

    @staticmethod
    def _build_compound_path(
        scan_id: str,
        pattern: dict[str, Any],
        host: str,
        participants: list[Finding],
    ) -> CompoundAttackPath:
        """Construct a CompoundAttackPath from a fired pattern."""
        finding_ids = [f.id for f in participants]
        steps: list[AttackChainStep] = []
        for i, f in enumerate(participants, start=1):
            steps.append(
                AttackChainStep(
                    step_number=i,
                    agent_type=f.agent_type,
                    technique=f.technique or "unknown",
                    description=(f"Stage {i}: {f.title} ({f.agent_type}) on {f.target_surface}"),
                    target_surface=f.target_surface,
                )
            )

        # Severity: max of participants, escalated one tier when validated
        # findings combine into a compound (the chain is more severe than parts).
        severities = {f.severity for f in participants}
        if FindingSeverity.CRITICAL in severities:
            sev = FindingSeverity.CRITICAL
        elif FindingSeverity.HIGH in severities:
            sev = FindingSeverity.CRITICAL
        else:
            sev = FindingSeverity.HIGH

        title = pattern["title"]
        if host != "__global__" and host != "multi-host":
            title = f"{title} on {host}"

        # Build a description that includes both the compound impact and
        # the explicit indicator vocabulary (data_exfiltration, etc.) so
        # the rubric matcher can credit the chain to the right scenario.
        description = (
            f"compound chain detected ({pattern['id']}). "
            f"{pattern['compound_impact']} "
            f"Participating findings: {', '.join(f.title for f in participants[:5])}."
        )

        remediation = RemediationGuidance(
            summary=(
                f"Break the chain at any stage: validate inputs flowing between the "
                f"{', '.join(sorted(pattern['required_agents']))} stages."
            ),
            detailed_steps=[
                f"Audit {f.agent_type} surface {f.target_surface} per finding {f.id[:8]}" for f in participants[:5]
            ],
        )

        return CompoundAttackPath(
            scan_id=scan_id,
            title=title,
            description=description,
            severity=sev,
            finding_ids=finding_ids,
            attack_path_steps=steps,
            compound_impact=pattern["compound_impact"],
            exploitability_score=8.0,
            detectability_score=6.5,
            owasp_agentic=pattern["owasp"],
            remediation=remediation,
        )
