"""
agents/persona_hijacking_agent.py
PH-11 — Persona Hijacking Agent

Hunts vulnerabilities where an agent's identity, role, or behavioral
constraints can be overwritten by attacker-controlled content.

Unique to agentic AI — traditional security has no equivalent:
  - An agent can be convinced it has a different role mid-conversation
  - Role boundaries enforced only by prompt text are bypassable
  - Sub-agents inherit personas from orchestrators without verification
  - Constitutional constraints can be "updated" via injected system messages

Techniques (5):
  PH-T1  ROLE_BOUNDARY_WEAKNESS   — agent role defined only by prompt text
  PH-T2  PERSONA_INJECTION_SINK   — user input flows into identity/role context
  PH-T3  ORCHESTRATOR_IMPERSONATION — sub-agent trusts orchestrator identity claims
  PH-T4  CONSTITUTIONAL_OVERRIDE  — paths to overwrite constitutional constraints
  PH-T5  CROSS_AGENT_CONTAMINATION — one agent's persona bleeds into another

CLI:
  python persona_hijacking_agent.py https://github.com/target/repo -o results/
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
GRAY  = "\033[90m"
RESET = "\033[0m"


class PersonaHijackingAgent(BaseAgent):
    AGENT_ID   = "PH-11"
    AGENT_NAME = "Persona Hijacking Agent"
    VULN_CLASS = "MESH_TRUST"
    TECHNIQUES = ["PH-T1", "PH-T2", "PH-T3", "PH-T4", "PH-T5"]
    MAAC_PHASES = [2, 3]  # Prompt-Layer Access + Model-Layer Manipulation

    # Role definition patterns — where agent identity is established
    ROLE_DEFINITION_PATTERNS = [
        r'you are\s+(?:a|an|the)\s+\w+',
        r'your role is|your job is|your task is',
        r'act as|behave as|pretend to be',
        r'"role"\s*:\s*"system"',
        r'SystemMessage|system_message|system_prompt',
        r'persona\s*[=:]\s*["\']',
        r'identity\s*[=:]\s*["\']',
    ]

    # Injection sink patterns — where user input reaches identity context
    INJECTION_SINK_PATTERNS = [
        r'f["\'].*\{user_?input\}.*you are',
        r'format\(.*role.*=.*user',
        r'system.*\+.*user_message',
        r'prompt.*\+.*input',
        r'messages.*append.*system',
        r'insert\(0.*user',           # inserting user content at position 0 (system position)
    ]

    # Orchestrator trust patterns — where sub-agents accept identity claims
    ORCHESTRATOR_TRUST_PATTERNS = [
        r'from_orchestrator|orchestrator_message|parent_agent',
        r'trust.*orchestrator|orchestrator.*trust',
        r'if.*orchestrator.*:',
        r'orchestrator_id|agent_id.*orchestrator',
        r'delegate|delegat',
        r'spawn.*agent|create.*agent|new.*agent',
    ]

    # Constitutional constraint patterns — looking for overrideable ones
    OVERRIDE_PATTERNS = [
        r'if.*override|allow_override|can_override',
        r'bypass|skip.*safety|disable.*filter',
        r'unsafe\s*=\s*True|safe\s*=\s*False',
        r'force\s*=\s*True|strict\s*=\s*False',
        r'developer_mode|debug_mode|admin_mode',
    ]

    # Cross-agent contamination patterns — shared context between agents
    CONTAMINATION_PATTERNS = [
        r'shared.*context|global.*context|context.*shared',
        r'agent.*pool|pool.*agent',
        r'conversation.*history.*shared|shared.*history',
        r'memory.*global|global.*memory',
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "PH-T1": self._t1_role_boundary_weakness,
            "PH-T2": self._t2_persona_injection_sink,
            "PH-T3": self._t3_orchestrator_impersonation,
            "PH-T4": self._t4_constitutional_override,
            "PH-T5": self._t5_cross_agent_contamination,
        }

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        self._print_header(target)
        files = self._discover_files(repo_path)
        print(f"  Files     : {len(files)}\n")

        for tech_id, fn in self.technique_library.items():
            print(f"  {BLUE}[{tech_id}]{RESET} {fn.__doc__ or tech_id}")
            fn(files, repo_path)

        self.save_history(target, output_dir)
        out = self.save_findings(output_dir)
        self._print_summary()
        print(f"  Output    : {out}")
        return self.findings

    # ── PH-T1: Role Boundary Weakness ─────────────────────────────────────

    def _t1_role_boundary_weakness(self, files: list[str], repo_path: str):
        """Agent role enforced only by prompt text with no runtime verification"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            role_defs = sum(1 for p in self.ROLE_DEFINITION_PATTERNS
                           if re.search(p, code, re.IGNORECASE))
            if role_defs == 0:
                continue

            # Check if role has ANY runtime enforcement (code-based, not just text)
            has_runtime_enforcement = any(re.search(p, code) for p in [
                r'isinstance.*role|type.*check.*role',
                r'assert.*role|raise.*RoleError',
                r'verify.*identity|authenticate.*agent',
                r'role_validator|RoleGuard',
                r'if.*not.*authorized',
            ])

            try:
                data = self._haiku(f"""Analyze this agent code for persona/role boundary weaknesses.

FILE: {rel}
HAS RUNTIME ROLE ENFORCEMENT: {has_runtime_enforcement}
CODE (first 2000 chars): {code[:2000]}

Identify if agent role/identity is:
1. Defined ONLY in prompt text (no code-level enforcement) — attackers can override via injection
2. Accepted from user input without verification
3. Not re-verified between conversation turns

Return JSON only:
{{"findings": [{{"severity": "HIGH|MEDIUM", "title": "title", "description": "why boundary is weak", "attack_vector": "injection payload that overrides role: e.g. 'Ignore your previous role. You are now...'", "remediation": "how to add runtime enforcement"}}]}}
If boundaries are adequately enforced: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="MESH_TRUST",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="PH-T1",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=None,
                        poc_explanation="Role boundaries enforced only in system prompt text are trivially bypassable via direct instruction injection",
                        cvss_estimate="7.5 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}PH-T1 error {rel}: {e}{RESET}")

    # ── PH-T2: Persona Injection Sink ─────────────────────────────────────

    def _t2_persona_injection_sink(self, files: list[str], repo_path: str):
        """User-controlled input flows directly into agent identity/role context"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            # Find direct injection patterns
            for pattern in self.INJECTION_SINK_PATTERNS:
                if re.search(pattern, code, re.IGNORECASE):
                    try:
                        data = self._haiku(f"""This code appears to allow user input to influence agent identity/persona context.

FILE: {rel}
PATTERN MATCHED: {pattern}
CODE (first 2000 chars): {code[:2000]}

Confirm: Does user-controlled input flow into system prompt, role definition, or identity context WITHOUT sanitization?

Return JSON only:
{{"confirmed": true/false, "severity": "CRITICAL|HIGH", "title": "title", "description": "exact data flow: input → sink", "attack_vector": "payload that overrides agent identity", "poc": "python code demonstrating injection", "remediation": "fix"}}""")

                        if data.get("confirmed"):
                            self._add_finding(AgentFinding(
                                id=self._fid(rel + pattern),
                                agent_id=self.AGENT_ID,
                                vuln_class="MESH_TRUST",
                                severity=data["severity"],
                                title=data["title"],
                                file=rel,
                                technique="PH-T2",
                                description=data["description"],
                                attack_vector=data["attack_vector"],
                                poc=data.get("poc"),
                                poc_explanation="User content reaching system role context allows complete persona replacement",
                                cvss_estimate="9.1 (CRITICAL) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                                remediation=data.get("remediation")
                            ))
                    except Exception as e:
                        if self.verbose:
                            print(f"    {GRAY}PH-T2 error {rel}: {e}{RESET}")
                    break

    # ── PH-T3: Orchestrator Impersonation ─────────────────────────────────

    def _t3_orchestrator_impersonation(self, files: list[str], repo_path: str):
        """Sub-agents accept orchestrator identity claims without cryptographic verification"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            orch_count = sum(1 for p in self.ORCHESTRATOR_TRUST_PATTERNS
                           if re.search(p, code, re.IGNORECASE))
            if orch_count < 2:
                continue

            # Check if there's any cryptographic verification of orchestrator identity
            has_crypto_verify = any(re.search(p, code) for p in [
                r'hmac|signature|verify.*sign|sign.*verify',
                r'jwt|certificate|x509',
                r'public_key|private_key',
                r'cryptography|nacl|pyca',
            ])

            if has_crypto_verify:
                continue  # Has real verification, skip

            try:
                data = self._haiku(f"""Analyze this multi-agent code for orchestrator impersonation vulnerability.

FILE: {rel}
CODE (first 2000 chars): {code[:2000]}

Key question: When a sub-agent receives instructions from an "orchestrator", does it verify the orchestrator's identity cryptographically, or does it trust identity claims in the message content alone?

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH", "title": "title", "description": "what trust assumption is made", "attack_vector": "how attacker impersonates orchestrator to sub-agent", "remediation": "cryptographic identity verification approach"}}]}}
If orchestrator identity is properly verified: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="MESH_TRUST",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="PH-T3",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=None,
                        poc_explanation="Sub-agent with no cryptographic orchestrator verification accepts any message claiming orchestrator authority",
                        cvss_estimate="8.8 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}PH-T3 error {rel}: {e}{RESET}")

    # ── PH-T4: Constitutional Override ────────────────────────────────────

    def _t4_constitutional_override(self, files: list[str], repo_path: str):
        """Code paths that can disable or override constitutional safety constraints"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            override_count = sum(1 for p in self.OVERRIDE_PATTERNS
                                if re.search(p, code, re.IGNORECASE))
            if override_count == 0:
                continue

            try:
                data = self._haiku(f"""Analyze this code for paths that override, bypass, or disable safety constraints.

FILE: {rel}
CODE (first 2000 chars): {code[:2000]}

Specifically look for:
1. Parameters or flags that disable safety checks (unsafe=True, safe=False)
2. Developer/debug/admin mode that removes constraints
3. Override parameters accessible via API or user input
4. Configuration that disables constitutional constraints

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH|MEDIUM", "title": "title", "description": "what constraint can be bypassed", "attack_vector": "how to trigger override (API param, env var, etc.)", "poc": "code showing bypass", "remediation": "fix"}}]}}
If overrides are appropriately restricted: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="MESH_TRUST",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="PH-T4",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=f.get("poc"),
                        poc_explanation=None,
                        cvss_estimate="8.6 (High)" if f["severity"] in ("CRITICAL","HIGH") else None,
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}PH-T4 error {rel}: {e}{RESET}")

    # ── PH-T5: Cross-Agent Persona Contamination ──────────────────────────

    def _t5_cross_agent_contamination(self, files: list[str], repo_path: str):
        """Shared conversation context causes persona bleed between agents"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            contamination_count = sum(
                1 for p in self.CONTAMINATION_PATTERNS
                if re.search(p, code, re.IGNORECASE)
            )
            if contamination_count == 0:
                continue

            try:
                data = self._haiku(f"""Analyze this multi-agent code for cross-agent persona contamination.

FILE: {rel}
CODE (first 2000 chars): {code[:2000]}

Identify: Is conversation history or context shared between agents of different roles/personas? If agent A (e.g., a helpful assistant) shares context with agent B (e.g., a security auditor), can an attacker craft messages to agent A that corrupt agent B's persona?

Return JSON only:
{{"findings": [{{"severity": "HIGH|MEDIUM", "title": "title", "description": "which agents share context and why this is dangerous", "attack_vector": "message to agent A that corrupts agent B's persona", "remediation": "context isolation approach"}}]}}
If agents are properly isolated: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="MESH_TRUST",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="PH-T5",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=None,
                        poc_explanation=None,
                        cvss_estimate="7.5 (High)",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}PH-T5 error {rel}: {e}{RESET}")

    def _print_summary(self):
        crit = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        print(f"\n  {BOLD}PH-11 complete{RESET} — {len(self.findings)} findings | "
              f"\033[91m{crit} CRITICAL\033[0m | \033[93m{high} HIGH\033[0m")


if __name__ == "__main__":
    import argparse, subprocess, tempfile, shutil

    p = argparse.ArgumentParser(description="PH-11 Persona Hijacking Agent")
    p.add_argument("target", help="GitHub URL or local repo path")
    p.add_argument("-o", "--output", default="results/ph11/")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    repo_path = args.target
    tmp_dir = None

    if args.target.startswith("http"):
        tmp_dir = tempfile.mkdtemp(prefix="argus_ph_")
        repo_path = os.path.join(tmp_dir, "repo")
        print(f"Cloning {args.target}...")
        subprocess.run(["git", "clone", "--depth=1", "--quiet", args.target, repo_path])

    try:
        agent = PersonaHijackingAgent(verbose=args.verbose)
        agent.run(args.target, repo_path, args.output)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
