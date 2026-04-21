"""
agents/lateral_movement_agent.py
LM-13 — Lateral Movement Agent

Hunts TRACE_LATERAL vulnerabilities — attack paths where an agent uses
its legitimate access to reach systems, tools, or data it should not.

In traditional security, lateral movement means pivoting between hosts.
In agentic AI, it means pivoting between agents, tools, and trust boundaries
using the orchestration layer itself as the attack vector.

Techniques (5):
  LM-T1  TOOL_CHAIN_PIVOT       — tool A output feeds tool B privileged input unsanitized
  LM-T2  HANDOFF_HIJACK         — agent delegation/handoff reaches unintended privileged agent
  LM-T3  CONTEXT_PERSISTENCE    — injected context survives to subsequent agent turns/agents
  LM-T4  CROSS_AGENT_EXFIL      — multi-hop tool chain exfiltrates data across agent boundaries
  LM-T5  SPAWN_ESCALATION       — spawned sub-agent inherits or escalates parent permissions

CLI:
  python lateral_movement_agent.py https://github.com/target/repo -o results/
  python lateral_movement_agent.py /local/clone -o results/lm13/
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


class LateralMovementAgent(BaseAgent):
    AGENT_ID   = "LM-13"
    AGENT_NAME = "Lateral Movement Agent"
    VULN_CLASS = "TRACE_LATERAL"
    TECHNIQUES = ["LM-T1", "LM-T2", "LM-T3", "LM-T4", "LM-T5"]
    MAAC_PHASES = [7, 8]  # Multi-Agent Escalation + Environment Pivoting

    # Tool-to-tool data flow patterns — output of one tool becomes input of another
    TOOL_CHAIN_PATTERNS = [
        r"tool.*output.*input|output.*tool.*input",
        r"result.*=.*tool\.|tool\..*result",
        r"\.run\(.*\.run\(|\.execute\(.*\.execute\(",
        r"chain\(|pipe\(|compose\(",
        r"tool_result.*next_tool|previous.*tool.*current",
        r"callback.*tool|tool.*callback",
        r"on_tool_end|after_tool|tool_output",
        r"intermediate_steps|agent_scratchpad",
    ]

    # Agent handoff / delegation patterns
    HANDOFF_PATTERNS = [
        r"handoff|hand_off|transfer_to",
        r"delegate.*agent|agent.*delegate",
        r"swarm.*handoff|triage.*agent",
        r"Agent\(.*handoffs\s*=|handoffs\s*=\s*\[",
        r"escalate.*agent|route.*agent",
        r"transfer_to_\w+|handoff_to_\w+",
        r"\.handoffs\s*=|add_handoff\(",
    ]

    # Context persistence patterns — shared state surviving across turns/agents
    CONTEXT_PERSISTENCE_PATTERNS = [
        r"context\[|context\.update|context\.set",
        r"shared_context|global_context|run_context",
        r"RunContextWrapper|RunContext",
        r"memory\.save|store\.put|persist\(",
        r"session\[|session\.set|session\.update",
        r"state\[.*\]\s*=|state\.update",
        r"conversation_history|chat_history|message_history",
    ]

    # Cross-agent data exfiltration patterns
    EXFIL_PATTERNS = [
        r"tool.*url.*request|fetch.*user.*data",
        r"send.*external|post.*data.*http",
        r"write.*file.*user|export.*data",
        r"webhook|callback_url|notification_url",
        r"requests\.(get|post|put)|httpx\.(get|post)",
        r"urllib.*urlopen|aiohttp.*session",
    ]

    # Agent spawning and permission inheritance patterns
    SPAWN_PATTERNS = [
        r"Agent\(.*instructions|create_agent|spawn.*agent",
        r"sub_agent|child_agent|worker_agent",
        r"Runner\.run.*agent|asyncio.*create_task.*agent",
        r"clone\(\)|copy\(\).*agent",
        r"from_agent|inherit.*permissions|parent.*agent",
        r"nested.*agent|agent.*nested",
        r"ThreadPoolExecutor.*agent|concurrent.*agent",
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "LM-T1": self._t1_tool_chain_pivot,
            "LM-T2": self._t2_handoff_hijack,
            "LM-T3": self._t3_context_persistence,
            "LM-T4": self._t4_cross_agent_exfil,
            "LM-T5": self._t5_spawn_escalation,
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

    # ── LM-T1: Tool Chain Pivot ───────────────────────────────────────────

    def _t1_tool_chain_pivot(self, files: list[str], repo_path: str):
        """Tool A output flows into Tool B privileged input without sanitization"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            chain_count = sum(1 for p in self.TOOL_CHAIN_PATTERNS
                              if re.search(p, code, re.IGNORECASE))
            if chain_count < 2:
                continue

            # Check for dangerous sinks downstream in the same file
            has_privileged_sink = any(re.search(p, code) for p in [
                r"exec\(|eval\(|subprocess",
                r"open\(.*[\"']w|write\(",
                r"cursor\.execute|session\.execute",
                r"requests\.(get|post)|httpx\.",
                r"os\.system|os\.popen",
            ])

            if has_privileged_sink:
                hits.append((rel, code[:2500]))

        for rel, code_snippet in hits[:6]:
            try:
                data = self._haiku(f"""Analyze this code for tool chain lateral movement vulnerabilities.

FILE: {rel}
CODE: {code_snippet}

Identify paths where:
1. Output from one tool is passed as input to another tool without sanitization
2. An attacker-controlled tool result can influence what a privileged tool executes
3. The tool chain creates a path from low-privilege user input to privileged execution

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH|MEDIUM", "title": "title", "description": "exact chain: tool A output → tool B input → privileged sink", "attack_vector": "what attacker injects into tool A to reach tool B sink", "poc": "python code showing the pivot", "remediation": "fix"}}]}}
If no exploitable pivot: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="TRACE_LATERAL",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="LM-T1",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=f.get("poc"),
                        poc_explanation="Tool chain pivot allows low-privilege input to reach privileged execution sink",
                        cvss_estimate="8.8 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}LM-T1 error {rel}: {e}{RESET}")

    # ── LM-T2: Handoff Hijack ─────────────────────────────────────────────

    def _t2_handoff_hijack(self, files: list[str], repo_path: str):
        """Agent handoff/delegation reaches unintended privileged agent"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            handoff_count = sum(1 for p in self.HANDOFF_PATTERNS
                               if re.search(p, code, re.IGNORECASE))
            if handoff_count == 0:
                continue

            hits.append((rel, code[:2500]))

        for rel, code_snippet in hits[:6]:
            try:
                data = self._haiku(f"""Analyze this agent code for handoff hijacking vulnerabilities.

FILE: {rel}
CODE: {code_snippet}

Identify:
1. Agent handoffs where the destination agent is determined by LLM output or user input (no allowlist)
2. Triage/routing patterns where attacker input can redirect to a privileged agent
3. Handoff chains where a low-privilege agent can reach a high-privilege agent via intermediate hops
4. Missing verification that the receiving agent is authorized to receive the handoff

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH|MEDIUM", "title": "title", "description": "which agents are involved and how the handoff can be hijacked", "attack_vector": "what input causes handoff to unintended privileged agent", "poc": "python code or input payload", "remediation": "allowlist approach or verification"}}]}}
If handoffs are properly restricted: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="TRACE_LATERAL",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="LM-T2",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=f.get("poc"),
                        poc_explanation="Handoff to unintended agent grants attacker access to higher-privilege agent capabilities",
                        cvss_estimate="9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}LM-T2 error {rel}: {e}{RESET}")

    # ── LM-T3: Context Persistence Attack ────────────────────────────────

    def _t3_context_persistence(self, files: list[str], repo_path: str):
        """Injected context survives to subsequent agent turns or other agents"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            ctx_count = sum(1 for p in self.CONTEXT_PERSISTENCE_PATTERNS
                           if re.search(p, code, re.IGNORECASE))
            if ctx_count < 2:
                continue

            hits.append((rel, code[:2500]))

        for rel, code_snippet in hits[:6]:
            try:
                data = self._haiku(f"""Analyze this agent code for context persistence vulnerabilities.

FILE: {rel}
CODE: {code_snippet}

Identify:
1. User-controlled input stored in shared context/state that persists to future turns or other agents
2. Context that is never sanitized between agent turns (attacker can inject instructions that activate later)
3. Shared context objects where one agent's writes are visible to other agents without access control
4. Message history that includes tool results the attacker can control, read by subsequent agents

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH|MEDIUM", "title": "title", "description": "what persists and how long, which agents see it", "attack_vector": "injection payload and when it activates", "poc": "code showing injection and persistence", "remediation": "context isolation approach"}}]}}
If context is properly isolated: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="TRACE_LATERAL",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="LM-T3",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=f.get("poc"),
                        poc_explanation="Injected context persists across turns, activating in future agent operations",
                        cvss_estimate="8.6 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}LM-T3 error {rel}: {e}{RESET}")

    # ── LM-T4: Cross-Agent Exfiltration ──────────────────────────────────

    def _t4_cross_agent_exfil(self, files: list[str], repo_path: str):
        """Multi-hop tool chain moves data across agent boundaries to attacker"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            # Need both: data access AND outbound capability in same file/module
            has_data_access = any(re.search(p, code, re.IGNORECASE) for p in [
                r"database|db\.|cursor\.",
                r"read_file|open\(.*[\"']r",
                r"vector.*search|similarity_search|retrieve",
                r"memory\.load|context\.get",
                r"user.*data|private.*data|secret|credential",
            ])
            has_outbound = any(re.search(p, code) for p in self.EXFIL_PATTERNS)

            if has_data_access and has_outbound:
                hits.append((rel, code[:2500]))

        for rel, code_snippet in hits[:5]:
            try:
                data = self._haiku(f"""Analyze this agent code for cross-agent data exfiltration vulnerabilities.

FILE: {rel}
CODE: {code_snippet}

Identify paths where:
1. Sensitive data (user PII, credentials, internal data) is accessible to an agent
2. The same agent or a downstream agent has HTTP/file write capabilities
3. An attacker via prompt injection could chain these to exfiltrate data
4. The exfiltration path crosses agent or trust boundaries

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH", "title": "title", "description": "data source + exfil path + what leaves the trust boundary", "attack_vector": "prompt injection payload that triggers the exfil chain", "poc": "code or payload showing the exfil sequence", "remediation": "egress control and data boundary enforcement"}}]}}
If no exfil path: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="TRACE_LATERAL",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="LM-T4",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=f.get("poc"),
                        poc_explanation="Multi-hop tool chain moves private data from trusted store to attacker-controlled endpoint",
                        cvss_estimate="9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}LM-T4 error {rel}: {e}{RESET}")

    # ── LM-T5: Spawn Escalation ───────────────────────────────────────────

    def _t5_spawn_escalation(self, files: list[str], repo_path: str):
        """Spawned sub-agents inherit or escalate parent agent permissions"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            spawn_count = sum(1 for p in self.SPAWN_PATTERNS
                             if re.search(p, code, re.IGNORECASE))
            if spawn_count < 2:
                continue

            hits.append((rel, code[:2500]))

        for rel, code_snippet in hits[:6]:
            try:
                data = self._haiku(f"""Analyze this agent code for spawn-based privilege escalation.

FILE: {rel}
CODE: {code_snippet}

Identify:
1. Sub-agents spawned with the same or higher privilege level as the parent without downgrade
2. Dynamic agent creation where attacker input influences the spawned agent's instructions or tools
3. Agent cloning that preserves privileged tool access in the clone
4. Concurrent agent spawning where each spawned agent gets full parent permissions

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH|MEDIUM", "title": "title", "description": "what permission is inherited/escalated and by how many hops", "attack_vector": "how attacker triggers spawn with elevated permissions", "poc": "code demonstrating the spawn and inherited access", "remediation": "principle of least privilege on spawned agents"}}]}}
If spawned agents are properly restricted: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="TRACE_LATERAL",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="LM-T5",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=f.get("poc"),
                        poc_explanation="Spawned sub-agent inherits privileged tool access without least-privilege downgrade",
                        cvss_estimate="8.8 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}LM-T5 error {rel}: {e}{RESET}")

    def _print_summary(self):
        crit = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        print(f"\n  {BOLD}LM-13 complete{RESET} — {len(self.findings)} findings | "
              f"\033[91m{crit} CRITICAL\033[0m | \033[93m{high} HIGH\033[0m")


if __name__ == "__main__":
    import argparse, subprocess, tempfile, shutil

    p = argparse.ArgumentParser(description="LM-13 Lateral Movement Agent")
    p.add_argument("target", help="GitHub URL or local repo path")
    p.add_argument("-o", "--output", default="results/lm13/")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    repo_path = args.target
    tmp_dir = None

    if args.target.startswith("http"):
        tmp_dir = tempfile.mkdtemp(prefix="argus_lm_")
        repo_path = os.path.join(tmp_dir, "repo")
        print(f"Cloning {args.target}...")
        subprocess.run(["git", "clone", "--depth=1", "--quiet", args.target, repo_path])

    try:
        agent = LateralMovementAgent(verbose=args.verbose)
        agent.run(args.target, repo_path, args.output)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
