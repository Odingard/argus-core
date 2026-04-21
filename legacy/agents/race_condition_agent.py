"""
agents/race_condition_agent.py
RC-08 — Race Condition Agent

Hunts timing-dependent vulnerabilities in agentic AI systems.

Agentic frameworks are especially vulnerable to race conditions because:
  - Multiple agents share memory/state concurrently
  - Tool calls are async and non-atomic
  - Checkpoint/restore operations are not transactional
  - LLM-generated code often ignores concurrency entirely

Techniques (5):
  RC-T1  SHARED_STATE_RACE     — concurrent agents writing to same memory/store
  RC-T2  CHECKPOINT_TOCTOU     — time-of-check vs time-of-use on checkpoint files
  RC-T3  TOOL_INVOCATION_RACE  — concurrent tool calls that modify shared resource
  RC-T4  EVENT_ORDERING_ATTACK — exploiting non-deterministic event ordering
  RC-T5  SESSION_FIXATION_RACE — racing session creation to fixate token/ID

CLI:
  python race_condition_agent.py https://github.com/target/repo -o results/
  python race_condition_agent.py /local/clone -o results/
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
GRAY  = "\033[90m"
RESET = "\033[0m"


class RaceConditionAgent(BaseAgent):
    AGENT_ID   = "RC-08"
    AGENT_NAME = "Race Condition Agent"
    VULN_CLASS = "RACE_CONDITION"
    TECHNIQUES = ["RC-T1", "RC-T2", "RC-T3", "RC-T4", "RC-T5"]
    MAAC_PHASES = [5]  # Tool Misuse (race in tool invocation path)

    # Code patterns that indicate race condition vulnerability
    SHARED_STATE_PATTERNS = [
        r"class\s+\w+.*:\s*\n\s+\w+\s*[=:]\s*\{",          # class-level dict (SimpleMemory pattern)
        r"class\s+\w+.*:\s*\n\s+\w+\s*[=:]\s*\[",          # class-level list
        r"global\s+\w+",                                      # global state
        r"@classmethod|@staticmethod",                        # shared class methods
        r"threading\.Lock|asyncio\.Lock",                     # explicit lock (check for missing ones)
    ]

    CHECKPOINT_PATTERNS = [
        r"pickle\.load|pickle\.dump",
        r"open\([^)]+['\"]rb['\"]|['\"]wb['\"]",
        r"checkpoint|restore|save_state|load_state",
        r"\.pkl|\.checkpoint|\.state",
    ]

    ASYNC_TOOL_PATTERNS = [
        r"asyncio\.gather|asyncio\.create_task",
        r"await.*tool\.|await.*execute\(",
        r"concurrent\.futures|ThreadPoolExecutor",
        r"async def.*tool|async def.*agent",
    ]

    SESSION_PATTERNS = [
        r"session_id\s*=|token\s*=\s*uuid|generate.*token",
        r"secrets\.token|os\.urandom",
        r"if.*session.*not.*in|if.*token.*not.*in",
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "RC-T1": self._t1_shared_state_race,
            "RC-T2": self._t2_checkpoint_toctou,
            "RC-T3": self._t3_tool_invocation_race,
            "RC-T4": self._t4_event_ordering,
            "RC-T5": self._t5_session_fixation_race,
        }

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        self._print_header(target)
        files = self._discover_files(repo_path)
        print(f"  Files     : {len(files)}\n")

        for tech_id, technique_fn in self.technique_library.items():
            print(f"  {BLUE}[{tech_id}]{RESET} {technique_fn.__doc__ or tech_id}")
            technique_fn(files, repo_path)

        self.save_history(target, output_dir)
        out = self.save_findings(output_dir)
        self._print_summary()
        print(f"  Output    : {out}")
        return self.findings

    # ── RC-T1: Shared State Race ───────────────────────────────────────────

    def _t1_shared_state_race(self, files: list[str], repo_path: str):
        """Shared mutable class-level state with no locking"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)
            lines = code.split("\n")

            # Find class-level mutable defaults (the SimpleMemory anti-pattern)
            in_class = False
            class_indent = 0
            for i, line in enumerate(lines):
                stripped = line.strip()

                # Track class entry
                if re.match(r"^class\s+\w+", stripped):
                    in_class = True
                    class_indent = len(line) - len(line.lstrip())
                    continue

                if in_class:
                    indent = len(line) - len(line.lstrip())
                    # Exited class body
                    if stripped and indent <= class_indent and not stripped.startswith("#"):
                        in_class = False
                        continue

                    # Class-level mutable: dict or list assigned without __init__
                    if re.match(r"^\w+\s*(?::\s*\S+)?\s*=\s*[\{\[]", stripped):
                        # Not inside a method (would have deeper indent)
                        if indent == class_indent + 4:
                            hits.append((rel, i + 1, line.strip()))

        if not hits:
            return

        # Analyze with Haiku
        hits_summary = "\n".join([f"  {r}:{ln}: {code_}" for r, ln, code_ in hits[:10]])
        try:
            data = self._haiku(f"""Analyze these Python class-level mutable default assignments for race condition vulnerabilities in an agentic AI system.

CLASS-LEVEL MUTABLE STATE FOUND:
{hits_summary}

For each entry that is genuinely exploitable in a concurrent/multi-agent context, return findings. Consider: multiple agents sharing the same class instance memory, concurrent tool calls, multi-tenant deployments.

Return JSON only:
{{"findings": [{{"file": "path", "line": 42, "severity": "CRITICAL|HIGH|MEDIUM", "title": "concise title", "description": "technical detail", "attack_vector": "how attacker exploits this", "poc": "minimal poc code", "remediation": "specific fix"}}]}}
If no exploitable findings: {{"findings": []}}""")

            for f in data.get("findings", []):
                self._add_finding(AgentFinding(
                    id=self._fid(f["file"] + str(f.get("line", ""))),
                    agent_id=self.AGENT_ID,
                    vuln_class="RACE_CONDITION",
                    severity=f["severity"],
                    title=f["title"],
                    file=f["file"],
                    technique="RC-T1",
                    description=f["description"],
                    attack_vector=f["attack_vector"],
                    poc=f.get("poc"),
                    poc_explanation=None,
                    cvss_estimate=None,
                    remediation=f.get("remediation")
                ))
        except Exception as e:
            if self.verbose:
                print(f"    {GRAY}RC-T1 analysis error: {e}{RESET}")

    # ── RC-T2: Checkpoint TOCTOU ───────────────────────────────────────────

    def _t2_checkpoint_toctou(self, files: list[str], repo_path: str):
        """Checkpoint/restore TOCTOU — check-then-act on untrusted files"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)
            has_checkpoint = any(re.search(p, code, re.I) for p in self.CHECKPOINT_PATTERNS)
            if not has_checkpoint:
                continue

            # Look for the dangerous pattern: check file exists, then load without re-verify
            if re.search(r"os\.path\.exists|Path.*exists", code) and \
               re.search(r"pickle\.load|open\(.*rb\)", code):
                hits.append((rel, code[:1500]))

        if not hits:
            return

        for rel, code_snippet in hits[:5]:
            try:
                data = self._haiku(f"""Analyze this code for checkpoint/state TOCTOU (Time-Of-Check-Time-Of-Use) race conditions.

FILE: {rel}
CODE: {code_snippet}

Specifically look for:
1. File existence check followed by non-atomic file load (attacker can swap file between check and load)
2. Pickle/deserialization of files without integrity verification
3. Checkpoint restore that doesn't re-verify the file hasn't been modified

Return JSON only:
{{"findings": [{{"severity": "CRITICAL|HIGH|MEDIUM", "title": "title", "description": "technical detail of the race window", "attack_vector": "exact sequence: check→swap→load", "poc": "python poc code", "remediation": "fix"}}]}}
If no TOCTOU: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="RACE_CONDITION",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="RC-T2",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=f.get("poc"),
                        poc_explanation=None,
                        cvss_estimate="7.0 (High) — CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}RC-T2 error {rel}: {e}{RESET}")

    # ── RC-T3: Tool Invocation Race ────────────────────────────────────────

    def _t3_tool_invocation_race(self, files: list[str], repo_path: str):
        """Concurrent async tool calls racing for shared resource"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)

            has_async = any(re.search(p, code) for p in self.ASYNC_TOOL_PATTERNS)
            has_shared = any(re.search(p, code, re.I) for p in self.SHARED_STATE_PATTERNS)

            if has_async and has_shared:
                hits.append((rel, code[:2000]))

        if not hits:
            return

        for rel, code_snippet in hits[:5]:
            try:
                data = self._haiku(f"""Analyze this code for concurrent tool invocation race conditions in an agentic AI system.

FILE: {rel}
CODE: {code_snippet}

Look for: asyncio.gather() launching multiple agents that access the same resource without locking, concurrent tool calls that both read-modify-write shared state, non-atomic operations on shared agent memory.

Return JSON only:
{{"findings": [{{"severity": "HIGH|MEDIUM", "title": "title", "description": "what races", "attack_vector": "concurrent call sequence triggering race", "remediation": "fix"}}]}}
If no race: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="RACE_CONDITION",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="RC-T3",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=None,
                        poc_explanation=None,
                        cvss_estimate="6.8 (Medium)",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}RC-T3 error {rel}: {e}{RESET}")

    # ── RC-T4: Event Ordering Attack ───────────────────────────────────────

    def _t4_event_ordering(self, files: list[str], repo_path: str):
        """Non-deterministic event ordering exploitable by adversarial timing"""
        event_patterns = [
            r"on_event|event_handler|handle_event|dispatch\(",
            r"callback|on_complete|on_success|on_failure",
            r"queue\.put|queue\.get|deque\(",
            r"asyncio\.Queue|asyncio\.Event|asyncio\.Condition",
        ]

        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)
            if sum(1 for p in event_patterns if re.search(p, code)) >= 2:
                hits.append((rel, code[:2000]))

        if not hits:
            return

        for rel, code_snippet in hits[:4]:
            try:
                data = self._haiku(f"""Analyze this code for event ordering vulnerabilities in an agentic AI system.

FILE: {rel}
CODE: {code_snippet}

Look for: event handlers that assume ordering guarantees that don't exist, non-atomic state transitions observable between events, callbacks that can be triggered in adversarial order to corrupt agent state.

Return JSON only:
{{"findings": [{{"severity": "HIGH|MEDIUM|LOW", "title": "title", "description": "what ordering assumption is broken", "attack_vector": "how attacker exploits ordering", "remediation": "fix"}}]}}
If no ordering vulnerability: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="RACE_CONDITION",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="RC-T4",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=None,
                        poc_explanation=None,
                        cvss_estimate=None,
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}RC-T4 error: {e}{RESET}")

    # ── RC-T5: Session Fixation Race ───────────────────────────────────────

    def _t5_session_fixation_race(self, files: list[str], repo_path: str):
        """Race window between session creation and first use"""
        hits = []
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            rel = os.path.relpath(fp, repo_path)
            has_session = any(re.search(p, code, re.I) for p in self.SESSION_PATTERNS)
            has_async = "async def" in code or "asyncio" in code
            if has_session and has_async:
                hits.append((rel, code[:2000]))

        if not hits:
            return

        for rel, code_snippet in hits[:4]:
            try:
                data = self._haiku(f"""Analyze this code for session/token fixation race conditions.

FILE: {rel}
CODE: {code_snippet}

Look for: race window between token generation and token registration, predictable token generation that an attacker could guess and preemptively register, session stores that don't atomically create+register.

Return JSON only:
{{"findings": [{{"severity": "HIGH|MEDIUM", "title": "title", "description": "technical race window", "attack_vector": "attacker timing sequence", "remediation": "fix"}}]}}
If no session race: {{"findings": []}}""")

                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        id=self._fid(rel + f["title"]),
                        agent_id=self.AGENT_ID,
                        vuln_class="RACE_CONDITION",
                        severity=f["severity"],
                        title=f["title"],
                        file=rel,
                        technique="RC-T5",
                        description=f["description"],
                        attack_vector=f["attack_vector"],
                        poc=None,
                        poc_explanation=None,
                        cvss_estimate="7.5 (High)",
                        remediation=f.get("remediation")
                    ))
            except Exception as e:
                if self.verbose:
                    print(f"    {GRAY}RC-T5 error: {e}{RESET}")

    def _print_summary(self):
        crit = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        print(f"\n  {BOLD}RC-08 complete{RESET} — {len(self.findings)} findings | "
              f"\033[91m{crit} CRITICAL\033[0m | \033[93m{high} HIGH\033[0m")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, subprocess, tempfile, shutil

    p = argparse.ArgumentParser(description="RC-08 Race Condition Agent")
    p.add_argument("target", help="GitHub URL or local repo path")
    p.add_argument("-o", "--output", default="results/rc08/")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    repo_path = args.target
    tmp_dir = None

    if args.target.startswith("http"):
        tmp_dir = tempfile.mkdtemp(prefix="argus_rc_")
        repo_path = os.path.join(tmp_dir, "repo")
        print(f"Cloning {args.target}...")
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", args.target, repo_path],
            capture_output=True
        )
        if result.returncode != 0:
            print("Clone failed"); sys.exit(1)

    try:
        agent = RaceConditionAgent(verbose=args.verbose)
        findings = agent.run(args.target, repo_path, args.output)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
