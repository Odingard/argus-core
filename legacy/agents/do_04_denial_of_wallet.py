"""
agents/do_04_denial_of_wallet.py
DO-04 — Denial of Wallet Trapper

Hunts recursive multi-agent loops and unbounded context size exhaustion.

Techniques (3):
  DO-T1  INFINITE_DELEGATION — identify agents throwing loops at each other
  DO-T2  UNBOUNDED_CONTEXT   — agent memory without truncation limits
  DO-T3  RECURSIVE_TOOL_CALL — tools triggering an agent response recursively
"""
from __future__ import annotations

import json
import os
import re

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
GRAY  = "\033[90m"
RESET = "\033[0m"


class DenialOfWalletAgent(BaseAgent):
    AGENT_ID   = "DO-04"
    AGENT_NAME = "Denial of Wallet Trapper"
    VULN_CLASS = "UNBOUNDED_CONSUMPTION"
    TECHNIQUES = ["DO-T1", "DO-T2", "DO-T3"]
    MAAC_PHASES = [9]  # Impact (cost exhaustion)

    # Basic trigger keywords
    LOOP_PATTERNS = [
        r'handoff', r'transfer', r'delegate', r'.append\(', r'message_history'
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "DO-T1": self._t1_infinite_delegation,
            "DO-T2": self._t2_unbounded_context,
            "DO-T3": self._t3_recursive_tool,
        }

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        self._print_header(target)
        files = self._discover_files(repo_path)
        print(f"  Files     : {len(files)}\n")

        for tech_id, fn in self.technique_library.items():
            print(f"  {BLUE}[{tech_id}]{RESET} {fn.__doc__ or tech_id}")
            fn(files, repo_path)

        self.save_history(target, output_dir)
        self.save_findings(output_dir)
        print(f"\n  {BOLD}{self.AGENT_ID} complete{RESET} — {len(self.findings)} findings")
        return self.findings

    def _t1_infinite_delegation(self, files: list[str], repo_path: str):
        """Identify agents throwing infinite delegation loops at each other"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code: continue
            
            if not any(re.search(p, code, re.IGNORECASE) for p in self.LOOP_PATTERNS):
                continue
                
            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for Unbounded Consumption (Denial of Wallet) via Multi-Agent loops.
FILE: {rel}
CODE snippet: {code[:2000]}

Does this code allow an agent to continuously delegate back to another agent without a strict max_turn loop counter?
Return JSON only: {{"findings": [{{"severity": "HIGH", "title": "title", "description": "desc", "remediation": "fix"}}]}}""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(self._fid(rel+f["title"]), self.AGENT_ID, self.VULN_CLASS, f["severity"], f["title"], rel, "DO-T1", f["description"], "Trigger endless conversational delegation", None, None, None, f.get("remediation")))
            except (json.JSONDecodeError, KeyError, Exception) as e:
                if self.verbose:
                    print(f"  [DO-T1] {rel}: {type(e).__name__}: {e}")

    def _t2_unbounded_context(self, files: list[str], repo_path: str):
        """Agent memory arrays without token truncation limits"""
        context_patterns = [
            r'message_history', r'chat_history', r'conversation_memory',
            r'context_window', r'\.append\(.*message', r'messages\.append',
        ]
        truncation_patterns = [
            r'max_tokens', r'truncat', r'trim', r'limit.*len',
            r'\[:.*\]',  # slice notation suggesting truncation
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            has_context = any(
                re.search(p, code, re.IGNORECASE) for p in context_patterns
            )
            if not has_context:
                continue
            has_truncation = any(
                re.search(p, code, re.IGNORECASE) for p in truncation_patterns
            )
            if has_truncation:
                continue  # properly bounded
            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "unbounded_context"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Unbounded context growth in {rel}",
                rel, "DO-T2",
                "Message/context array grows without truncation or token limit. "
                "An attacker can exhaust memory/tokens by sending many messages.",
                "Send large volume of messages to exhaust context budget",
                None, None, None,
                "Add max_tokens or max_turns limit; truncate oldest messages.",
            ))

    def _t3_recursive_tool(self, files: list[str], repo_path: str):
        """Tools designed to trigger immediate re-execution infinitely"""
        recursive_patterns = [
            r'@tool[\s\S]{0,200}def \w+[\s\S]{0,500}(run_agent|execute|invoke)',
            r'tool_call[\s\S]{0,300}tool_call',
            r'while\s+True[\s\S]{0,300}(tool|agent|execute)',
        ]
        guard_patterns = [
            r'max_iter', r'max_recursi', r'depth.*limit', r'recursion_limit',
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            has_recursive = any(
                re.search(p, code, re.IGNORECASE | re.DOTALL)
                for p in recursive_patterns
            )
            if not has_recursive:
                continue
            has_guard = any(
                re.search(p, code, re.IGNORECASE) for p in guard_patterns
            )
            if has_guard:
                continue
            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "recursive_tool"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Recursive tool call without depth guard in {rel}",
                rel, "DO-T3",
                "A tool invocation can trigger agent re-execution without a "
                "recursion depth or iteration limit, enabling infinite loops.",
                "Trigger tool that re-invokes agent execution repeatedly",
                None, None, None,
                "Add max_iterations or recursion_limit guard before tool dispatch.",
            ))

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = DenialOfWalletAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
