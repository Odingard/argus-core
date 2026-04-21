"""
agents/ea_12_excessive_agency.py
EA-12 — Excessive Agency Agent

Hunts over-permissioned agent tools, unrestricted shell access, and broad MCP schemas.

Techniques (3):
  EA-T1  UNRESTRICTED_SHELL — find tools allowing raw shell command execution
  EA-T2  BROAD_FS_ACCESS    — tools granting agent access outside a sandbox
  EA-T3  MCP_SCHEMA_POISON  — overly broad MCP schemas exposed to manipulation
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


class ExcessiveAgencyAgent(BaseAgent):
    AGENT_ID   = "EA-12"
    AGENT_NAME = "Excessive Agency Agent"
    VULN_CLASS = "EXCESSIVE_AGENCY"
    TECHNIQUES = ["EA-T1", "EA-T2", "EA-T3"]
    MAAC_PHASES = [5, 8]  # Tool Misuse + Environment Pivoting

    TOOL_PATTERNS = [
        r'@tool', r'def \w+.*shell', r'subprocess\.run', r'os\.system', r'eval\(', r'exec\('
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "EA-T1": self._t1_unrestricted_shell,
            "EA-T2": self._t2_broad_fs_access,
            "EA-T3": self._t3_mcp_schema,
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

    def _t1_unrestricted_shell(self, files: list[str], repo_path: str):
        """Find agent tools allowing raw shell command execution"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code: continue
            
            if not any(re.search(p, code, re.IGNORECASE) for p in self.TOOL_PATTERNS):
                continue
                
            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for Excessive Agency.
FILE: {rel}
CODE snippet: {code[:2000]}

Does this code expose an agent tool that allows LLMs to execute raw OS commands or python code without human verification?
Return JSON only: {{"findings": [{{"severity": "CRITICAL", "title": "title", "description": "desc", "remediation": "fix"}}]}}""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(self._fid(rel+f["title"]), self.AGENT_ID, self.VULN_CLASS, f["severity"], f["title"], rel, "EA-T1", f["description"], "Prompt injection -> tool call -> RCE", None, None, None, f.get("remediation")))
            except (json.JSONDecodeError, KeyError, Exception) as e:
                if self.verbose:
                    print(f"  [EA-T1] {rel}: {type(e).__name__}: {e}")

    def _t2_broad_fs_access(self, files: list[str], repo_path: str):
        """Find tools granting agent access outside a filesystem sandbox"""
        fs_patterns = [
            r'open\(', r'Path\(', r'os\.path', r'shutil\.',
            r'read_file', r'write_file', r'file_tool',
        ]
        sandbox_patterns = [
            r'sandbox', r'allowed_path', r'chroot', r'restrict',
            r'whitelist.*path', r'allowlist.*path',
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            # Must look like a tool definition with file access
            if not re.search(r'@tool', code, re.IGNORECASE):
                continue
            has_fs = any(
                re.search(p, code, re.IGNORECASE) for p in fs_patterns
            )
            if not has_fs:
                continue
            has_sandbox = any(
                re.search(p, code, re.IGNORECASE) for p in sandbox_patterns
            )
            if has_sandbox:
                continue  # has some sandboxing
            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "broad_fs_access"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Unsandboxed filesystem access in agent tool in {rel}",
                rel, "EA-T2",
                "An agent tool performs filesystem operations without path "
                "restriction or sandboxing. A prompt-injected agent could "
                "read/write arbitrary files.",
                "Prompt injection -> tool call -> arbitrary file read/write",
                None, None, None,
                "Restrict tool file access to an explicit allowlist of paths "
                "or a sandboxed directory.",
            ))

    def _t3_mcp_schema(self, files: list[str], repo_path: str):
        """Identify overly broad MCP schemas exposed to manipulation"""
        mcp_patterns = [
            r'mcp', r'tool_schema', r'function_call', r'tool_definition',
            r'register_tool', r'add_tool',
        ]
        validation_patterns = [
            r'json_?schema', r'validate', r'pydantic', r'TypedDict',
            r'required.*param', r'enum\b',
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            has_mcp = any(
                re.search(p, code, re.IGNORECASE) for p in mcp_patterns
            )
            if not has_mcp:
                continue
            has_validation = any(
                re.search(p, code, re.IGNORECASE) for p in validation_patterns
            )
            if has_validation:
                continue
            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "mcp_schema_broad"),
                self.AGENT_ID, self.VULN_CLASS, "MEDIUM",
                f"Overly broad MCP/tool schema without validation in {rel}",
                rel, "EA-T3",
                "Tool or MCP schema accepts arbitrary parameters without type "
                "validation or enum constraints. An attacker could manipulate "
                "tool parameters via prompt injection.",
                "Inject unexpected parameter values via crafted prompts",
                None, None, None,
                "Add JSON Schema validation, Pydantic models, or enum "
                "constraints to all tool parameter definitions.",
            ))

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = ExcessiveAgencyAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
