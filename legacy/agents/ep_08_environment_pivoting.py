"""
agents/ep_08_environment_pivoting.py
EP-08 — Environment Pivoting Agent

Covers MAAC phase 8 (Environment Pivoting). Hunts the seams where a
compromised agent pivots from its own process into the surrounding
organization — OAuth tokens, cloud SDK credentials, browser sessions,
filesystem paths that escape their sandbox.

Techniques (4):
  EP-T1  UNSCOPED_OAUTH       — OAuth tokens stored with broad scope and reachable from tools
  EP-T2  CLOUD_CRED_EXPOSURE  — boto3/GCS/Azure clients with wide creds in tool execution scope
  EP-T3  BROWSER_SESSION      — automated browser with authenticated cookies exposed to agent
  EP-T4  FS_SANDBOX_ESCAPE    — tool filesystem access bypasses intended allowlist
"""
from __future__ import annotations

import os
import re

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
RESET = "\033[0m"


class EnvironmentPivotingAgent(BaseAgent):
    AGENT_ID   = "EP-08"
    AGENT_NAME = "Environment Pivoting Agent"
    VULN_CLASS = "ENVIRONMENT_PIVOT"
    TECHNIQUES = ["EP-T1", "EP-T2", "EP-T3", "EP-T4"]
    MAAC_PHASES = [8]  # Environment Pivoting
    PERSONA = "auditor"

    # Signals that this file is on an agent / tool execution path.
    TOOL_CONTEXT_PATTERNS = [
        r"@tool", r"class\s+\w*Tool\b", r"ToolRegistry",
        r"def\s+call_tool\b", r"def\s+execute_tool\b",
        r"\bagent\.run\b", r"\bagent\.execute\b",
        r"BaseAgent", r"BaseTool", r"FunctionTool",
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "EP-T1": self._t1_unscoped_oauth,
            "EP-T2": self._t2_cloud_credentials,
            "EP-T3": self._t3_browser_session,
            "EP-T4": self._t4_fs_sandbox_escape,
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

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _in_tool_context(self, code: str) -> bool:
        return any(re.search(p, code) for p in self.TOOL_CONTEXT_PATTERNS)

    # ── Techniques ──────────────────────────────────────────────────────────

    def _t1_unscoped_oauth(self, files: list[str], repo_path: str):
        """OAuth tokens with broad scope reachable from agent tool code"""
        oauth_patterns = [
            r"access_token", r"refresh_token", r"bearer[_\s]token",
            r"oauth\d?_?client", r"Oauth2Credentials",
            r"google_auth", r"googleapiclient\.discovery",
        ]
        scope_patterns = [
            r"scope\s*=\s*\[\s*['\"]\s*(?:\.\.|\*|all|full[_\s]access)",
            r"\.readonly['\"]\s*,\s*['\"][^'\"]*\.write",
            r"https://www\.googleapis\.com/auth/[a-z\.]+",  # Google broad scopes
            r"offline_access",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            has_oauth = any(re.search(p, code, re.IGNORECASE) for p in oauth_patterns)
            if not has_oauth:
                continue
            # Only care if the token is reachable from tool / agent code.
            if not self._in_tool_context(code):
                continue
            broad = any(re.search(p, code, re.IGNORECASE) for p in scope_patterns)
            if not broad:
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "ep_oauth"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"OAuth token with broad scope reachable from agent tool in {rel}",
                rel, "EP-T1",
                "An OAuth access / refresh token with broad scope (e.g. "
                "offline_access, multi-service Google scopes, wildcard) is "
                "held on an agent / tool execution path. A prompt-injected "
                "agent that invokes this tool inherits the full token, "
                "enabling lateral movement into every service the scope "
                "authorizes.",
                "Prompt injection -> authorized tool -> service abuse with "
                "organizational identity",
                None, None, None,
                "Minimize scopes to exactly what each tool needs. Keep tokens "
                "out of the agent's reachable process memory; proxy through a "
                "scoped microservice that enforces per-tool quotas.",
            ))

    def _t2_cloud_credentials(self, files: list[str], repo_path: str):
        """Cloud SDK clients initialized with wide creds inside tool scope"""
        cloud_patterns = [
            r"\bboto3\.(client|resource|Session)\(",
            r"google\.cloud\.",
            r"azure\.identity\.",
            r"azure\.storage\.",
            r"DefaultAzureCredential",
            r"aws_access_key_id",
            r"GOOGLE_APPLICATION_CREDENTIALS",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            if not any(re.search(p, code) for p in cloud_patterns):
                continue
            if not self._in_tool_context(code):
                continue

            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for MAAC Phase 8 (Environment Pivoting) — cloud credential exposure.

FILE: {rel}
CODE (up to 3000 chars):
{code[:3000]}

Question: does this code initialize a cloud SDK client (AWS boto3, GCP,
Azure) whose credentials would inherit organization-wide permissions,
and is that client reachable from an agent's tool invocation path? A
compromised agent calling that tool would pivot into the cloud
environment.

Only flag cases where:
  - Credentials are genuinely broad (default identity, admin role, no
    explicit scoping), and
  - The code path is reachable from tool execution (not just infra setup)

Return JSON ONLY:
{{"findings": [
  {{"severity": "CRITICAL|HIGH|MEDIUM",
    "title": "short title",
    "description": "describe the pivot path",
    "remediation": "specific fix"}}
]}}
If there's no real pivot, return {{"findings": []}}.""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        self._fid(rel + "ep_cloud_" + f["title"][:20]),
                        self.AGENT_ID, self.VULN_CLASS, f.get("severity", "HIGH"),
                        f.get("title", f"Cloud credential pivot in {rel}"),
                        rel, "EP-T2",
                        f.get("description", ""),
                        "Prompt injection -> tool call -> cloud SDK call with "
                        "organizational identity",
                        None, None, None,
                        f.get("remediation", "Constrain the tool's cloud "
                              "credentials to a minimum IAM role scoped to a "
                              "single bucket / project / resource group."),
                    ))
            except Exception:
                pass

    def _t3_browser_session(self, files: list[str], repo_path: str):
        """Automated browser with authenticated cookies exposed to agent"""
        browser_patterns = [
            r"playwright", r"selenium", r"puppeteer",
            r"browser_use", r"\.new_context\(", r"\.storage_state\b",
            r"cookies\.load\b",
        ]
        auth_context_patterns = [
            r"storage_state\s*=\s*['\"]",
            r"auth_state", r"logged_in", r"authenticated_session",
            r"cookies=\{.*session",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            if not any(re.search(p, code, re.IGNORECASE) for p in browser_patterns):
                continue
            if not any(re.search(p, code, re.IGNORECASE) for p in auth_context_patterns):
                continue
            if not self._in_tool_context(code):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "ep_browser"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Authenticated browser session reachable from agent tool in {rel}",
                rel, "EP-T3",
                "An automated browser (Playwright / Selenium / Puppeteer) is "
                "loaded with persisted authenticated state — session cookies, "
                "storage_state, or logged-in context — and placed on an agent "
                "tool execution path. A prompt-injected agent can drive the "
                "browser into any authenticated site with the user's identity.",
                "Prompt injection -> browser tool -> actions as authenticated "
                "user on third-party sites",
                None, None, None,
                "Strip long-lived session state from browser contexts used by "
                "agents. Require per-task re-authentication with human-visible "
                "consent, or proxy through a purpose-scoped API.",
            ))

    def _t4_fs_sandbox_escape(self, files: list[str], repo_path: str):
        """Tool filesystem access whose path is not constrained to a sandbox"""
        fs_ops = [
            r"open\(", r"Path\(.*\)\.read", r"Path\(.*\)\.write",
            r"shutil\.(copy|move|rmtree)", r"os\.remove\(",
            r"pathlib\.Path\(",
        ]
        # Signals the path came from agent / attacker input.
        taint_patterns = [
            r"tool_args\[", r"arguments\[", r"\bparams\[",
            r"\buser_path\b", r"\bfile_path\s*=\s*(?:args|params|request)",
        ]
        # Signals there IS a sandbox / allowlist check.
        sandbox_patterns = [
            r"resolve\(\)\.is_relative_to\(",
            r"\.resolve\(\)\.parts\b.*starts_?with",
            r"allowed_paths", r"allowlist", r"ALLOW.*DIR",
            r"chroot", r"os\.chroot",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._in_tool_context(code):
                continue
            if not any(re.search(p, code) for p in fs_ops):
                continue
            if not any(re.search(p, code) for p in taint_patterns):
                continue
            if any(re.search(p, code) for p in sandbox_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "ep_fs_escape"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Tool filesystem access without sandbox / allowlist in {rel}",
                rel, "EP-T4",
                "A tool opens or writes filesystem paths supplied by agent "
                "arguments without resolving and checking the path against an "
                "allowlist. An attacker who steers the agent (prompt "
                "injection, indirect tool feedback) can pivot into the host "
                "filesystem — reading secrets, overwriting config, placing "
                "persistence.",
                "Prompt injection supplies ../../../etc/... path to tool; "
                "tool reads or writes outside intended sandbox",
                None, None, None,
                "Resolve the path with Path.resolve() and verify "
                "is_relative_to(ALLOWED_ROOT) before any open/read/write. "
                "Reject symlinks. Run the tool in a filesystem sandbox.",
            ))


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = EnvironmentPivotingAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
