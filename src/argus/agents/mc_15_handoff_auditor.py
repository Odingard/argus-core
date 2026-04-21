"""
agents/mc_15_handoff_auditor.py
MC-15 — Handoff Auditor Agent

Critical failures in agentic systems rarely happen inside a single model
call; they happen at the SEAMS between stages — where a prompt becomes a
tool call, where one agent delegates to another, where an MCP server's
response enters the host's prompt, where a tool result gets re-used as
context. Catastrophic impact (System and Evolutionary boundaries in
MAAC) hides in those seams.

This agent explicitly audits four handoff classes:

  MC-T1  TOOL_BOUNDARY      — LLM output -> tool call path without schema-enforced gate
  MC-T2  AGENT_DELEGATION   — parent agent hands off to child without caller identity proof
  MC-T3  SERVER_TO_CLIENT   — MCP/tool-server response trusted into host prompt without sanitization
  MC-T4  TOOL_RESULT_REENTRY — tool output fed back into subsequent LLM call as if it were user input

MAAC phases covered: 2 (Prompt-Layer), 5 (Tool Misuse), 7 (Multi-Agent).
"""
from __future__ import annotations

import json
import os
import re

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
RESET = "\033[0m"


class HandoffAuditorAgent(BaseAgent):
    AGENT_ID   = "MC-15"
    AGENT_NAME = "Handoff Auditor Agent"
    VULN_CLASS = "HANDOFF_BOUNDARY"
    TECHNIQUES = ["MC-T1", "MC-T2", "MC-T3", "MC-T4"]
    MAAC_PHASES = [2, 5, 7]  # Prompt-Layer + Tool Misuse + Multi-Agent Escalation
    PERSONA = "chainer"

    # Does this file sit on an agent / tool dispatch path?
    DISPATCH_PATTERNS = [
        r"BaseAgent", r"class\s+\w*Agent\b",
        r"@tool", r"BaseTool", r"FunctionTool",
        r"call_tool", r"execute_tool", r"invoke_tool",
        r"\bmcp\b", r"ClientSession",
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "MC-T1": self._t1_tool_boundary,
            "MC-T2": self._t2_agent_delegation,
            "MC-T3": self._t3_server_to_client,
            "MC-T4": self._t4_tool_result_reentry,
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

    def _on_dispatch_path(self, code: str) -> bool:
        return any(re.search(p, code) for p in self.DISPATCH_PATTERNS)

    # ── Techniques ──────────────────────────────────────────────────────────

    def _t1_tool_boundary(self, files: list[str], repo_path: str):
        """LLM output -> tool call without schema-enforced gate"""
        # LLM produces tool-call candidates, host parses them, dispatches.
        parse_patterns = [
            r"json\.loads\(.*response",
            r"json\.loads\(.*completion",
            r"parse_tool_call\s*\(",
            r"extract_tool_call",
            r"tool_calls\s*=\s*.*response",
        ]
        # Host dispatches to a tool
        dispatch_patterns = [
            r"\.call\(\*\*tool_args\b",
            r"tool_registry\[",
            r"TOOLS\[tool_name\]",
            r"getattr\(tools,",
            r"globals\(\)\[tool_name\]",
        ]
        # Guard: enum / allowlist / schema validation before dispatch
        guard_patterns = [
            r"ALLOWED_TOOLS", r"tool_allowlist",
            r"if\s+tool_name\s+not\s+in\s+",
            r"pydantic\b.*tool", r"jsonschema\.validate",
            r"Literal\[",
            r"TypedDict",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._on_dispatch_path(code):
                continue
            if not any(re.search(p, code) for p in parse_patterns):
                continue
            if not any(re.search(p, code) for p in dispatch_patterns):
                continue
            if any(re.search(p, code) for p in guard_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "mc_tool_boundary"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"LLM-to-tool boundary lacks schema gate in {rel}",
                rel, "MC-T1",
                "The host parses tool-call candidates from model output and "
                "dispatches them through a dynamic tool map without a schema "
                "/ allowlist gate between parse and dispatch. A prompt-"
                "injected model can emit a tool name / argument shape the "
                "host dispatches faithfully — the exact seam MAAC describes "
                "as System-boundary breach.",
                "Prompt injection -> model emits arbitrary tool call -> "
                "host dispatches without boundary check",
                None, None, None,
                "Validate every LLM-produced tool call against a Pydantic / "
                "jsonschema model AND an explicit tool-name allowlist before "
                "dispatch. Reject unknown fields, unknown tool names, and "
                "arguments outside declared types.",
            ))

    def _t2_agent_delegation(self, files: list[str], repo_path: str):
        """Parent agent hands off to child without caller-identity proof"""
        handoff_patterns = [
            r"delegate_to\s*\(",
            r"handoff_to\s*\(",
            r"transfer_to_agent\s*\(",
            r"\.assign\s*\(",
            r"crew\.kickoff_for_each\s*\(",
        ]
        identity_patterns = [
            r"caller_identity", r"parent_token",
            r"signed_request", r"auth_context",
            r"verify_caller", r"jwt\.decode",
            r"hmac\.", r"parent_agent_signature",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._on_dispatch_path(code):
                continue
            if not any(re.search(p, code) for p in handoff_patterns):
                continue
            if any(re.search(p, code) for p in identity_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(
                    f"Analyze agent code for MAAC Phase 7 — AGENT DELEGATION HANDOFF.\n\n"
                    f"FILE: {rel}\nCODE (3000):\n{code[:3000]}\n\n"
                    "Question: does a PARENT agent hand off work to a CHILD / "
                    "sibling / specialist agent without the CHILD verifying the "
                    "caller's identity or authority? If the child trusts any "
                    "incoming task as originating from a legitimate parent, "
                    "an attacker who compromises any peer in the mesh can "
                    "impersonate the parent and task the child with anything.\n\n"
                    "Only flag concrete paths. If the child verifies caller "
                    "identity (JWT / HMAC / signed context), say there is no "
                    "finding.\n\n"
                    "Return JSON ONLY:\n"
                    '{"findings": [{"severity": "HIGH|CRITICAL", "title": "...", '
                    '"description": "...", "remediation": "..."}]}\n'
                    "Empty list if no real path."
                )
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        self._fid(rel + "mc_delegation_" + f["title"][:20]),
                        self.AGENT_ID, self.VULN_CLASS, f.get("severity", "HIGH"),
                        f.get("title", f"Unverified agent handoff in {rel}"),
                        rel, "MC-T2",
                        f.get("description", ""),
                        "Peer impersonates parent -> target child accepts and "
                        "executes with parent's implied authority",
                        None, None, None,
                        f.get("remediation", "Require signed / HMAC caller "
                              "identity on every handoff. Child verifies the "
                              "signature and the parent's declared scope "
                              "before accepting work."),
                    ))
            except (json.JSONDecodeError, KeyError, Exception) as e:
                if self.verbose:
                    print(f"  [MC-T2] {rel}: {type(e).__name__}: {e}")

    def _t3_server_to_client(self, files: list[str], repo_path: str):
        """MCP / tool-server response trusted into host prompt without sanitization"""
        server_response_patterns = [
            r"mcp.*result",
            r"tool_result\s*=",
            r"call_tool\s*\(.*\)\s*\.result",
            r"session\.call_tool\s*\(",
            r"response\.content\s*=.*tool",
        ]
        enters_prompt_patterns = [
            r"messages\.append\s*\(.*tool_result",
            r"messages\.append\s*\(.*response",
            r"prompt\s*\+=\s*tool_result",
            r"context\s*\+=\s*tool",
            r"system_prompt\s*=.*tool_result",
        ]
        sanitize_patterns = [
            r"sanitize", r"strip_hidden", r"normalize_unicode",
            r"html\.escape", r"delimit", r"<untrusted>",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._on_dispatch_path(code):
                continue
            if not any(re.search(p, code, re.IGNORECASE) for p in server_response_patterns):
                continue
            if not any(re.search(p, code) for p in enters_prompt_patterns):
                continue
            if any(re.search(p, code, re.IGNORECASE) for p in sanitize_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "mc_server_to_client"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"MCP / tool-server response enters host prompt unsanitized in {rel}",
                rel, "MC-T3",
                "Content returned by an MCP server or tool invocation is "
                "placed into the host LLM's message list without stripping "
                "hidden text, normalizing Unicode, or wrapping inside a "
                "structurally-delimited untrusted section. An adversary who "
                "controls any upstream server can embed instructions that "
                "the host model treats as authoritative.",
                "Compromise an upstream MCP server -> embed hidden directives "
                "in tool response -> host executes as system context",
                None, None, None,
                "Process every server / tool response through a sanitizer "
                "that strips hidden text, normalizes Unicode, and wraps "
                "content inside a clearly-marked untrusted block before the "
                "host LLM sees it. Never concatenate tool output into the "
                "system portion of the prompt.",
            ))

    def _t4_tool_result_reentry(self, files: list[str], repo_path: str):
        """Tool output re-fed into a subsequent LLM call as if it were user input"""
        # Signal that tool output is stored
        capture_patterns = [
            r"tool_output\s*=", r"result\s*=.*\.call\(",
            r"response\s*=.*invoke_tool",
            r"tool_history\.append",
        ]
        # Signal that it's later used as a USER-role input rather than tool-role
        misuse_patterns = [
            r'role\s*[:=]\s*["\']user["\'].*tool_output',
            r'role\s*[:=]\s*["\']user["\'].*result',
            r"user_message\s*=\s*tool",
            r"user_input\s*=\s*tool",
            r"messages\.append.*\{\s*['\"]role['\"]\s*:\s*['\"]user['\"].*tool",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._on_dispatch_path(code):
                continue
            if not any(re.search(p, code) for p in capture_patterns):
                continue
            if not any(re.search(p, code) for p in misuse_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "mc_result_reentry"),
                self.AGENT_ID, self.VULN_CLASS, "MEDIUM",
                f"Tool output re-enters LLM as user-role content in {rel}",
                rel, "MC-T4",
                "Tool output is re-injected into the conversation as a "
                "user-role message rather than a tool-role message. This "
                "erases the provenance boundary the model relies on to "
                "distinguish instructions it must follow (user) from "
                "evidence it should weigh (tool). An attacker poisoning "
                "tool output gets their content promoted to user-intent.",
                "Poison tool output -> host routes it as user message -> "
                "model follows embedded instructions",
                None, None, None,
                "Always re-inject tool results under role=tool (or an "
                "equivalent explicit tool-result content block). Never "
                "remap tool output to user-role content.",
            ))


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = HandoffAuditorAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
