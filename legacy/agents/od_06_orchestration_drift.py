"""
agents/od_06_orchestration_drift.py
OD-06 — Orchestration Drift Agent

Covers MAAC phase 6 (Orchestration Drift) — "subtly shifting task
decomposition to insert adversary-aligned sub-goals". The agent hunts
static signals that an agentic system's plan / goal / step pipeline can
be mutated between decomposition and execution without an integrity
check, allowing an attacker to redirect the workflow.

Techniques (3):
  OD-T1  PLAN_MUTATION          — plan state mutable after creation, no hash / signature
  OD-T2  GOAL_INJECTION         — untrusted input flows into goal decomposition
  OD-T3  STEP_EXECUTION_BYPASS  — executor doesn't verify plan integrity before running steps
"""
from __future__ import annotations

import os
import re

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
GRAY  = "\033[90m"
RESET = "\033[0m"


class OrchestrationDriftAgent(BaseAgent):
    AGENT_ID   = "OD-06"
    AGENT_NAME = "Orchestration Drift Agent"
    VULN_CLASS = "ORCHESTRATION_DRIFT"
    TECHNIQUES = ["OD-T1", "OD-T2", "OD-T3"]
    MAAC_PHASES = [6]  # Orchestration Drift
    PERSONA = "chainer"

    # Signals that code is doing planning / task decomposition at all.
    PLANNING_PATTERNS = [
        r"\bdecompose\b", r"\bplan_steps\b", r"\bbreak_down\b",
        r"\bsubtasks\b", r"\bsubgoals\b", r"\bsub_goals\b",
        r"\btask_plan\b", r"\bplan\.steps\b", r"\bgoal\.subgoals\b",
        r"class\s+\w*Planner\b", r"def\s+plan\b", r"\bTaskPlan\b",
        r"\bLangGraph\b", r"\bStateGraph\b", r"\bWorkflow\b",
    ]

    # Mutation signals on the plan itself.
    PLAN_MUTATION_PATTERNS = [
        r"self\.plan\s*=",
        r"plan\.steps\.(append|insert|extend|pop|remove|clear)",
        r"plan\.tasks\.(append|insert|extend|pop|remove|clear)",
        r"plan\.subgoals\.(append|insert|extend)",
        r"self\.steps\s*=",
        r"self\.goals\s*=",
        r"\.replace_step\(",  r"\.add_step\(",  r"\.remove_step\(",
    ]

    # Signals that plan integrity IS being verified — suppresses findings.
    INTEGRITY_PATTERNS = [
        r"hmac\.", r"hashlib\.", r"\.sign\(", r"\.verify\(",
        r"plan_hash", r"plan_signature", r"checksum",
        r"nacl\.", r"cryptography\.hazmat",
    ]

    # Inputs considered untrusted for goal-injection analysis.
    UNTRUSTED_INPUT_PATTERNS = [
        r"request\.(json|form|args|body|data)",
        r"\buser_input\b", r"\buser_message\b",
        r"\bmessages\[",
        r"websocket\.receive", r"stream\.read",
        r"llm_output", r"model_response",
        r"retrieved_(doc|content|context)",
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "OD-T1": self._t1_plan_mutation,
            "OD-T2": self._t2_goal_injection,
            "OD-T3": self._t3_step_execution_bypass,
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

    def _is_planning_code(self, code: str) -> bool:
        return any(re.search(p, code, re.IGNORECASE) for p in self.PLANNING_PATTERNS)

    def _has_integrity_check(self, code: str) -> bool:
        return any(re.search(p, code, re.IGNORECASE) for p in self.INTEGRITY_PATTERNS)

    # ── Techniques ──────────────────────────────────────────────────────────

    def _t1_plan_mutation(self, files: list[str], repo_path: str):
        """Detect plan/goal state mutable after creation without integrity check"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._is_planning_code(code):
                continue
            mutations = [p for p in self.PLAN_MUTATION_PATTERNS
                         if re.search(p, code)]
            if not mutations:
                continue
            if self._has_integrity_check(code):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "od_plan_mutation"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Agent plan is mutable post-creation without integrity check in {rel}",
                rel, "OD-T1",
                "The planner mutates plan state (steps, subgoals, tasks) after "
                "the plan has been constructed, and no hash / signature / HMAC "
                "is verified before execution. An adversary who can reach this "
                "mutation point — via prompt injection, indirect tool feedback, "
                "or a compromised sub-agent — can insert adversary-aligned "
                "sub-goals that the executor will faithfully carry out.",
                "Prompt injection or tool-output poisoning causes plan mutation, "
                "redirecting workflow to attacker goals",
                None, None, None,
                "Sign the plan (HMAC or similar) at decomposition time and "
                "verify the signature inside the executor before each step. "
                "Reject mutations that lack a fresh signature.",
            ))

    def _t2_goal_injection(self, files: list[str], repo_path: str):
        """Untrusted input flows into goal decomposition without sanitization"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._is_planning_code(code):
                continue

            # Evidence that untrusted input reaches planning in this file.
            untrusted_hits = [p for p in self.UNTRUSTED_INPUT_PATTERNS
                              if re.search(p, code)]
            if not untrusted_hits:
                continue

            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this agentic code for MAAC Phase 6 (Orchestration Drift).

FILE: {rel}
CODE (up to 3000 chars):
{code[:3000]}

Question: does untrusted input (user message, retrieved document, tool
output, LLM response) reach plan/goal decomposition in a way that lets
an adversary insert or replace sub-goals the executor will later run?
Require a CONCRETE path from untrusted source to planning call — do not
flag code that merely contains both. If the code validates/sanitizes the
untrusted input before it reaches planning, there is NO finding.

Return JSON ONLY:
{{"findings": [
  {{"severity": "HIGH|MEDIUM",
    "title": "short title",
    "description": "describe the source -> planning path with line refs",
    "remediation": "specific fix"}}
]}}
If no real path, return {{"findings": []}}.""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        self._fid(rel + "od_goal_injection_" + f["title"][:20]),
                        self.AGENT_ID, self.VULN_CLASS, f.get("severity", "MEDIUM"),
                        f.get("title", f"Goal injection path in {rel}"),
                        rel, "OD-T2",
                        f.get("description", ""),
                        "Untrusted input routed into plan decomposition "
                        "without validation gate",
                        None, None, None,
                        f.get("remediation", "Validate untrusted content against "
                              "an allowlist of goal templates before it can "
                              "influence plan decomposition."),
                    ))
            except Exception:
                # Haiku rejected or JSON malformed — skip, don't fabricate.
                pass

    def _t3_step_execution_bypass(self, files: list[str], repo_path: str):
        """Executor runs plan steps without verifying plan integrity"""
        exec_patterns = [
            r"def\s+execute_step\b", r"def\s+run_step\b",
            r"def\s+execute_plan\b", r"def\s+run_plan\b",
            r"for\s+step\s+in\s+.*plan",
            r"for\s+task\s+in\s+.*plan",
            r"for\s+goal\s+in\s+.*subgoals",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            if not any(re.search(p, code, re.IGNORECASE) for p in exec_patterns):
                continue
            # Executor exists in this file — does it verify plan integrity?
            if self._has_integrity_check(code):
                continue
            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "od_exec_bypass"),
                self.AGENT_ID, self.VULN_CLASS, "MEDIUM",
                f"Plan executor runs steps without integrity verification in {rel}",
                rel, "OD-T3",
                "An executor iterates over plan steps / subgoals / tasks and "
                "dispatches them without verifying that the plan it is running "
                "is the plan that was originally decomposed. Combined with a "
                "mutation point (see OD-T1), this allows adversary-injected "
                "steps to execute indistinguishably from legitimate ones.",
                "Inject a step into plan state; executor runs it without "
                "noticing",
                None, None, None,
                "Have the executor recompute and compare a plan hash/signature "
                "before each step, fed in from the original decomposition call.",
            ))


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = OrchestrationDriftAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
