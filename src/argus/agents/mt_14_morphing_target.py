"""
agents/mt_14_morphing_target.py
MT-14 — Morphing Target Agent

Hunts transformation / self-modification patterns that snapshot-based
scanners miss. Agents that rewrite their own prompts, spawn sub-agents
past their authority, swap models mid-run, or feed their own output
back into their own memory are the open frontier of agentic AI attack
surface — and no competitor in the 7-project research currently hunts
them.

Techniques (4):
  MT-T1  SELF_MODIFYING_PROMPT — agent rewrites its own system prompt at runtime
  MT-T2  UNAUTHORIZED_SUBAGENT_SPAWN — parent spawns child without auth / budget cap
  MT-T3  MODEL_SWAP_ROUTING — routing logic lets attacker influence model selection
  MT-T4  MEMORY_FEEDBACK_LOOP — agent output gets ingested back into its own RAG

MAAC phases covered: 3 (Model-Layer Manipulation — model swap),
                     4 (Memory Corruption — feedback loop),
                     6 (Orchestration Drift — self-rewrite),
                     7 (Multi-Agent Escalation — spawn without gate).
"""
from __future__ import annotations

import json
import os
import re

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
RESET = "\033[0m"


class MorphingTargetAgent(BaseAgent):
    AGENT_ID   = "MT-14"
    AGENT_NAME = "Morphing Target Agent"
    VULN_CLASS = "MORPHING_TRANSFORMATION"
    TECHNIQUES = ["MT-T1", "MT-T2", "MT-T3", "MT-T4"]
    MAAC_PHASES = [3, 4, 6, 7]  # Model-Layer + Memory + Orchestration Drift + Multi-Agent
    PERSONA = "chainer"

    # Signals that code is AGENT code (not arbitrary business logic).
    AGENT_CONTEXT_PATTERNS = [
        r"BaseAgent", r"class\s+\w*Agent\b",
        r"system_prompt", r"SystemMessage",
        r"\bllm\.(invoke|generate|complete)\b",
        r"\.chat\.completions\.create\(",
        r"\.messages\.create\(",
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "MT-T1": self._t1_self_modifying_prompt,
            "MT-T2": self._t2_unauthorized_subagent_spawn,
            "MT-T3": self._t3_model_swap_routing,
            "MT-T4": self._t4_memory_feedback_loop,
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

    def _is_agent_code(self, code: str) -> bool:
        return any(re.search(p, code) for p in self.AGENT_CONTEXT_PATTERNS)

    # ── Techniques ──────────────────────────────────────────────────────────

    def _t1_self_modifying_prompt(self, files: list[str], repo_path: str):
        """Agent code that rewrites its own system prompt at runtime"""
        # Write patterns: assignment to an attribute that ALSO appears as a
        # prompt source. An agent that does `self.system_prompt = new_value`
        # mid-run (outside __init__) is a morphing target.
        self_write_patterns = [
            r"self\.system_prompt\s*=\s*[^=]",
            r"self\.instructions\s*=\s*[^=]",
            r"self\.persona\s*=\s*[^=]",
            r"self\.directives\s*=\s*[^=]",
            r"self\.\w*prompt\w*\s*=.*\+.*",   # += concat
            r"self\.messages\[0\]\s*=",         # overwriting the system msg
            r"self\.messages\[0\]\[.content.\]\s*=",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._is_agent_code(code):
                continue
            hits = [p for p in self_write_patterns if re.search(p, code)]
            if not hits:
                continue
            # Suppress the case where the write is guarded by a hash or signature check.
            if re.search(r"verify|hmac|signature|checksum", code, re.IGNORECASE):
                continue

            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(
                    f"Analyze agent code for MAAC Phase 6 / 3 — SELF-MODIFYING PROMPT.\n\n"
                    f"FILE: {rel}\nCODE (3000 chars):\n{code[:3000]}\n\n"
                    "Question: does this code MUTATE the agent's system prompt, "
                    "persona, or core directives AFTER initial construction, and "
                    "is that mutation reachable from untrusted input? Do NOT flag "
                    "code that only sets the prompt once in __init__. Flag only "
                    "runtime-reachable overwrites without signature/HMAC gate.\n\n"
                    "Return JSON ONLY:\n"
                    '{"findings": [{"severity": "HIGH|MEDIUM", "title": "...", '
                    '"description": "...", "remediation": "..."}]}\n'
                    "If no real path, return {\"findings\": []}."
                )
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        self._fid(rel + "mt_self_modifying_" + f["title"][:20]),
                        self.AGENT_ID, self.VULN_CLASS, f.get("severity", "HIGH"),
                        f.get("title", f"Self-modifying system prompt in {rel}"),
                        rel, "MT-T1",
                        f.get("description", ""),
                        "Prompt-injected input triggers self-rewrite; agent's "
                        "directives permanently mutated within the session",
                        None, None, None,
                        f.get("remediation", "Make the system prompt immutable "
                              "post-construction. If mutation is required, gate "
                              "it behind a signed / HMAC-verified update and "
                              "an explicit user consent step."),
                    ))
            except (json.JSONDecodeError, KeyError, Exception) as e:
                if self.verbose:
                    print(f"  [MT-T1] {rel}: {type(e).__name__}: {e}")

    def _t2_unauthorized_subagent_spawn(self, files: list[str], repo_path: str):
        """Parent agent spawns child without auth / budget cap / parent-context check"""
        spawn_patterns = [
            r"spawn_agent\s*\(",
            r"delegate_to\s*\(",
            r"create_sub(_?)agent\s*\(",
            r"new\s+\w*Agent\s*\(",
            r"crew\.kickoff\s*\(",          # CrewAI
            r"Agent\s*\([^)]*tools\s*=",    # direct Agent ctor with tools
            r"child_agent\s*=",
        ]
        auth_patterns = [
            r"authorize", r"permission", r"can_spawn",
            r"parent_authority", r"max_depth", r"max_children",
            r"spawn_budget", r"scope_check",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._is_agent_code(code):
                continue
            if not any(re.search(p, code, re.IGNORECASE) for p in spawn_patterns):
                continue
            if any(re.search(p, code, re.IGNORECASE) for p in auth_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "mt_spawn_no_gate"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Sub-agent spawn without authority / budget gate in {rel}",
                rel, "MT-T2",
                "Parent agent constructs and dispatches a sub-agent without "
                "checking parent authority, spawn depth, budget, or scope. "
                "A prompt-injected parent can spawn children with the parent's "
                "tools and credentials but without the parent's safety gates, "
                "since child creation bypasses whatever guardrails live on the "
                "parent's main execution path.",
                "Prompt injection to parent -> spawn malicious child with "
                "full parent tool set, no guardrails",
                None, None, None,
                "Add a spawn gate: parent must hold an explicit `can_spawn` "
                "capability, max_depth must be enforced, and child scope must "
                "be the intersection of parent scope and explicit sub-tool "
                "allowlist.",
            ))

    def _t3_model_swap_routing(self, files: list[str], repo_path: str):
        """Routing logic allows attacker to influence model selection"""
        routing_patterns = [
            r"model\s*=\s*(request|user|args|params|ctx)\.",
            r"model_name\s*=\s*(request|user|args|params)",
            r"route_to_model\s*\(",
            r"select_model\s*\(",
            r"llm_router",
            r"['\"]?model['\"]?\s*:\s*\w+\.get\(",
        ]
        # Guard patterns that SHOULD be present — allowlist, enum check.
        guard_patterns = [
            r"ALLOWED_MODELS", r"model_allowlist",
            r"if\s+model\s+not\s+in\s+",
            r"assert\s+model\s+in\s+",
            r"Literal\[['\"]claude-", r"Literal\[['\"]gpt-",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            if not any(re.search(p, code) for p in routing_patterns):
                continue
            if any(re.search(p, code) for p in guard_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "mt_model_swap"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Model routing uses untrusted input without allowlist in {rel}",
                rel, "MT-T3",
                "Model selection is influenced by untrusted caller input (HTTP "
                "request, user args, context) without a server-side allowlist. "
                "An attacker who controls input can force the host to route "
                "sensitive reasoning to a weaker, less-aligned, or "
                "attacker-controlled model — defeating multi-model consensus "
                "(MAAC §3 mitigation) and enabling capability downgrade.",
                "Craft request to force routing to a weaker / compromised "
                "model, then exploit the capability gap",
                None, None, None,
                "Decide model server-side from content policy, not caller "
                "input. If caller-configurable, enforce a hardcoded allowlist "
                "(enum / Literal type) and reject unknown values.",
            ))

    def _t4_memory_feedback_loop(self, files: list[str], repo_path: str):
        """Agent output gets ingested back into its own RAG store / memory"""
        # Write-to-memory patterns
        memory_write_patterns = [
            r"vector_?store\.(add|upsert|insert)",
            r"chromadb\.(add|upsert)",
            r"\.embed_and_store\(",
            r"memory\.(add|append|store)",
            r"knowledge_base\.add",
        ]
        # Signals the value being stored is agent-produced output, not user-audited content
        agent_output_patterns = [
            r"\.add\(.*(response|output|generated|completion|agent_output)",
            r"\.upsert\(.*(response|output|generated|completion|agent_output)",
            r"embed\(.*(response|output|generated|completion)",
            r"llm_output", r"agent_output", r"self\.last_response",
        ]
        # Curation / human-in-loop guard
        curation_patterns = [
            r"human_review", r"approved", r"curated",
            r"moderation", r"content_filter",
            r"quarantine", r"review_queue",
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._is_agent_code(code):
                continue
            if not any(re.search(p, code, re.IGNORECASE) for p in memory_write_patterns):
                continue
            if not any(re.search(p, code, re.IGNORECASE) for p in agent_output_patterns):
                continue
            if any(re.search(p, code, re.IGNORECASE) for p in curation_patterns):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "mt_feedback_loop"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Agent-output-to-own-memory feedback loop in {rel}",
                rel, "MT-T4",
                "Agent writes its own responses / completions into its own "
                "vector store / memory WITHOUT human curation or moderation. "
                "A single successful prompt injection that produces a poisoned "
                "response is permanently ingested as retrievable context for "
                "future runs — the agent progressively trains itself on its "
                "own compromised output. Runaway amplification of a single "
                "seed.",
                "Inject once -> poisoned output stored in RAG -> future "
                "retrievals poison future completions -> escalation",
                None, None, None,
                "Never write raw agent output back to its own memory store. "
                "Require human review / moderation before ingestion, or sign "
                "ingested entries with a verifiable source tag and filter "
                "retrieval by that tag.",
            ))


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = MorphingTargetAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
