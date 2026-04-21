"""
agents/pi_02_prompt_injection.py
PI-02 — Prompt Injection Agent

Covers MAAC phase 2 (Prompt-Layer Access). Hunts static code paths where
attacker-controlled text can reach the LLM call without structural
separation from system instructions — direct injections via user input,
indirect injections via retrieved content, and skill/manifest files
loaded from mutable locations without integrity verification.

Techniques (4):
  PI-T1  DIRECT_INPUT_TO_PROMPT  — raw user input concatenated into prompt
  PI-T2  INDIRECT_RAG_SINK       — retrieved/tool content reaches prompt unsanitized
  PI-T3  SKILL_FILE_UNSIGNED     — skills/manifests loaded without signature check
  PI-T4  SYSTEM_PROMPT_BLEND     — system and user content concatenated without delimiter
"""
from __future__ import annotations

import os
import re

from argus.agents.base import BaseAgent, AgentFinding

BOLD  = "\033[1m"
BLUE  = "\033[94m"
RESET = "\033[0m"


class PromptInjectionAgent(BaseAgent):
    AGENT_ID   = "PI-02"
    AGENT_NAME = "Prompt Injection Agent"
    VULN_CLASS = "PROMPT_INJECTION"
    TECHNIQUES = ["PI-T1", "PI-T2", "PI-T3", "PI-T4"]
    MAAC_PHASES = [2]  # Prompt-Layer Access
    PERSONA = "fuzzer"

    # Signals that code is constructing or dispatching a prompt.
    PROMPT_DISPATCH_PATTERNS = [
        r"messages\s*=\s*\[",
        r"messages\.append\(",
        r"\.chat\.completions\.create\(",
        r"\.messages\.create\(",
        r"generate_content\(",
        r"\bllm\.invoke\(",
        r"\bllm\.generate\(",
        r'role\s*[:=]\s*["\']system["\']',
        r'role\s*[:=]\s*["\']user["\']',
    ]

    # Untrusted sources.
    UNTRUSTED_DIRECT_PATTERNS = [
        r"request\.(json|form|args|body|data)",
        r"\bquery_params\b",
        r"\buser_input\b",
        r"\bprompt_arg\b",
    ]
    UNTRUSTED_INDIRECT_PATTERNS = [
        r"retriev(e|er|ed)_(docs?|content|context|chunks?)",
        r"\bknowledge_base\b.*\.search\(",
        r"\bvector(_|\.)store\b",
        r"\bfetch_url\b",
        r"requests\.(get|post)\(",
        r"\bbeautiful_?soup\b",
        r"\.read_text\(",
        r"\bopen\(.*\)\.read\(",
        r"mcp.*tool_description",
        r"tool_result",
    ]

    # Skill / manifest loading surface.
    SKILL_LOAD_PATTERNS = [
        r"load_skill", r"SkillRegistry", r"\.skills\[",
        r"yaml\.safe_load", r"yaml\.load",
        r"load_manifest", r"Manifest\.from_",
        r"load_prompt_template", r"PromptTemplate\.from_file",
    ]

    # Integrity signals that suppress findings.
    INTEGRITY_PATTERNS = [
        r"hmac\.", r"hashlib\.", r"\.sign\(", r"\.verify\(",
        r"signature", r"checksum", r"pgp", r"gpg_verify",
    ]

    # Delimiter / structural-separation signals.
    DELIMITER_PATTERNS = [
        r"<\|im_start\|>", r"<\|system\|>", r"\[INST\]",
        r"role\s*[:=]\s*['\"]system['\"]",
        r"structured_messages", r"ChatMessageTemplate",
    ]

    @property
    def technique_library(self) -> dict:
        return {
            "PI-T1": self._t1_direct_input,
            "PI-T2": self._t2_indirect_rag,
            "PI-T3": self._t3_skill_unsigned,
            "PI-T4": self._t4_system_user_blend,
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

    def _has_prompt_dispatch(self, code: str) -> bool:
        return any(re.search(p, code) for p in self.PROMPT_DISPATCH_PATTERNS)

    def _has_integrity(self, code: str) -> bool:
        return any(re.search(p, code, re.IGNORECASE) for p in self.INTEGRITY_PATTERNS)

    # ── Techniques ──────────────────────────────────────────────────────────

    def _t1_direct_input(self, files: list[str], repo_path: str):
        """Raw user input concatenated into prompt content"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._has_prompt_dispatch(code):
                continue
            if not any(re.search(p, code) for p in self.UNTRUSTED_DIRECT_PATTERNS):
                continue

            rel = os.path.relpath(fp, repo_path)
            try:
                data = self._haiku(f"""Analyze this code for MAAC Phase 2 (Prompt-Layer Access) — direct prompt injection.

FILE: {rel}
CODE (up to 3000 chars):
{code[:3000]}

Question: is untrusted user-controlled input (HTTP request body, query
params, named argument) concatenated into an LLM message WITHOUT an
input filter / guard model / structural escape? Require a concrete path
from the untrusted source to the outgoing prompt. Ignore code that
already validates or sanitizes the input.

Return JSON ONLY:
{{"findings": [
  {{"severity": "HIGH|MEDIUM",
    "title": "short title",
    "description": "describe source -> prompt path with references",
    "remediation": "specific fix"}}
]}}
If no real path, return {{"findings": []}}.""")
                for f in data.get("findings", []):
                    self._add_finding(AgentFinding(
                        self._fid(rel + "pi_direct_" + f["title"][:20]),
                        self.AGENT_ID, self.VULN_CLASS, f.get("severity", "MEDIUM"),
                        f.get("title", f"Direct prompt injection surface in {rel}"),
                        rel, "PI-T1",
                        f.get("description", ""),
                        "Crafted user input overrides system instructions",
                        None, None, None,
                        f.get("remediation", "Deploy a prompt-injection detector "
                              "on all untrusted input before it enters the LLM "
                              "context window; use structured messages with a "
                              "clear system/user boundary."),
                    ))
            except Exception:
                pass

    def _t2_indirect_rag(self, files: list[str], repo_path: str):
        """Retrieved or tool-returned content reaches prompt unsanitized"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._has_prompt_dispatch(code):
                continue
            if not any(re.search(p, code, re.IGNORECASE)
                       for p in self.UNTRUSTED_INDIRECT_PATTERNS):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "pi_indirect_rag"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"Indirect prompt injection sink — retrieved content reaches prompt in {rel}",
                rel, "PI-T2",
                "Content fetched from an external source (RAG retrieval, web "
                "fetch, file read, MCP tool result) is placed into the LLM's "
                "message list without sanitization or structural escaping. An "
                "attacker who controls any of those external sources can embed "
                "instructions (visible text, hidden Unicode, HTML comments) "
                "that the model will execute.",
                "Plant payload in retrieved source -> LLM executes embedded "
                "instructions",
                None, None, None,
                "Process retrieved content in a sandbox that strips hidden "
                "text, normalizes Unicode, and wraps content in a "
                "structurally-delimited 'untrusted' section before inclusion.",
            ))

    def _t3_skill_unsigned(self, files: list[str], repo_path: str):
        """Skill / manifest / prompt-template files loaded without integrity check"""
        for fp in files:
            code = self._read_file_safe(fp)
            if not code:
                continue
            if not any(re.search(p, code) for p in self.SKILL_LOAD_PATTERNS):
                continue
            if self._has_integrity(code):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "pi_skill_unsigned"),
                self.AGENT_ID, self.VULN_CLASS, "MEDIUM",
                f"Skill/manifest/prompt file loaded without signature verification in {rel}",
                rel, "PI-T3",
                "Skills, manifests, or prompt templates are loaded from disk "
                "(YAML / Markdown / JSON) and folded into the agent's system "
                "context without cryptographic integrity verification. An "
                "attacker with write access to the skill directory — via a "
                "supply-chain push, a compromised dev tool, or a malicious "
                "skill marketplace — can inject directives that persist across "
                "sessions.",
                "Modify skill file -> injected directives load as trusted "
                "system prompt",
                None, None, None,
                "Sign skill / manifest files and verify the signature on load. "
                "Pin versions by content hash. Reject unsigned skills in "
                "production.",
            ))

    def _t4_system_user_blend(self, files: list[str], repo_path: str):
        """System and user content concatenated into a single string without delimiter"""
        blend_patterns = [
            r"system_prompt\s*\+\s*user",
            r"system_prompt\s*\+\s*request",
            r"f\"[^\"]*\{system[^}]*\}[^\"]*\{user[^}]*\}",
            r"prompt\s*=\s*system_prompt\s*\+",
            r'"""[^"]*\{user_input\}[^"]*"""',
        ]
        for fp in files:
            code = self._read_file_safe(fp)
            if not code or not self._has_prompt_dispatch(code):
                continue
            if not any(re.search(p, code) for p in blend_patterns):
                continue
            if any(re.search(p, code) for p in self.DELIMITER_PATTERNS):
                continue

            rel = os.path.relpath(fp, repo_path)
            self._add_finding(AgentFinding(
                self._fid(rel + "pi_blend"),
                self.AGENT_ID, self.VULN_CLASS, "HIGH",
                f"System and user content concatenated without structural delimiter in {rel}",
                rel, "PI-T4",
                "The prompt is built by string concatenation of system and "
                "user sections without a structural separator (chat role, "
                "delimiter token, schema boundary). This lets a user message "
                "trivially close the system section and issue new directives.",
                "User message includes syntax that terminates the system "
                "section and injects new instructions",
                None, None, None,
                "Use the provider's structured messages API (role:system, "
                "role:user) or, for raw completion endpoints, insert "
                "unguessable random delimiter tokens around user content.",
            ))


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-o", "--output", default="results/")
    args = p.parse_args()
    agent = PromptInjectionAgent(verbose=True)
    agent.run(args.target, args.target, args.output)
