#!/usr/bin/env python3
"""
Agentic Infrastructure Zero-Day Scanner v2
Standalone research tool

Changes from v1:
  - Fix 1: PoC failures are loud — separate except blocks per error type
  - Fix 2: Example/demo files tagged and separated in output
  - Fix 3: Chain synthesis pass — connects findings into attack chains
  - Fix 4: Severity escalation — framework AUTH_BYPASS upgraded to CRITICAL
  - Fix 5: Structured report (chains / production_findings / example_findings)
  - Fix 6: TRUST_ESCALATION-specific PoC prompt (multi-turn injection aware)
  - Fix 7: PoC max_tokens raised 2048 → 4096 (was silently truncating PoCs)
  - Fix 8: Robust JSON fence stripper handles ```json, ``` etc.

Usage:
  python scanner.py <github_url>
  python scanner.py <github_url> -o report.json
  python scanner.py <github_url> --skip-poc --verbose
  python scanner.py <github_url> --skip-chains
"""

from argus.shared.client import ArgusClient
import anthropic
import subprocess
import tempfile
import os
import json
import argparse
import hashlib
import shutil
import threading
import queue
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional

# ─── ANSI Color Codes ────────────────────────────────────────────────────────
class C:
    RESET   = "[0m"
    BOLD    = "[1m"
    DIM     = "[2m"
    RED     = "[91m"    # CRITICAL
    ORANGE  = "[33m"    # HIGH
    YELLOW  = "[93m"    # MEDIUM
    GREEN   = "[92m"    # LOW / success
    CYAN    = "[96m"    # info / file names
    BLUE    = "[94m"    # PHANTOM_MEMORY
    MAGENTA = "[95m"    # MESH_TRUST
    TEAL    = "[36m"    # TRACE_LATERAL
    WHITE   = "[97m"    # banner
    GRAY    = "[90m"    # dim labels

SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.ORANGE,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
}

CLASS_COLOR = {
    "MESH_TRUST":      C.MAGENTA,
    "PHANTOM_MEMORY":  C.BLUE,
    "TRACE_LATERAL":   C.TEAL,
    "TRUST_ESCALATION":C.ORANGE,
    "SSRF":            C.CYAN,
    "AUTH_BYPASS":     C.RED,
    "DESER":           C.YELLOW,
    "MEM_NAMESPACE_LEAK": C.BLUE,
}

def c(color: str, text: str) -> str:
    """Wrap text in color code + reset."""
    return f"{color}{text}{C.RESET}"

# ─── Config ──────────────────────────────────────────────────────────────────
# ── Model configuration ─────────────────────────────────────────────────────
# Two-model approach: Haiku for analysis (cheap, fast), Opus for PoC (powerful)
# Cost comparison on 2000-file repo:
#   Single Opus  : ~$100    Full Haiku+Opus : ~$10
#   Analysis only: ~$6      PoC generation  : ~$4
from argus.shared.prompts import L2_MODEL as ANALYSIS_MODEL, L5_MODEL as POC_MODEL
PARALLEL_WORKERS = 4    # concurrent file analysis threads — tune for your machine
                        # M1 Pro: 4-5 is optimal. Raise if API rate limits allow.

# Legacy alias — used in banner display
MODEL = POC_MODEL
CHUNK_SIZE      = 12_000
MAX_FILE_SIZE   = 200_000   # raised from 80KB — was skipping core source files
POC_THRESHOLD   = {"CRITICAL", "HIGH"}
POC_MAX_TOKENS  = 4096      # Fix 7: was 2048

RELEVANT_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".java", ".rb", ".php"
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "dist", "build",
    "vendor", ".venv", "venv", "env", ".env", "coverage",
    "migrations", "fixtures", "static", "assets", "docs",
}

# Fix 2: example file detection
EXAMPLE_DIRS = {
    "example", "examples", "demo", "demos",
    "sample", "samples", "tutorial", "tutorials"
}

# Fix 4: framework file patterns — AUTH_BYPASS here → CRITICAL
FRAMEWORK_PATTERNS = [
    "server.", "client.", "transport.", "middleware.",
    "auth.", "router.", "app.", "main.", "index.",
    "FastMCP", "ToolUser", "Agent", "Orchestrat",
]

# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    id:              str
    vuln_class:      str
    severity:        str
    title:           str
    file:            str
    line_hint:       str
    description:     str
    code_snippet:    str
    attack_vector:   str
    is_example:      bool = False
    poc:             Optional[str] = None
    poc_explanation: Optional[str] = None
    cvss_estimate:   Optional[str] = None
    remediation:     Optional[str] = None

@dataclass
class AttackChain:
    ids:             list
    title:           str
    description:     str
    combined_impact: str
    severity:        str

@dataclass
class ScanReport:
    target:                str
    scanner_version:       str
    total_files_analyzed:  int
    total_findings:        int
    critical_count:        int
    high_count:            int
    medium_count:          int
    low_count:             int
    chains:                list = field(default_factory=list)
    production_findings:   list = field(default_factory=list)
    example_findings:      list = field(default_factory=list)

# ─── Prompts ─────────────────────────────────────────────────────────────────

ANALYSIS_PROMPT = """\
You are a senior offensive security researcher specializing in agentic AI systems.
Analyze the code below for these vulnerability classes ONLY. Be precise — flag concrete
exploitable patterns, not theoretical concerns.

# ── TRADITIONAL CLASSES (MCP server layer) ────────────────────────────────────

SSRF
  User-controlled input flowing into outbound HTTP/network requests inside MCP tool handlers,
  agent tool implementations, LLM orchestration code, or RAG fetchers. Flag any location where
  a tool call parameter, user message, or agent output reaches requests.get/post, httpx, fetch,
  urllib, aiohttp, or similar without hostname validation. Include LLM-mediated SSRF: prompt
  injection causing the LLM to request attacker-controlled URLs through the tool.

DESER
  Unsafe deserialization of untrusted data: pickle.loads, yaml.load (non-SafeLoader), eval(),
  exec(), marshal.loads, jsonpickle.decode, or similar in agent state persistence, tool result
  handling, memory stores, or checkpoint loading.

AUTH_BYPASS
  Missing or trivially bypassable authentication/authorization before privileged operations:
  tool execution, agent spawning, memory writes, admin endpoints, or external API calls where
  the caller identity is never verified or can be spoofed. Include framework-level bypasses
  where developer-configured auth is silently not enforced on certain code paths, and hardcoded
  credentials that grant privileged access.

MEM_NAMESPACE_LEAK
  Cross-user or cross-tenant data exposure in vector stores, RAG pipelines, agent scratchpads,
  or session memory: missing namespace isolation, shared collection without tenant filtering,
  or session IDs that can be predicted or collided.

# ── TRIDENT CLASSES (agentic AI-specific, novel attack surface) ───────────────

MESH_TRUST
  Agent-to-agent trust exploitation — the MESH pillar of TRIDENT:
  - An orchestrator agent delegates tasks to sub-agents without cryptographic identity verification
  - Sub-agent accepts instructions from any caller claiming to be the orchestrator (no token/signature check)
  - Agent impersonation: attacker injects messages into the inter-agent bus that are indistinguishable from legitimate orchestrator commands
  - Implicit trust in agent role names, header values, or message metadata without verification
  - Tool calls routed between agents without re-authorization at each hop
  - Delegation chains where permission scope expands rather than contracts at each step
  Look for: agent message parsing without sender verification, role-based trust without cryptographic proof,
  inter-agent APIs that accept identity claims in plaintext, orchestrator patterns that spawn sub-agents and pass context without signing it.

PHANTOM_MEMORY
  AI memory persistence attacks — the PHANTOM pillar of TRIDENT:
  - Vector store / embedding database writes that accept user-controlled content without sanitization,
    enabling persistent prompt injection across sessions (poisoned memories retrieved in future turns)
  - Cross-session context leakage: one user's conversation history, retrieved memories, or scratchpad
    content accessible or influencing another user's agent session
  - Memory-based privilege escalation: content written to memory in a low-privilege context is later
    retrieved and acted on in a high-privilege context without re-authorization
  - Scratchpad or working memory that persists tool results without filtering for adversarial content
  - RAG pipelines that embed and retrieve external content without isolation between tenants/users
  Look for: vector DB upsert/insert calls with user-controlled content, shared embedding collections
  across users, memory retrieval that feeds directly into LLM context without sandboxing,
  agent scratchpads written from tool outputs without adversarial content filtering.

TRACE_LATERAL
  Agentic lateral movement via tool chain pivoting — the TRACE pillar of TRIDENT:
  - Tool output from one tool is passed as input to another tool without re-authorization or sanitization,
    allowing an attacker who controls tool A's output to influence tool B's execution
  - Sub-agent spawning chains: an agent spawns child agents that inherit parent permissions
    without scope reduction, enabling privilege amplification through recursive delegation
  - API traversal: agent's tool access graph allows reaching privileged APIs by chaining
    multiple low-privilege tool calls (A→B→C where C is privileged but A is not)
  - Behavioral signature evasion: agent takes the same action via multiple indirect tool paths
    to avoid detection/rate-limiting on the direct path
  - Tool result injection: attacker-controlled external content (web page, file, API response)
    contains instructions that cause the agent to invoke additional tools
  Look for: tool result passed directly to another tool call without validation, agent spawning
  with permission inheritance, tool chains where intermediate results are trusted as instructions,
  external content (fetched URLs, files, emails) processed by agents that then take tool actions.

TRUST_ESCALATION
  An agent or tool acquiring elevated permissions without re-validation:
  - LLM output parsed and executed as privileged commands without authorization gate
  - Tool results fed back as trusted context enabling further tool invocations
  - Permission context flowing through delegation chains without re-checking
  - Session roles set once and never re-validated against an authoritative source

FILE: {filename}

CODE:
```
{code}
```

Return ONLY valid JSON with no markdown fences:
{{
  "findings": [
    {{
      "vuln_class":    "SSRF|DESER|AUTH_BYPASS|MEM_NAMESPACE_LEAK|MESH_TRUST|PHANTOM_MEMORY|TRACE_LATERAL|TRUST_ESCALATION",
      "severity":      "CRITICAL|HIGH|MEDIUM|LOW",
      "title":         "concise technical title (max 80 chars)",
      "line_hint":     "function name or approximate line numbers",
      "description":   "precise technical description of what is vulnerable and why",
      "code_snippet":  "the specific vulnerable code (max 10 lines)",
      "attack_vector": "numbered steps from first attacker contact to impact"
    }}
  ]
}}

If no findings: {{"findings": []}}
No preamble, explanation, or markdown around the JSON.\
"""


# ── PoC reproducibility contract ──────────────────────────────────────────────
# Every PoC we emit must be reproducible against the SHIPPING library, not a
# stub recreation of it. Triagers reject "theoretical" PoCs that redefine the
# vulnerable class inside the PoC itself (we learned this the hard way: 22
# CRITICAL findings closed as "not reproducible" on 2026-04-20).
#
# Contract, enforced in every prompt below:
#   1. Import the real vulnerable symbol from its real module path derived
#      from the file path — e.g. src/crewai/agents/base.py →
#      `from crewai.agents.base import ...`. NEVER redeclare the class.
#   2. Exercise the real vulnerable code path with attacker input.
#   3. Print `ARGUS_POC_LANDED:<title-slug>` on successful exploitation so
#      the L7 sandbox can confirm reproducibility automatically.
#   4. Non-destructive — use file markers like /tmp/argus_poc_<slug> or
#      stdout, never `rm`, network exfil to real hosts, or DB writes.
#   5. Must `sys.exit(1)` if the vulnerable path was not reached, so
#      import errors, renamed symbols, or patched versions fail loudly.

POC_PROMPT_STANDARD = """\
You are a security researcher generating a REPRODUCIBLE proof-of-concept for
responsible disclosure. Triagers reject theoretical PoCs; yours must exploit
the REAL shipping library, not a stub recreation of it.

Vulnerability Title: {title}
Class:               {vuln_class}
File:                {file}
Location:            {line_hint}
Description:         {description}
Attack Vector:       {attack_vector}

Vulnerable Code:
```
{code_snippet}
```

HARD REQUIREMENTS (rejecting any PoC that violates these):
1. Import from the INSTALLED package namespace — use the names in
   TARGET_PACKAGES below, NOT the on-disk directory layout. If the
   file is `src/<pkg>/<a>/<b>.py` the correct import is
   `from <pkg>.<a>.<b> import <Symbol>` (the `src/` prefix is NOT part
   of the import path after pip install -e .). NEVER redefine the
   class inside the PoC.
2. Actually CALL the imported symbol with attacker-controlled input.
   A PoC that imports but never references the imported name is
   statically rejected by the ARGUS gate before the sandbox runs.
3. On successful exploitation print exactly this marker on its own line:
       ARGUS_POC_LANDED:{title_slug}
   Use a filesystem side-effect as evidence (e.g. write a marker file to
   /tmp/argus_poc_{title_slug} then read it back and print the marker).
4. If the vulnerable path was NOT reached (ImportError, AttributeError,
   patched version, guard clause rejected input), call sys.exit(1) with
   the reason. Silent success on a patched library is worse than a crash.
5. Non-destructive. No rm, no network traffic to real hosts, no DB writes.
   Only the /tmp marker and stdout.

TARGET_PACKAGES (exact import namespaces available after install):
{target_packages}

Return ONLY valid JSON with no markdown fences:
{{
  "poc_code":        "complete PoC as a single string, \\n for newlines",
  "poc_explanation": "what code path runs, what evidence proves it, what attacker gains",
  "cvss_estimate":   "score (severity) — CVSS vector string and brief justification",
  "remediation":     "specific actionable fix for this vulnerability"
}}\
"""


# Fix 6: TRUST_ESCALATION-specific prompt — same reproducibility contract.
POC_PROMPT_TRUST = """\
You are a security researcher generating a REPRODUCIBLE proof-of-concept for
a TRUST_ESCALATION finding in an agentic AI system. Triagers reject
theoretical PoCs; yours must exploit the REAL shipping library.

Vulnerability Title: {title}
File:                {file}
Location:            {line_hint}
Description:         {description}
Attack Vector:       {attack_vector}

Vulnerable Code:
```
{code_snippet}
```

HARD REQUIREMENTS (rejecting any PoC that violates these):
1. Import the real agent / orchestrator / tool classes from the INSTALLED
   package namespace listed in TARGET_PACKAGES below — NOT the on-disk
   directory layout. NEVER recreate them inside the PoC.
2. Actually CALL an imported symbol — the static gate rejects
   import-and-print PoCs that never reference the import.
3. It is OK to stub the LLM response (a fixed string is fine) because the
   vulnerability is in the ROUTING of that string into privileged
   execution, not in the LLM itself. But the routing code must be the
   shipping library's code, not your recreation of it.
4. Show: attacker input → library's own dispatch path → privileged call
   with attacker-controlled argument. Print exactly this marker on its
   own line on success:
       ARGUS_POC_LANDED:{title_slug}
5. Use a /tmp/argus_poc_{title_slug} filesystem marker as evidence.
6. If the escalation path doesn't reach the privileged sink
   (authorization gate exists, input validated, dispatch refused),
   sys.exit(1) with the reason. Never stub past a guard.
7. Non-destructive — no rm, no real network, no DB writes.

TARGET_PACKAGES (exact import namespaces available after install):
{target_packages}

Return ONLY valid JSON with no markdown fences:
{{
  "poc_code":        "complete PoC as a single string, \\n for newlines",
  "poc_explanation": "step-by-step: attacker input → library dispatch → privileged sink → attacker gain",
  "cvss_estimate":   "score (severity) — CVSS vector and justification, note scope if agents cross boundaries",
  "remediation":     "where to add the authorization gate, what to validate, how to constrain execution"
}}\
"""


CHAIN_SYNTHESIS_PROMPT = """\
You are an offensive security researcher. Given these vulnerability findings, list attack chains where one finding enables another.

FINDINGS:
{findings_summary}

Rules: Cross-file chains are valid. Only include chains where A causally enables B.

Respond ONLY with this JSON (no markdown, no explanation):
{{"chains":[{{"ids":["id1","id2"],"title":"A enables B","impact":"what attacker gets","sev":"CRITICAL"}}]}}

Use "sev" not "severity". Keep title and impact under 50 chars each. Max 5 chains.
If no chains: {{"chains":[]}}\
"""


# ─── Helpers ─────────────────────────────────────────────────────────────────

def strip_fences(raw: str) -> str:
    """Fix 8: remove all markdown fence variants."""
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        raw = "\n".join(lines[start:end]).strip()
    return raw

def is_example_file(filepath: str) -> bool:
    """Fix 2: detect example/demo/sample files by directory name."""
    return any(p.lower() in EXAMPLE_DIRS for p in Path(filepath).parts)

def is_framework_file(filepath: str) -> bool:
    """Fix 4: detect framework-level files for severity escalation."""
    name = Path(filepath).name
    return any(pat.lower() in name.lower() for pat in FRAMEWORK_PATTERNS)

def escalate_severity(finding: Finding) -> Finding:
    """Fix 4: AUTH_BYPASS in framework files → CRITICAL."""
    if (finding.vuln_class == "AUTH_BYPASS"
            and finding.severity == "HIGH"
            and not finding.is_example
            and is_framework_file(finding.file)):
        finding.severity = "CRITICAL"
    return finding

# ─── Repo Handling ────────────────────────────────────────────────────────────

def clone_repo(url: str, dest: str, verbose: bool = False) -> bool:
    import zipfile
    import urllib.request
    from urllib.error import URLError
    
    # Try fetching as a zip to bypass git-lfs missing dependencies entirely
    try:
        if url.endswith(".git"):
            url = url[:-4]
        zip_url = f"{url}/archive/refs/heads/main.zip"
        
        try:
            temp_zip = os.path.join(tempfile.gettempdir(), "repo_download.zip")
            urllib.request.urlretrieve(zip_url, temp_zip)
        except URLError:
            # Fallback for master branch if main doesn't exist
            zip_url = f"{url}/archive/refs/heads/master.zip"
            urllib.request.urlretrieve(zip_url, temp_zip)
            
        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
            # Extract to temporary directory first
            temp_ext = os.path.join(tempfile.gettempdir(), "repo_extract")
            zip_ref.extractall(temp_ext)
            
            # Find the top level directory created inside the zip
            extracted_roots = os.listdir(temp_ext)
            if extracted_roots:
                top_dir = os.path.join(temp_ext, extracted_roots[0])
                # Move contents to final dest directory
                shutil.copytree(top_dir, dest, dirs_exist_ok=True)
                
            shutil.rmtree(temp_ext, ignore_errors=True)
            
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        return True
        
    except Exception as e:
        if verbose:
            print(f"    Zip Download Failed: {e}")
        return False

def discover_files(repo_dir: str, verbose: bool = False) -> list[str]:
    files = []
    for root, dirs, filenames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if Path(name).suffix in RELEVANT_EXT:
                fp = os.path.join(root, name)
                size = os.path.getsize(fp)
                if 100 < size < MAX_FILE_SIZE:
                    files.append(fp)
                elif size >= MAX_FILE_SIZE and size < 500_000:
                    # Large but not huge — include it, chunker will handle it
                    files.append(fp)
                    if verbose:
                        print(f"    large file (will chunk): {os.path.relpath(fp, repo_dir)}")
                elif verbose and size >= 500_000:
                    print(f"    skipped (too large >500KB): {os.path.relpath(fp, repo_dir)}")
    return sorted(files)

# ─── Analysis ────────────────────────────────────────────────────────────────

def chunk_code(code: str) -> list[str]:
    if len(code) <= CHUNK_SIZE:
        return [code]
    chunks, current, size = [], [], 0
    for line in code.split("\n"):
        lsize = len(line) + 1
        if size + lsize > CHUNK_SIZE and current:
            chunks.append("\n".join(current))
            current = current[-10:]
            size = sum(len(l) + 1 for l in current)
        current.append(line)
        size += lsize
    if current:
        chunks.append("\n".join(current))
    return chunks


def analyze_file(filepath: str, repo_dir: str, client: ArgusClient, verbose: bool = False) -> list[Finding]:
    try:
        code = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    rel     = os.path.relpath(filepath, repo_dir)
    example = is_example_file(filepath)
    chunks  = chunk_code(code)
    out     = []

    for idx, chunk in enumerate(chunks):
        label  = f"{rel} [{idx+1}/{len(chunks)}]" if len(chunks) > 1 else rel
        prompt = ANALYSIS_PROMPT.format(filename=label, code=chunk)
        resp   = None

        try:
            resp = client.messages.create(
                model=ANALYSIS_MODEL, max_tokens=3072,
                messages=[{"role": "user", "content": prompt}]
            )
            raw  = strip_fences(resp.content[0].text)
            data = json.loads(raw)

            for f in data.get("findings", []):
                fid = hashlib.md5(
                    f"{rel}|{f.get('line_hint','')}|{f.get('title','')}".encode()
                ).hexdigest()[:8]
                finding = Finding(
                    id=fid,
                    vuln_class=f.get("vuln_class", "UNKNOWN"),
                    severity=f.get("severity", "MEDIUM"),
                    title=f.get("title", "Untitled"),
                    file=rel, line_hint=f.get("line_hint", ""),
                    description=f.get("description", ""),
                    code_snippet=f.get("code_snippet", ""),
                    attack_vector=f.get("attack_vector", ""),
                    is_example=example,
                )
                finding = escalate_severity(finding)
                out.append(finding)

        # Fix 1: loud specific errors
        except json.JSONDecodeError as e:
            if verbose:
                raw_text = resp.content[0].text[:300] if resp else "no response"
                print(f"\n    [!] JSON parse error on {label}: {e}")
                print(f"    [!] Raw: {raw_text}")
        except Exception as e:
            if verbose:
                print(f"\n    [!] API/Processing error on {label}: {e}")
                print(f"\n    [!] Error on {label}: {type(e).__name__}: {e}")

    return out


def _title_slug(title: str) -> str:
    """Stable ASCII slug used in ARGUS_POC_LANDED markers."""
    import re as _re
    slug = _re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
    return (slug[:48] or "finding")


def generate_poc(finding: Finding, client: ArgusClient, verbose: bool = False,
                 repo_path: Optional[str] = None) -> Finding:
    """Fix 1 + 6 + 7 + real-library reproducibility + target-package injection."""
    TRIDENT_VULN_CLASSES = {"TRUST_ESCALATION", "MESH_TRUST", "PHANTOM_MEMORY", "TRACE_LATERAL"}
    # Resolve installed-package names so Opus writes correct imports.
    tpkgs: list[str] = []
    if repo_path:
        try:
            from argus.layer7.sandbox import target_packages as _tp
            tpkgs = _tp(repo_path) or []
        except Exception:
            pass
    tpkg_line = ", ".join(tpkgs) if tpkgs else "(none resolved — derive from the file path)"

    prompt = (
        POC_PROMPT_TRUST if finding.vuln_class in TRIDENT_VULN_CLASSES
        else POC_PROMPT_STANDARD
    ).format(
        title=finding.title, vuln_class=finding.vuln_class,
        file=finding.file, line_hint=finding.line_hint,
        description=finding.description, attack_vector=finding.attack_vector,
        code_snippet=finding.code_snippet,
        title_slug=_title_slug(finding.title),
        target_packages=tpkg_line,
    )

    resp = None
    try:
        resp = client.messages.create(
            model=POC_MODEL, max_tokens=POC_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}]
        )
        raw  = strip_fences(resp.content[0].text)
        data = json.loads(raw)
        finding.poc             = data.get("poc_code", "")
        finding.poc_explanation = data.get("poc_explanation", "")
        finding.cvss_estimate   = data.get("cvss_estimate", "")
        finding.remediation     = data.get("remediation", "")

    except json.JSONDecodeError as e:
        print(f"\n    [!] PoC JSON parse failed '{finding.title}': {e}")
        if verbose and resp:
            print(f"    [!] Raw: {resp.content[0].text[:400]}")
    except anthropic.BadRequestError as e:
        print(f"\n    [!] PoC content filter '{finding.title}': {e}")
    except anthropic.APIStatusError as e:
        print(f"\n    [!] PoC API error '{finding.title}': {e.status_code}")
    except anthropic.APIConnectionError as e:
        print(f"\n    [!] PoC connection error '{finding.title}': {e}")
    except Exception as e:
        print(f"\n    [!] PoC error '{finding.title}': {type(e).__name__}: {e}")

    return finding


def _run_chain_pass(
    findings: list[Finding],
    client: ArgusClient,
    verbose: bool = False
) -> list[AttackChain]:
    """Single chain synthesis API call over a findings subset."""
    if len(findings) < 2:
        return []
    # Cap to top 15 findings — prevents response truncation on large scans
    SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    capped = sorted(findings, key=lambda f: SEV_RANK.get(f.severity, 4))[:15]
    lines = []
    for f in capped:
        # Truncate attack vector to 100 chars — keep summary tight
        av_short = (f.attack_vector[:100] + "...") if len(f.attack_vector) > 100 else f.attack_vector
        av_short = av_short.replace("\n", " ")
        lines.append(
            f"- [{f.id}] {f.severity} {f.vuln_class} | {f.title[:60]}\n"
            f"  ATTACK: {av_short}"
        )
    summary = "\n".join(lines)
    try:
        resp = client.messages.create(
            model=ANALYSIS_MODEL, max_tokens=1024,
            messages=[{"role": "user", "content": CHAIN_SYNTHESIS_PROMPT.format(findings_summary=summary)}]
        )
        raw  = strip_fences(resp.content[0].text)
        data = json.loads(raw)
        found = data.get("chains", [])
        # Always show chain count — critical diagnostic
        print(f"  [chain] API returned {len(found)} chain(s)")
        if verbose and not found:
            print(f"  [chain] Raw response: {raw[:400]}")
        return [
            AttackChain(
                ids=c.get("ids", []),
                title=c.get("title", ""),
                description=c.get("description", c.get("impact", "")),
                combined_impact=c.get("combined_impact", c.get("impact", "")),
                severity=c.get("severity", c.get("sev", "HIGH")),
            )
            for c in found
        ]
    except json.JSONDecodeError as e:
        # Always loud — this is a real bug
        print(f"\n  [!] Chain JSON parse error: {e}")
        if resp:
            print(f"  [!] Raw (first 400): {resp.content[0].text[:400]}")
    except Exception as e:
        print(f"\n  [!] Chain synthesis error: {type(e).__name__}: {e}")
    return []


def synthesize_chains(findings: list[Finding], client: ArgusClient, verbose: bool = False) -> list[AttackChain]:
    """
    Multi-pass chain synthesis:
    Pass 1 — HIGH/CRITICAL only (primary signal, no noise from MEDIUMs)
    Pass 2 — Cross-class pairs most likely to chain (credential + auth, ssrf + auth, etc.)
    Dedup chains by id-set before returning.
    """
    # Pass 1: HIGH and CRITICAL findings only
    high_crit = [f for f in findings if f.severity in {"CRITICAL", "HIGH"}]
    if verbose:
        print(f"\n    [chain] Pass 1: {len(high_crit)} HIGH/CRITICAL findings")
    chains_p1 = _run_chain_pass(high_crit, client, verbose)

    # Pass 2: Include MEDIUM findings that could enable HIGH/CRITICAL ones
    # Focus on credential/token findings (often MEDIUM) that unlock auth bypasses
    cred_classes   = {"AUTH_BYPASS", "TRUST_ESCALATION"}
    cred_mediums   = [f for f in findings
                      if f.severity == "MEDIUM"
                      and f.vuln_class in cred_classes]
    cross_findings = high_crit + cred_mediums

    chains_p2: list[AttackChain] = []
    if cred_mediums and len(cross_findings) > len(high_crit):
        if verbose:
            print(f"    [chain] Pass 2: {len(cross_findings)} findings (added {len(cred_mediums)} MEDIUM cred findings)")
        chains_p2 = _run_chain_pass(cross_findings, client, verbose)

    # Dedup: two chains are the same if they share the same id-set
    seen: set[frozenset] = set()
    merged: list[AttackChain] = []
    for c in chains_p1 + chains_p2:
        key = frozenset(c.ids)
        if key not in seen:
            seen.add(key)
            merged.append(c)

    return merged

# ─── Output ───────────────────────────────────────────────────────────────────

SEV_ICON = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"
}

def print_finding(f: Finding):
    sev_col   = SEV_COLOR.get(f.severity, C.WHITE)
    cls_col   = CLASS_COLOR.get(f.vuln_class, C.WHITE)
    icon      = SEV_ICON.get(f.severity, "⚪")
    tag       = c(C.GRAY, " [EXAMPLE]") if f.is_example else ""
    trident   = f.vuln_class in {"MESH_TRUST","PHANTOM_MEMORY","TRACE_LATERAL"}
    trident_badge = c(cls_col, " ★TRIDENT") if trident else ""

    print(f"\n  {icon} {c(sev_col+C.BOLD, f'[{f.severity}]')} {c(C.WHITE, f.title)}{tag}{trident_badge}")
    print(f"  {c(C.GRAY,'  ID       :')} {c(C.CYAN, f.id)}")
    print(f"  {c(C.GRAY,'  Class    :')} {c(cls_col, f.vuln_class)}")
    print(f"  {c(C.GRAY,'  File     :')} {c(C.CYAN, f.file)}")
    print(f"  {c(C.GRAY,'  Location :')} {f.line_hint}")
    print(f"  {c(C.GRAY,'  Attack   :')} {f.attack_vector[:140]}")
    if f.cvss_estimate:
        print(f"  {c(C.GRAY,'  CVSS     :')} {c(sev_col, f.cvss_estimate)}")
    if f.poc:
        print(f"  {c(C.GRAY,'  PoC      :')} {c(C.GREEN, '[generated — see report JSON]')}")
    elif f.severity in POC_THRESHOLD:
        print(f"  {c(C.GRAY,'  PoC      :')} {c(C.RED, '[generation failed — rerun with --verbose]')}")

def print_chain(ch: AttackChain):
    sev_col = SEV_COLOR.get(ch.severity, C.WHITE)
    icon    = SEV_ICON.get(ch.severity, "⚪")
    ids_str = c(C.CYAN, " → ".join(ch.ids))
    print(f"\n  {icon} {c(sev_col+C.BOLD, 'CHAIN:')} {c(C.WHITE, ch.title)}")
    print(f"  {c(C.GRAY,'  Findings :')} {ids_str}")
    print(f"  {c(C.GRAY,'  How      :')} {ch.description[:140]}")
    print(f"  {c(C.GRAY,'  Impact   :')} {c(sev_col, ch.combined_impact[:140])}")

def print_banner(target: str):
    rule = c(C.BLUE, "─" * 64)
    print(f"\n{rule}")
    print(f"  {c(C.WHITE+C.BOLD, 'AGENTIC INFRASTRUCTURE ZERO-DAY SCANNER')}  {c(C.CYAN, 'v3')}")
    print(f"  {c(C.GRAY, 'Target           :')} {c(C.CYAN, target)}")
    print(f"  {c(C.GRAY, 'Analysis Model   :')} {c(C.GREEN, ANALYSIS_MODEL)}")
    print(f"  {c(C.GRAY, 'PoC Engine Model :')} {c(C.ORANGE, POC_MODEL)}")
    print(f"{rule}\n")

# ─── Main Pipeline ────────────────────────────────────────────────────────────

TRIDENT_CLASSES = {"MESH_TRUST", "PHANTOM_MEMORY", "TRACE_LATERAL"}

def _poc_filter(finding: Finding, sev_filter: set, cls_filter: set) -> bool:
    """
    Returns True if this finding should receive PoC generation.
    sev_filter: set of severity strings to include e.g. {"CRITICAL","HIGH"}
    cls_filter: set of vuln_class strings to include e.g. {"MESH_TRUST"}
                Empty set means no class filter (use severity only).
    """
    if finding.severity not in sev_filter:
        return False
    if cls_filter and finding.vuln_class not in cls_filter:
        return False
    return True


def run_scan(target: str, output_file: Optional[str], skip_poc: bool, skip_chains: bool, verbose: bool, poc_sev: str = "CRITICAL,HIGH", poc_cls: str = ""):
    """
    v3: Concurrent producer-consumer pipeline.
    Analysis and PoC generation run in parallel:
      - Main thread: analyzes files one by one (producer)
      - PoC worker thread: generates PoCs as findings arrive (consumer)
    Chain synthesis still runs after both threads complete.
    """
    print_banner(target)
    client   = ArgusClient()
    tmp      = tempfile.mkdtemp(prefix="azd_")
    repo_dir = os.path.join(tmp, "repo")

    try:
        # ── 1. Clone ─────────────────────────────────────────────────────────
        if os.path.isdir(target):
            print(f"[1/5] Using local repository: {target}")
            repo_dir = target
        else:
            print("[1/5] Extracting repository...")
            if not clone_repo(target, repo_dir, verbose):
                print("  [✗] Extract failed.")
                return
            return
        print("  [✓] Cloned\n")

        # ── 2. Discover ───────────────────────────────────────────────────────
        print("[2/5] Discovering source files...")
        files = discover_files(repo_dir, verbose)
        print(f"  [✓] {len(files)} files\n")
        if not files:
            print("  No relevant source files found.")
            return

        # ── 3+4. Concurrent analysis + PoC generation ─────────────────────────
        # Parse PoC filter — which findings qualify for PoC generation
        poc_filter_sev = set(s.strip().upper() for s in poc_sev.split(",") if s.strip())
        poc_filter_cls = set(s.strip() for s in poc_cls.split(",") if s.strip())
        if not skip_poc and poc_filter_cls:
            print(f"  {c(C.CYAN, f'PoC filter: severity={poc_filter_sev} class={poc_filter_cls}')}")
        elif not skip_poc:
            print(f"  {c(C.CYAN, f'PoC filter: severity={poc_filter_sev} (all classes)')}")

        # Shared state (thread-safe via queue and lock)
        poc_queue:   queue.Queue = queue.Queue()   # analysis → PoC worker
        all_findings: list[Finding] = []
        enriched:    dict[str, Finding] = {}       # id → PoC-enriched finding
        lock         = threading.Lock()
        poc_done     = threading.Event()
        poc_counter  = [0]                         # mutable counter for display

        _SENTINEL = None  # signals worker to stop

        def poc_worker():
            """Runs in background thread. Pops findings, generates PoCs."""
            while True:
                item = poc_queue.get()
                if item is _SENTINEL:
                    poc_queue.task_done()
                    break
                finding = item
                trident = {"TRUST_ESCALATION","MESH_TRUST","PHANTOM_MEMORY","TRACE_LATERAL"}
                tag = " [TRIDENT]" if finding.vuln_class in trident else ""
                with lock:
                    poc_counter[0] += 1
                    n = poc_counter[0]
                print(f"  [PoC{tag}] #{n} {finding.title[:60]}", flush=True)
                enriched_finding = generate_poc(finding, client, verbose,
                                                 repo_path=target)
                with lock:
                    enriched[enriched_finding.id] = enriched_finding
                poc_queue.task_done()

        # Start PoC worker thread (only if PoCs are not skipped)
        worker = None
        if not skip_poc:
            print("[3+4/5] Analyzing files + generating PoCs concurrently...\n")
            worker = threading.Thread(target=poc_worker, daemon=True)
            worker.start()
        else:
            print("[3/5] Analyzing for vulnerabilities...\n")

        # ── Parallel file analysis using ThreadPoolExecutor ─────────────────
        # Each worker sends its own API request concurrently.
        # M1 Pro sweet spot: 4 workers. Increase if API rate limits allow.
        workers = 1 if verbose else PARALLEL_WORKERS
        file_index = {}  # fp → index for ordered display
        for i, fp in enumerate(files):
            file_index[fp] = i

        print_lock = threading.Lock()
        findings_lock = threading.Lock()
        checkpoint_counter = [0]

        def analyze_one(fp):
            """Worker: analyze one file, return (fp, hits)."""
            return fp, analyze_file(fp, repo_dir, client, verbose)

        completed = [0]

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(analyze_one, fp): fp for fp in files}
            for future in as_completed(futures):
                fp, hits = future.result()
                rel = os.path.relpath(fp, repo_dir)
                idx = file_index[fp]
                completed[0] += 1

                with print_lock:
                    if hits:
                        worst = min(hits, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity) if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99)
                        cnt_col = SEV_COLOR.get(worst.severity, C.WHITE)
                        print(f"  {c(C.GRAY, f'[{idx+1:>3}/{len(files)}]')} {c(C.CYAN, rel)}  {c(cnt_col+C.BOLD, f'→ {len(hits)} finding(s)')}")
                    else:
                        if verbose:
                            print(f"  {c(C.GRAY, f'[{idx+1:>3}/{len(files)}]')} {c(C.GRAY, rel)}")

                if hits:
                    with findings_lock:
                        all_findings.extend(hits)
                        checkpoint_counter[0] += 1
                        # Checkpoint every 10 files with findings
                        if output_file and checkpoint_counter[0] % 10 == 0:
                            _checkpoint_path = output_file.replace(".json", ".checkpoint.json")
                            try:
                                with open(_checkpoint_path, "w") as _cp:
                                    json.dump([asdict(f) for f in all_findings], _cp, indent=2)
                            except Exception:
                                pass

                    if not skip_poc:
                        for h in hits:
                            if _poc_filter(h, poc_filter_sev, poc_filter_cls):
                                poc_queue.put(h)

        # Final checkpoint save
        if output_file and all_findings:
            _checkpoint_path = output_file.replace(".json", ".checkpoint.json")
            try:
                with open(_checkpoint_path, "w") as _cp:
                    json.dump([asdict(f) for f in all_findings], _cp, indent=2)
                print(f"  {c(C.GRAY, f'Checkpoint saved → {_checkpoint_path}')}")
            except Exception:
                pass

        # Signal worker that analysis is done, wait for all PoCs to complete
        if worker:
            poc_queue.put(_SENTINEL)
            worker.join()
            print(f"\n  [✓] PoC generation complete ({len(enriched)} PoC(s) generated)")
        elif skip_poc:
            print("\n[4/5] Skipping PoC generation")

        if not all_findings:
            print("\n  No vulnerabilities identified.")
            if output_file:
                empty = ScanReport(
                    target=target, scanner_version="3.0",
                    total_files_analyzed=len(files), total_findings=0,
                    critical_count=0, high_count=0, medium_count=0, low_count=0,
                )
                with open(output_file, "w") as out:
                    json.dump(asdict(empty), out, indent=2)
                print(f"  Empty report saved → {output_file}")
            return

        # Merge enriched findings back
        final = []
        for f in all_findings:
            final.append(enriched.get(f.id, f))

        # ── 5. Chain synthesis ────────────────────────────────────────────────
        chains: list[AttackChain] = []
        if not skip_chains and len(final) >= 2:
            print(f"\n[5/5] Synthesizing attack chains...")
            chains = synthesize_chains(final, client, verbose)
            print(f"  [✓] {len(chains)} chain(s)")
        else:
            print("\n[5/5] Skipping chain synthesis")

        prod = [f for f in final if not f.is_example]
        exs  = [f for f in final if f.is_example]

        report = ScanReport(
            target=target, scanner_version="3.0",
            total_files_analyzed=len(files), total_findings=len(final),
            critical_count=sum(1 for f in final if f.severity == "CRITICAL"),
            high_count=sum(1 for f in final if f.severity == "HIGH"),
            medium_count=sum(1 for f in final if f.severity == "MEDIUM"),
            low_count=sum(1 for f in final if f.severity == "LOW"),
            chains=[asdict(ch) for ch in chains],
            production_findings=[asdict(f) for f in prod],
            example_findings=[asdict(f) for f in exs],
        )

        rule = c(C.BLUE, "─" * 64)
        print(f"\n{rule}")
        print(f"  {c(C.WHITE+C.BOLD, 'SCAN COMPLETE')}  {c(C.CYAN, '(v3 — concurrent)')}")
        print(f"{rule}")
        print(f"  {c(C.GRAY,'Files analyzed      :')} {report.total_files_analyzed}")
        print(f"  {c(C.GRAY,'Total findings      :')} {c(C.WHITE+C.BOLD, str(report.total_findings))}")
        print(f"  🔴 {c(C.RED+C.BOLD,   'Critical         :')} {c(C.RED,    str(report.critical_count))}")
        print(f"  🟠 {c(C.ORANGE+C.BOLD,'High             :')} {c(C.ORANGE, str(report.high_count))}")
        print(f"  🟡 {c(C.YELLOW+C.BOLD,'Medium           :')} {c(C.YELLOW, str(report.medium_count))}")
        print(f"  🟢 {c(C.GREEN+C.BOLD, 'Low              :')} {c(C.GREEN,  str(report.low_count))}")
        print(f"  ⛓  {c(C.CYAN+C.BOLD,  'Chains           :')} {c(C.CYAN,   str(len(chains)))}")
        print(f"  {c(C.GRAY,'Production findings :')} {len(prod)}")
        print(f"  {c(C.GRAY,'Example findings    :')} {len(exs)}")

        if chains:
            print(f"\n{c(C.BLUE,'─'*64)}\n  {c(C.CYAN+C.BOLD,'ATTACK CHAINS')}\n{c(C.BLUE,'─'*64)}")
            for ch in chains:
                print_chain(ch)

        if prod:
            print(f"\n{c(C.BLUE,'─'*64)}\n  {c(C.WHITE+C.BOLD,'PRODUCTION FINDINGS')}\n{c(C.BLUE,'─'*64)}")
            for f in prod:
                print_finding(f)

        if exs:
            print(f"\n{c(C.BLUE,'─'*64)}\n  {c(C.GRAY,'EXAMPLE / DEMO FINDINGS')}\n{c(C.BLUE,'─'*64)}")
            for f in exs:
                print_finding(f)

        if output_file:
            with open(output_file, "w") as out:
                json.dump(asdict(report), out, indent=2)
            print(f"\n\n  Report saved → {output_file}")

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_batch(targets_file: str, output_dir: str, skip_poc: bool, skip_chains: bool, verbose: bool, poc_sev: str = "CRITICAL,HIGH", poc_cls: str = ""):
    """Run the scanner against every URL in a targets file."""
    import time
    from datetime import datetime

    targets_path = Path(targets_file)
    if not targets_path.exists():
        print(f"[!] Targets file not found: {targets_file}")
        return

    lines = [l.strip() for l in targets_path.read_text().splitlines()
             if l.strip() and not l.strip().startswith("#")]

    if not lines:
        print("[!] No targets found in file.")
        return

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rule = "─" * 64
    print(f"\n{rule}")
    print(f"  BATCH SCAN — {len(lines)} target(s)")
    print(f"  Output dir : {out_dir.resolve()}")
    print(f"{rule}\n")

    summary = []
    for i, url in enumerate(lines):
        print(f"\n[{i+1}/{len(lines)}] {url}")
        # Derive safe filename from URL
        slug = url.replace("https://github.com/", "").replace("/", "_").replace(".", "_")
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        outf = str(out_dir / f"{slug}_{ts}.json")

        start = time.time()
        try:
            run_scan(url, outf, skip_poc, skip_chains, verbose, poc_sev=poc_sev, poc_cls=poc_cls)
            elapsed = time.time() - start
            summary.append({"url": url, "report": outf, "status": "ok", "elapsed": f"{elapsed:.0f}s"})
        except Exception as e:
            elapsed = time.time() - start
            print(f"  [!] Scan failed: {e}")
            summary.append({"url": url, "report": None, "status": f"error: {e}", "elapsed": f"{elapsed:.0f}s"})

        # Brief pause between scans to avoid rate limits
        if i < len(lines) - 1:
            time.sleep(2)

    # Batch summary
    print(f"\n{rule}")
    print(f"  BATCH COMPLETE")
    print(f"{rule}")
    for s in summary:
        status = "✓" if s["status"] == "ok" else "✗"
        print(f"  {status} {s['url']} ({s['elapsed']})")
        if s["report"]:
            print(f"      → {s['report']}")

    # Write batch index
    index_file = out_dir / "batch_index.json"
    with open(index_file, "w") as f:
        json.dump({"targets": summary, "total": len(lines),
                   "succeeded": sum(1 for s in summary if s["status"] == "ok")}, f, indent=2)
    print(f"\n  Batch index → {index_file}")



def run_poc_only(report_file: str, output_file: Optional[str], poc_sev: str, poc_cls: str, verbose: bool):
    """
    --poc-only mode: read an existing JSON report, generate PoCs for findings
    that are missing them, write updated report back. No re-scanning required.
    """
    rule = c(C.BLUE, "─" * 64)
    print(f"\n{rule}")
    print(f"  {c(C.WHITE+C.BOLD, 'ARGUS PoC-ONLY MODE')}")
    print(f"  {c(C.GRAY, 'Report  :')} {c(C.CYAN, report_file)}")
    print(f"{rule}\n")

    # Load report
    try:
        with open(report_file) as f:
            report_data = json.load(f)
    except Exception as e:
        print(c(C.RED, f"[!] Failed to load report: {e}"))
        return

    # Flatten all findings from report
    prod = report_data.get("production_findings", report_data.get("findings", []))
    exs  = report_data.get("example_findings", [])
    all_findings_raw = prod + exs

    # Parse filters
    poc_filter_sev = {s.strip().upper() for s in poc_sev.split(",") if s.strip()}
    poc_filter_cls = {s.strip() for s in poc_cls.split(",") if s.strip()}

    # Find findings that need PoCs
    need_poc = []
    for f in all_findings_raw:
        if f.get("poc"):
            continue  # already has one
        sev = f.get("severity", "")
        cls = f.get("vuln_class", "")
        if sev not in poc_filter_sev:
            continue
        if poc_filter_cls and cls not in poc_filter_cls:
            continue
        need_poc.append(f)

    total = len(need_poc)
    already = sum(1 for f in all_findings_raw if f.get("poc"))
    print(f"  {c(C.GRAY, 'Findings in report  :')} {len(all_findings_raw)}")
    print(f"  {c(C.GRAY, 'Already have PoC    :')} {c(C.GREEN, str(already))}")
    print(f"  {c(C.GRAY, 'Need PoC (filtered) :')} {c(C.ORANGE, str(total))}")
    print(f"  {c(C.GRAY, 'Severity filter     :')} {poc_filter_sev}")
    if poc_filter_cls:
        print(f"  {c(C.GRAY, 'Class filter        :')} {poc_filter_cls}")
    print()

    if total == 0:
        print(c(C.GREEN, "  [✓] All qualifying findings already have PoC code. Nothing to do."))
        return

    client = ArgusClient()
    generated = 0
    failed = 0

    for i, raw_f in enumerate(need_poc):
        sev = raw_f.get("severity", "?")
        cls = raw_f.get("vuln_class", "?")
        title = raw_f.get("title", "?")[:60]
        sev_col = SEV_COLOR.get(sev, C.WHITE)
        cls_col = CLASS_COLOR.get(cls, C.WHITE)
        trident = " " + c(cls_col, "★") if cls in TRIDENT_CLASSES else ""

        print(f"  {c(C.GRAY, f'[{i+1:>3}/{total}]')} {c(sev_col, sev)}{trident} {c(C.CYAN, title)}", flush=True)

        # Convert raw dict to Finding dataclass
        finding = Finding(
            id=raw_f.get("id", ""),
            vuln_class=cls,
            severity=sev,
            title=raw_f.get("title", ""),
            file=raw_f.get("file", ""),
            line_hint=raw_f.get("line_hint", ""),
            description=raw_f.get("description", ""),
            code_snippet=raw_f.get("code_snippet", ""),
            attack_vector=raw_f.get("attack_vector", ""),
            is_example=raw_f.get("is_example", False),
            cvss_estimate=raw_f.get("cvss_estimate", ""),
            remediation=raw_f.get("remediation", ""),
        )

        enriched = generate_poc(finding, client, verbose)

        if enriched.poc:
            # Write PoC back to the raw dict in-place
            raw_f["poc"]             = enriched.poc
            raw_f["poc_explanation"] = enriched.poc_explanation
            raw_f["cvss_estimate"]   = enriched.cvss_estimate or raw_f.get("cvss_estimate", "")
            raw_f["remediation"]     = enriched.remediation or raw_f.get("remediation", "")
            print(f"    {c(C.GREEN, '[✓] PoC generated')}")
            generated += 1
        else:
            print(f"    {c(C.RED, '[✗] PoC generation failed')}")
            failed += 1

    # Write updated report
    out_path = output_file or report_file  # overwrite in place if no --output specified
    with open(out_path, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n{rule}")
    print(f"  {c(C.WHITE+C.BOLD, 'POC-ONLY COMPLETE')}")
    print(f"  {c(C.GRAY, 'Generated  :')} {c(C.GREEN, str(generated))}")
    print(f"  {c(C.GRAY, 'Failed     :')} {c(C.RED, str(failed))}")
    print(f"  {c(C.GRAY, 'Report     :')} {c(C.CYAN, out_path)}")
    print(f"{rule}\n")

def main():
    p = argparse.ArgumentParser(
        description="Agentic AI Infrastructure Zero-Day Scanner v3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Single target:
  python scanner.py https://github.com/org/mcp-server
  python scanner.py https://github.com/org/agent-framework -o report.json --verbose

Batch mode:
  python scanner.py --targets targets.txt --output-dir ./results
  python scanner.py --targets targets.txt --output-dir ./results --skip-poc
        """
    )
    # Single target (positional, optional when --targets is used)
    p.add_argument("target",         nargs="?", default=None,
                   help="Single GitHub URL to scan")
    p.add_argument("-o", "--output", default=None,
                   help="Output JSON file (single target mode)")

    # Batch mode
    p.add_argument("--targets",      default=None,
                   help="File containing one GitHub URL per line")
    p.add_argument("--output-dir",   default="./scan_results",
                   help="Directory for batch scan reports (default: ./scan_results)")

    # Shared flags
    p.add_argument("--skip-poc",     action="store_true")
    p.add_argument("--skip-chains",  action="store_true")
    p.add_argument("--verbose",      action="store_true")

    # PoC filter flags — control which findings get PoC generation
    p.add_argument("--poc-sev",
                   default="CRITICAL,HIGH",
                   help="Comma-separated severities to generate PoCs for (default: CRITICAL,HIGH)")
    p.add_argument("--poc-cls",
                   default="",
                   help="Comma-separated vuln classes to generate PoCs for (default: all). "
                        "Examples: MESH_TRUST,PHANTOM_MEMORY,TRACE_LATERAL  or  CRITICAL_ONLY")

    # PoC-only mode — enrich an existing report without re-scanning
    p.add_argument("--poc-only",
                   default=None,
                   metavar="REPORT.json",
                   help="Path to existing JSON report. Generate missing PoCs without re-scanning. "
                        "Respects --poc-sev and --poc-cls filters. Writes back to same file "
                        "unless --output is specified.")

    args = p.parse_args()

    if args.poc_only:
        run_poc_only(args.poc_only, args.output, args.poc_sev, args.poc_cls, args.verbose)
    elif args.targets:
        run_batch(args.targets, args.output_dir, args.skip_poc, args.skip_chains,
                  args.verbose, args.poc_sev, args.poc_cls)
    elif args.target:
        run_scan(args.target, args.output, args.skip_poc, args.skip_chains,
                 args.verbose, args.poc_sev, args.poc_cls)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
