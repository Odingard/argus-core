"""
argus/evidence/extractor.py — Raw evidence extraction and preservation.

Captures ALL signal from every probe response at the transport layer.
No evidence leakage. Everything that lands in stdout/stderr is stored,
decoded, and indexed for finding confirmation.

Problems this solves:
  1. Binary buffers in MCP responses contain exploit output (passwd file,
     AWS keys, etc.) but were silently dropped before reaching detectors.
  2. macOS uses root:*:0:0: not root:x:0:0: — pattern mismatch missed it.
  3. docker error messages containing injection proof weren't extracted.
  4. Evidence was truncated before structural markers could be matched.

This module sits between the raw MCP response and the detector layer.
It extracts, decodes, and surfaces every piece of evidence so clients
get irrefutable proof — not just "beacon confirmed" but the actual
file contents, the actual error, the actual shell output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Extraction patterns — BOTH Linux and macOS ────────────────────────────────

_PASSWD_PATTERNS = [
    # Linux: root:x:0:0:
    re.compile(r"root:x:\d+:\d+:[^\n]*", re.MULTILINE),
    # macOS: root:*:0:0:
    re.compile(r"root:\*:\d+:\d+:[^\n]*", re.MULTILINE),
    # macOS ## User Database header
    re.compile(r"##\s*\n#\s*User Database[^\n]*", re.MULTILINE),
    # Any passwd-format line: user:x/password:uid:gid:
    re.compile(r"[a-z_][a-z0-9_-]*:[x*!]?:\d+:\d+:[^\n]{0,80}", re.MULTILINE),
]

_BEACON_PATTERNS = [
    re.compile(r"ARGUS_INJECT_BEACON_\d+"),
    re.compile(r"invalid reference format.*ARGUS_INJECT_BEACON[^\n]*"),
    re.compile(r"repository name.*ARGUS_INJECT_BEACON[^\n]*"),
]

_DOCKER_INJECTION_PATTERNS = [
    re.compile(r"docker: invalid reference format[^\n]*"),
    re.compile(r"invalid reference format: repository name \([^\)]+\)"),
]

_SECRET_PATTERNS = [
    ("aws_key",       re.compile(r"AKIA[A-Z0-9]{16}")),
    ("aws_secret",    re.compile(r"(?i)aws_secret_access_key[^\n]*")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key",    re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("private_key",   re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY")),
    ("github_token",  re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("env_vars",      re.compile(r"[A-Z_]{4,}=.{4,}", re.MULTILINE)),
]


@dataclass
class ExtractedEvidence:
    """All evidence extracted from a single probe response."""
    raw_text:          str = ""
    decoded_buffers:   list[str] = field(default_factory=list)
    passwd_lines:      list[str] = field(default_factory=list)
    beacon_hits:       list[str] = field(default_factory=list)
    docker_proofs:     list[str] = field(default_factory=list)
    secret_hits:       list[tuple[str, str]] = field(default_factory=list)
    full_text:         str = ""   # combined clean text for downstream
    clean_exfil:       list[tuple[str, str]] = field(default_factory=list)
    has_shell_proof:   bool = False
    has_passwd_proof:  bool = False
    has_secret_proof:  bool = False

    @property
    def strongest_proof(self) -> str:
        """Return the single strongest piece of proof for client reports."""
        if self.passwd_lines:
            return self.passwd_lines[0]
        if self.secret_hits:
            name, val = self.secret_hits[0]
            return f"{name}: {val[:60]}"
        if self.docker_proofs:
            return self.docker_proofs[0]
        if self.beacon_hits:
            return self.beacon_hits[0]
        return ""

    @property
    def proof_grade(self) -> str:
        """IRREFUTABLE / STRONG / INDICATIVE / NONE"""
        if self.has_passwd_proof or self.has_secret_proof:
            return "IRREFUTABLE"
        if self.clean_exfil or self.docker_proofs or self.beacon_hits:
            return "STRONG"
        if self.full_text and len(self.full_text) > 80:
            return "INDICATIVE"
        return "NONE"


def _decode_buffer_hex(text: str) -> list[str]:
    """Decode hex buffer representations from MCP error output.

    MCP SDK error objects include stdout/stderr as Buffer objects:
      <Buffer 23 23 0a 23 20 55 73 65 72 ...>
    These contain the actual exploit output (passwd file, etc.)
    and must be decoded before pattern matching.
    """
    decoded = []
    for m in re.finditer(r"<Buffer ((?:[0-9a-f]{2} ?)+)>", text):
        hex_str = m.group(1).strip()
        try:
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            text_content = raw.decode("utf-8", errors="replace")
            if text_content.strip():
                decoded.append(text_content)
        except Exception:
            pass
    return decoded


def extract_evidence(response_text: str,
                     stderr_text: str = "") -> ExtractedEvidence:
    """Extract all evidence from a probe response.

    Call this instead of raw pattern matching on response_text.
    Handles: Buffer decoding, macOS/Linux passwd variants,
    beacon markers, docker injection proofs, secrets.
    """
    ev = ExtractedEvidence(raw_text=response_text)

    # 1. Decode all Buffer hex representations
    ev.decoded_buffers = _decode_buffer_hex(response_text)
    if stderr_text:
        ev.decoded_buffers.extend(_decode_buffer_hex(stderr_text))

    # 2. Build full text corpus: response + stderr + decoded buffers
    parts = [response_text]
    if stderr_text:
        parts.append(stderr_text)
    parts.extend(ev.decoded_buffers)
    ev.full_text = "\n".join(p for p in parts if p.strip())

    # 3. Scan for passwd content (Linux + macOS)
    for pat in _PASSWD_PATTERNS:
        for m in pat.finditer(ev.full_text):
            hit = m.group(0).strip()
            if hit and hit not in ev.passwd_lines:
                ev.passwd_lines.append(hit)

    # 4. Scan for beacon markers
    for pat in _BEACON_PATTERNS:
        for m in pat.finditer(ev.full_text):
            hit = m.group(0).strip()
            if hit and hit not in ev.beacon_hits:
                ev.beacon_hits.append(hit)

    # 5. Scan for docker injection proof
    for pat in _DOCKER_INJECTION_PATTERNS:
        for m in pat.finditer(ev.full_text):
            hit = m.group(0).strip()
            if hit and hit not in ev.docker_proofs:
                ev.docker_proofs.append(hit)

    # 6. Scan for secrets
    for name, pat in _SECRET_PATTERNS:
        for m in pat.finditer(ev.full_text):
            hit = m.group(0).strip()
            if hit:
                ev.secret_hits.append((name, hit))

    ev.has_shell_proof  = bool(ev.beacon_hits or ev.docker_proofs)
    ev.has_passwd_proof = bool(ev.passwd_lines)
    ev.has_secret_proof = bool(ev.secret_hits)

    # 7. Clean exfiltration — parse structured data from error channel
    ev.clean_exfil = _extract_clean_exfil(ev.full_text)

    return ev


def format_for_report(ev: ExtractedEvidence,
                      max_chars: int = 800) -> str:
    """Format extracted evidence for client-facing report.

    Produces clean, readable proof that a non-technical reader
    can understand. No raw hex, no buffer objects.
    """
    lines = []

    if ev.proof_grade == "NONE":
        return "No exploitable evidence extracted."

    lines.append(f"[Proof Grade: {ev.proof_grade}]")

    if ev.passwd_lines:
        lines.append("\n--- Host /etc/passwd Contents ---")
        for line in ev.passwd_lines[:10]:
            lines.append(f"  {line}")
        if len(ev.passwd_lines) > 10:
            lines.append(f"  ... ({len(ev.passwd_lines)} total lines)")

    if ev.beacon_hits:
        lines.append("\n--- Shell Execution Confirmed ---")
        for hit in ev.beacon_hits[:3]:
            lines.append(f"  {hit}")

    if ev.docker_proofs:
        lines.append("\n--- Docker Injection Proof ---")
        for hit in ev.docker_proofs[:3]:
            lines.append(f"  {hit}")

    if ev.secret_hits:
        lines.append("\n--- Secrets Exposed ---")
        for name, val in ev.secret_hits[:5]:
            lines.append(f"  {name}: {val[:80]}")

    result = "\n".join(lines)
    return result[:max_chars]


# ── Clean exfiltration result patterns ───────────────────────────────────────

_CLEAN_EXFIL_PATTERNS = [
    # id output: uid-0-root-gid-0-root
    re.compile(r"uid-\d+-[a-z]+-gid-\d+-[a-z]+"),
    # whoami result in docker error
    re.compile(r"library/(root|admin|ubuntu|daemon|[a-z_][a-z0-9_]{1,15})\)"),
    # base64-encoded first passwd line
    re.compile(r"library/([A-Za-z0-9+/]{20,})\)"),
    # env var exfil: ARGUS_ENV_HOME_/root_USER_root_12345
    re.compile(r"ARGUS_ENV_HOME_([^\s_]+)_USER_([^\s_]+)_(\d+)"),
    # hostname in docker error
    re.compile(r"library/([a-z0-9][a-z0-9\-\.]{3,})\)"),
]


def _extract_clean_exfil(text: str) -> list[tuple[str, str]]:
    """Extract clean exfiltration results from docker error messages."""
    results = []
    for pat in _CLEAN_EXFIL_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0)
            if "ARGUS_ENV" in val:
                results.append(("env_exfil", val))
            elif "uid-" in val:
                results.append(("id_output", val))
            elif "library/" in val:
                inner = val.split("library/")[1].rstrip(")")
                results.append(("exfil_value", inner))
    return results
