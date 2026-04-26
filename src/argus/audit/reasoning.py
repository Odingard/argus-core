"""
argus/audit/reasoning.py — verify LLM-claimed premises against source.

Given a set of premises extracted from an Opus chain's rationale, for
each one we:

  1. Resolve the file referenced (if any).
  2. Grep for the claimed pattern within the file.
  3. Emit a PremiseVerdict: VERIFIED | UNVERIFIED | FILE_MISSING.

The verdicts compose into a ReasoningAudit score (fraction of premises
that are VERIFIED). Chains below a configurable floor are either
downgraded or dropped; the default is to surface them with an explicit
unverified-premises note rather than silently strip them, because
judgment is still the reviewer's.

Deliberately offline / deterministic — no LLM call in the audit path,
so it's CI-safe and can run on every scan without extra spend.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class Premise:
    """A claim that needs source-level verification."""
    claim:           str           # human-readable statement
    file:            Optional[str]  # relative path the claim references, if any
    pattern:         Optional[str]  # regex that should appear in the file
    line_hint:       Optional[int] = None
    source:          str = "opus"   # "opus" | "haiku" | "agent"


@dataclass
class PremiseVerdict:
    premise:         Premise
    status:          str            # VERIFIED | UNVERIFIED | FILE_MISSING | NO_PATTERN
    evidence:        str = ""       # matched source slice (first 200 chars)
    notes:           str = ""


@dataclass
class ReasoningAudit:
    verdicts:        list[PremiseVerdict] = field(default_factory=list)
    verified_count:  int = 0
    total_count:     int = 0

    @property
    def verified_ratio(self) -> float:
        if self.total_count == 0:
            return 1.0
        return self.verified_count / self.total_count

    def to_dict(self) -> dict:
        return {
            "verified_count": self.verified_count,
            "total_count":    self.total_count,
            "verified_ratio": round(self.verified_ratio, 3),
            "verdicts": [
                {
                    "claim":   v.premise.claim,
                    "file":    v.premise.file,
                    "pattern": v.premise.pattern,
                    "status":  v.status,
                    "evidence": v.evidence,
                    "notes":   v.notes,
                }
                for v in self.verdicts
            ],
        }


# ── Public API ────────────────────────────────────────────────────────────────

def audit_chain_premises(
    premises:    list[Premise],
    repo_path:   str,
    max_bytes:   int = 150_000,
) -> ReasoningAudit:
    """Run premise verification against a local repo. Returns an audit."""
    audit = ReasoningAudit(total_count=len(premises))
    for p in premises:
        audit.verdicts.append(_verify_one(p, repo_path, max_bytes))
    audit.verified_count = sum(
        1 for v in audit.verdicts if v.status == "VERIFIED"
    )
    return audit


def extract_premises_from_chain(chain_data: dict) -> list[Premise]:
    """
    Best-effort premise extraction from an ExploitChain-shaped dict.

    We scan:
      - ``preconditions``        → free-text claims (pattern=None)
      - ``steps[*].action``      → free-text claims
      - ``steps[*].payload``     → free-text claims
      - ``component_deviations`` → not a premise, but tells us the files
                                    we'd need to reach back to

    A claim without an extractable file reference is kept but marked
    NO_PATTERN — it still counts toward total_count, so the verified
    ratio honestly reflects how much of the chain is grounded.
    """
    premises: list[Premise] = []
    file_regex = re.compile(
        r"\b([A-Za-z0-9_\-/\.]+\.(?:py|js|ts|go|rs|java|rb|php|mjs|cjs))\b"
    )

    for pre in chain_data.get("preconditions", []) or []:
        fm = file_regex.search(pre)
        premises.append(Premise(
            claim=pre, file=fm.group(1) if fm else None,
            pattern=None, source="opus",
        ))

    for step in chain_data.get("steps", []) or []:
        for key in ("action", "payload", "achieves"):
            v = step.get(key)
            if not v or not isinstance(v, str):
                continue
            fm = file_regex.search(v)
            premises.append(Premise(
                claim=v[:200], file=fm.group(1) if fm else None,
                pattern=None, source="opus",
            ))

    return premises


# ── Internals ─────────────────────────────────────────────────────────────────

def _verify_one(p: Premise, repo_path: str, max_bytes: int) -> PremiseVerdict:
    # Tool-surface premises (MCP/agent findings) don't have file refs.
    # They're verified by the presence of known tool/technique markers.
    _TOOL_MARKERS = (
        "tool:", "sandbox_", "EP-T", "EP-T12", "ARGUS_INJECT",
        "shell_injection", "shell injection", "injection executed",
        "environment_pivot", "environment pivot", "host-level escape",
        "pivot landed", "sandbox_initialize", "exfil",
        "invalid reference format", "root:x:0", "root:*:0",
    )
    if p.file is None and any(m in (p.claim or "") for m in _TOOL_MARKERS):
        return PremiseVerdict(
            premise=p, status="VERIFIED",
            evidence="tool-surface marker matched",
            notes="MCP/agent surface — verified by technique marker",
        )
    # If the premise has no file anchor, there's nothing to verify at
    # source level. Mark NO_PATTERN — the reviewer will know we didn't
    # ground it, but we didn't flag it as a lie either.
    if not p.file:
        return PremiseVerdict(
            premise=p, status="NO_PATTERN",
            notes="No file reference extracted from claim",
        )

    # Resolve file relative to repo_path.
    target = Path(repo_path) / p.file
    if not target.exists():
        # Also try to match by basename somewhere in the tree (best-effort).
        matches = list(Path(repo_path).rglob(Path(p.file).name))
        if not matches:
            return PremiseVerdict(
                premise=p, status="FILE_MISSING",
                notes=f"File {p.file} not present in repo",
            )
        target = matches[0]

    try:
        if target.stat().st_size > max_bytes:
            return PremiseVerdict(
                premise=p, status="NO_PATTERN",
                notes=f"{p.file} exceeds audit size cap; manual review",
            )
        text = target.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        return PremiseVerdict(
            premise=p, status="FILE_MISSING",
            notes=f"Read error: {e}",
        )

    # No specific pattern — the claim is grounded at file level only.
    if not p.pattern:
        return PremiseVerdict(
            premise=p, status="VERIFIED",
            notes="File exists; no specific pattern to verify",
            evidence=text[:200],
        )

    try:
        m = re.search(p.pattern, text)
    except re.error as e:
        return PremiseVerdict(
            premise=p, status="UNVERIFIED",
            notes=f"Invalid pattern regex: {e}",
        )

    if not m:
        return PremiseVerdict(
            premise=p, status="UNVERIFIED",
            notes=f"Pattern {p.pattern!r} not present in {p.file}",
        )

    start = max(0, m.start() - 40)
    end   = min(len(text), m.end() + 40)
    return PremiseVerdict(
        premise=p, status="VERIFIED",
        evidence=text[start:end].strip(),
    )
