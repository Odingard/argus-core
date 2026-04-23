"""
argus.pro.consensus — multi-model CRITICAL agreement gate.

A single LLM judge can hallucinate a "CRITICAL" finding; Bugcrowd and
HackerOne triage reject theoretical issues, so an operator whose
report contains AI-slop criticals burns their submission budget on
junk. This module enforces **N-of-M model agreement** before any
finding is allowed to keep the CRITICAL severity label — if the
required number of independent judges (Claude Opus / GPT-5 / Gemini
Ultra) don't all agree, the severity downgrades to HIGH with a
`downgraded_from: CRITICAL (consensus=N/M)` annotation.

This is a PRO-tier feature — operators on the MIT core tier do not
need it and should not pay for it. The `argus.license.require()`
gate below is a stub today (permissive) and tightens on first PRO
customer; when tightened, `import argus.pro.consensus` without a
valid license raises `LicenseError` with a clear upgrade message.

Import-time-gating rationale: failing at import means the *absence*
of the feature is loud and unambiguous. A caller that tries to
`from argus.pro.consensus import require_agreement` and doesn't
have a license gets a clear error at the line that requires it,
not silently-degraded behaviour mid-run.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from argus.license import require

# Gate first — any code path below is PRO-only. When the license
# stub tightens, this line is the single choke-point.
require("consensus")


@dataclass(frozen=True)
class ConsensusVerdict:
    """Outcome of evaluating a finding against N independent judges."""
    original_severity: str
    agreed_severity:   str         # may be downgraded from the original
    agreement_count:   int         # how many judges confirmed original
    total_judges:      int
    downgraded:        bool        # True iff agreed != original

    @property
    def annotation(self) -> str:
        if not self.downgraded:
            return f"consensus {self.agreement_count}/{self.total_judges}"
        return (
            f"downgraded from {self.original_severity} "
            f"(consensus {self.agreement_count}/{self.total_judges})"
        )


def require_agreement(
    original_severity: str,
    judge_votes:       Sequence[str],
    *,
    min_agreement:     int = 2,
) -> ConsensusVerdict:
    """Apply N-of-M agreement. Pure function — testable without LLMs."""
    agreement = sum(1 for v in judge_votes if v == original_severity)
    total     = len(judge_votes)
    if agreement >= min_agreement:
        return ConsensusVerdict(
            original_severity=original_severity,
            agreed_severity=original_severity,
            agreement_count=agreement,
            total_judges=total,
            downgraded=False,
        )
    fallback = _downgrade(original_severity)
    return ConsensusVerdict(
        original_severity=original_severity,
        agreed_severity=fallback,
        agreement_count=agreement,
        total_judges=total,
        downgraded=True,
    )


_DOWNGRADES = {
    "CRITICAL": "HIGH",
    "HIGH":     "MEDIUM",
    "MEDIUM":   "LOW",
    "LOW":      "LOW",
    "INFO":     "INFO",
}


def _downgrade(severity: str) -> str:
    return _DOWNGRADES.get(severity.upper(), severity)


__all__ = ["ConsensusVerdict", "require_agreement"]
