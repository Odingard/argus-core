"""Schema-ambiguity matcher — FastAPI-style auth boundary confusion.

``ext-schema-boundary-confusion`` exercises auth boundaries that
string-match on role names without normalising the claim shape:

* nested JSON claim where the validator inspects ``role`` but the
  intent classifier uses ``user.role`` (so the elevated value
  survives validation but reaches downstream code as authoritative);
* claim arrays (``"role": ["user", "admin"]``) where the validator
  picks index 0 and the consumer iterates;
* JWT-embedded role claims that decode to a richer payload;
* unicode-collision role names (e.g. ``аdmin`` with a Cyrillic ``а``)
  that pass a denylist but display identical to the protected role.

The matcher reads two structural signals from the probe:

1. **Auth-status flip** — a probe that started 401/403 and ended 200
   on the protected endpoint, recorded by the runner into
   ``probe.raw_response["auth_status_sequence"]``.
2. **Role-claim shape** — the probe's ``raw_response`` carries the
   role string actually sent; we detect array-shaped claims, nested
   JSON paths, and unicode confusables in role names.

Pure deterministic computation (rules #3 + #7). Returns ``None``
when neither structural signal is present (rule #9 — explainable
empty result).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..core.types import Confidence
from .matcher import Match, ProbeResult

# ASCII letters used in privileged-role names. A unicode codepoint
# that *displays* as one of these characters but isn't actually it
# is a confusable.
_ASCII_ROLE_NAMES: frozenset[str] = frozenset({"admin", "root", "owner", "superuser", "operator", "moderator"})

# Explicit Latin-look-alike confusable map. A pure unicodedata NFKD
# round-trip will not collapse Cyrillic ``а`` (U+0430) onto Latin
# ``a`` (U+0061) — they're considered semantically different code
# points by Unicode. For role-name boundary checks the *visual*
# collision is the entire attack, so we maintain an explicit
# code-point → Latin map of the characters real-world auth-boundary
# bypasses use. Deterministic (rules #3 + #7); no normalization
# library calls.
_LATIN_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic small a
    "\u0435": "e",  # Cyrillic small ie
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0441": "c",  # Cyrillic small es
    "\u0445": "x",  # Cyrillic small ha
    "\u0455": "s",  # Cyrillic small dze
    "\u0456": "i",  # Cyrillic small byelorussian-ukrainian i
    "\u0457": "i",  # Cyrillic small yi
    "\u0458": "j",  # Cyrillic small je
    "\u051d": "w",  # Cyrillic small we
    "\u03bf": "o",  # Greek small omicron
    "\u03b1": "a",  # Greek small alpha
    "\u03c1": "p",  # Greek small rho
    "\u0251": "a",  # Latin small alpha
    "\u0261": "g",  # Latin small script g
    "\u0274": "n",  # Latin small capital n
    "\u0280": "r",  # Latin small capital r
    "\u029c": "h",  # Latin small capital h
    "\u207f": "n",  # Superscript n
}

# Status codes that count as "denied" on entry to the boundary.
_DENIED_STATUS: frozenset[int] = frozenset({401, 403})
# Status codes that count as "served" on exit from the boundary.
_SERVED_STATUS: frozenset[int] = frozenset({200, 201, 202, 204})


def _detect_auth_status_flip(
    sequence: list[int] | tuple[int, ...],
) -> tuple[int, int] | None:
    """Return (first_denied_status, served_status) when a flip occurred."""
    denied: int | None = None
    for status in sequence:
        if status in _DENIED_STATUS and denied is None:
            denied = status
        elif status in _SERVED_STATUS and denied is not None:
            return denied, status
    return None


def _detect_unicode_confusable(role: str) -> tuple[str, str] | None:
    """Return (role, normalised_role) when role contains a confusable.

    Walks the role string character-by-character, replacing any code
    point in :data:`_LATIN_CONFUSABLES` with its Latin equivalent. If
    the resulting case-folded string matches a protected ASCII role
    name and the original string was *not* already that role name,
    the role contains a visual confusable.
    """
    if not role:
        return None
    if role.isascii() and role.lower() in _ASCII_ROLE_NAMES:
        # Pure ASCII that's already a privileged-role name isn't a
        # confusable — it's the role itself, and validation would
        # reject it at the front door.
        return None
    folded_chars = [_LATIN_CONFUSABLES.get(ch, ch) for ch in role]
    folded = "".join(folded_chars).lower()
    if folded in _ASCII_ROLE_NAMES and folded != role.lower():
        return role, folded
    return None


def _detect_array_role_claim(claim: Any) -> bool:
    return isinstance(claim, list) and any(
        isinstance(item, str) and item.lower() in _ASCII_ROLE_NAMES for item in claim
    )


def _detect_nested_role_claim(payload: dict[str, Any] | None) -> str | None:
    """Find ``user.role`` / ``profile.role`` / ``claims.role`` paths."""
    if not payload:
        return None
    for parent in ("user", "profile", "claims", "identity", "context"):
        sub = payload.get(parent)
        if isinstance(sub, dict):
            role = sub.get("role")
            if isinstance(role, str) and role.lower() in _ASCII_ROLE_NAMES:
                return f"{parent}.role={role}"
            if isinstance(role, list) and _detect_array_role_claim(role):
                return f"{parent}.role=[array]"
    return None


_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")


def _detect_jwt_in_role_claim(role_claim: Any) -> bool:
    return isinstance(role_claim, str) and bool(_JWT_PATTERN.search(role_claim))


@dataclass(frozen=True, slots=True)
class SchemaAmbiguityMatcher:
    """Detects auth-boundary schema confusion (Phase-S ext-schema-boundary-confusion)."""

    matcher_id: str = "schema-ambiguity"
    confidence: Confidence = "HIGH"

    def evaluate(self, probe: ProbeResult) -> Match | None:
        raw = probe.raw_response or {}
        hits: list[dict] = []
        max_conf: Confidence = "LOW"
        order = ("LOW", "MEDIUM", "HIGH", "IRREFUTABLE")

        def _bump(tier: Confidence) -> None:
            nonlocal max_conf
            if order.index(tier) > order.index(max_conf):
                max_conf = tier

        sequence = raw.get("auth_status_sequence")
        if isinstance(sequence, (list, tuple)):
            statuses: list[int] = []
            for s in sequence:
                try:
                    statuses.append(int(s))
                except (TypeError, ValueError):
                    continue
            flip = _detect_auth_status_flip(statuses)
            if flip is not None:
                hits.append(
                    {
                        "rule": "auth_status_flip",
                        "from_status": flip[0],
                        "to_status": flip[1],
                        "sequence": statuses,
                    }
                )
                _bump("HIGH")

        role_claim = raw.get("role_claim")
        if _detect_array_role_claim(role_claim):
            hits.append({"rule": "array_role_claim", "claim": list(role_claim)})
            _bump("HIGH")
        if _detect_jwt_in_role_claim(role_claim):
            hits.append({"rule": "embedded_jwt_role_claim"})
            _bump("MEDIUM")

        nested = _detect_nested_role_claim(raw.get("claim_payload"))
        if nested is not None:
            hits.append({"rule": "nested_role_claim", "path": nested})
            _bump("HIGH")

        if isinstance(role_claim, str):
            conf = _detect_unicode_confusable(role_claim)
            if conf is not None:
                hits.append(
                    {
                        "rule": "unicode_confusable_role",
                        "claimed": conf[0],
                        "normalised": conf[1],
                    }
                )
                _bump("HIGH")

        if not hits:
            return None
        if probe.refused:
            # Rule #5 — a refused probe never lands the boundary,
            # regardless of how its claim was shaped.
            return None

        return Match(
            matcher_id=self.matcher_id,
            confidence=max_conf,
            evidence={"hits": tuple(hits[:8]), "total_hits": len(hits)},
            landed=True,
            notes=f"{len(hits)} schema-ambiguity signal(s)",
        )


__all__ = [
    "SchemaAmbiguityMatcher",
]
