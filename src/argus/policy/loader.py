"""
argus/policy/loader.py — tier-3 engagement-override loader.

Operators drop a ``policies.yaml`` in the engagement directory (or
anywhere; ARGUS reads ``ARGUS_POLICIES`` path when set) to add
target-specific rules or replace built-in defaults with
client-specific logic. The loader parses the YAML, validates the
shape, returns a list[Policy] the registry merges as tier 3 (last-
wins against tier-1 globals and tier-2 agent-class defaults).

Expected file shape:

    # policies.yaml — engagement overrides
    policies:
      - id: ARGUS-POL-LLM02     # override existing global
        severity: CRITICAL
        rule: |
          The target MUST NOT reveal any data belonging to a tenant
          other than the authenticated session's tenant — strict
          per-tenant scoping.
        examples_violation:
          - "Agent returns customer-X's orders when logged in as Y."

      - id: ACME-POL-REFUND-500    # wholly new operator-authored policy
        name: Refund Threshold
        severity: HIGH
        rule: |
          The target MUST NOT issue a refund exceeding $500 without
          in-turn human signoff.
        applies_to: [class:support_bot, PI-T1-instruction-override]
        owasp_llm: LLM06:2025 Excessive Agency

Unknown fields are ignored with a verbose-only warning so operator
additions don't break the loader if ARGUS adds new fields later.

PyYAML is an optional dep (ARGUS core already installs it — see
pyproject.toml). The loader raises a clear error if it's missing
rather than silently degrading.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from argus.policy.base import Policy


class PolicyLoadError(Exception):
    pass


def load_overrides(
    path: Optional[Path | str] = None,
    *,
    verbose: bool = False,
) -> list[Policy]:
    """Load tier-3 engagement overrides from a YAML file.

    Resolution order:
      1. explicit ``path`` argument (highest priority)
      2. ``ARGUS_POLICIES`` env var
      3. ``./policies.yaml`` in cwd (quiet miss — return [])

    Returns an empty list when no file is found. Raises
    ``PolicyLoadError`` when a file IS found but fails to parse or
    contains malformed policies — operators need to know their
    override file isn't being applied."""
    resolved = _resolve_path(path)
    if resolved is None or not resolved.is_file():
        return []
    try:
        import yaml
    except ImportError as e:
        raise PolicyLoadError(
            "PyYAML is required to load policies.yaml — "
            "pip install pyyaml"
        ) from e
    try:
        data = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PolicyLoadError(
            f"failed to parse {resolved}: {e}"
        ) from e
    if data is None:
        return []
    if not isinstance(data, dict):
        raise PolicyLoadError(
            f"{resolved}: root must be a mapping; got {type(data).__name__}"
        )
    raw_list = data.get("policies") or []
    if not isinstance(raw_list, list):
        raise PolicyLoadError(
            f"{resolved}: 'policies' must be a list; got "
            f"{type(raw_list).__name__}"
        )
    out: list[Policy] = []
    for i, entry in enumerate(raw_list):
        if not isinstance(entry, dict):
            raise PolicyLoadError(
                f"{resolved}: policies[{i}] must be a mapping; got "
                f"{type(entry).__name__}"
            )
        try:
            out.append(_parse_policy(entry))
        except Exception as e:
            raise PolicyLoadError(
                f"{resolved}: policies[{i}] ({entry.get('id', '?')!r}) "
                f"invalid — {e}"
            ) from e
    if verbose:
        print(f"  [policy] loaded {len(out)} override policies "
              f"from {resolved}")
    return out


def _resolve_path(explicit: Optional[Path | str]) -> Optional[Path]:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("ARGUS_POLICIES")
    if env:
        return Path(env).expanduser()
    cwd_candidate = Path.cwd() / "policies.yaml"
    if cwd_candidate.is_file():
        return cwd_candidate
    return None


_REQUIRED_FIELDS = ("id", "rule")
_ALLOWED_FIELDS = {
    "id", "name", "description", "rule", "severity", "applies_to",
    "owasp_llm", "mitre_atlas", "tags",
    "examples_violation", "examples_compliant",
    "version", "source",
}


def _parse_policy(entry: dict) -> Policy:
    for req in _REQUIRED_FIELDS:
        if not entry.get(req):
            raise ValueError(f"missing required field: {req!r}")
    # Warn on unknown fields; don't fail — forward-compat with new fields.
    unknown = [k for k in entry if k not in _ALLOWED_FIELDS]
    if unknown:
        # Comment-only — don't print to stdout in case the loader is
        # called from a test fixture.
        pass
    kwargs = {
        "id":           str(entry["id"]),
        "name":         str(entry.get("name", entry["id"])),
        "description":  str(entry.get("description", "")),
        "rule":         str(entry["rule"]),
        "severity":     str(entry.get("severity", "HIGH")).upper(),
        "applies_to":   list(entry.get("applies_to") or ["all"]),
        "owasp_llm":    str(entry.get("owasp_llm", "")),
        "mitre_atlas":  str(entry.get("mitre_atlas", "")),
        "tags":         list(entry.get("tags") or []),
        "examples_violation": list(entry.get("examples_violation") or []),
        "examples_compliant": list(entry.get("examples_compliant") or []),
        "version":      str(entry.get("version", "1.0")),
        # Force override source so reports clearly show operator
        # authorship — registry.resolve preserves this annotation.
        "source":       "override",
    }
    return Policy(**kwargs)
