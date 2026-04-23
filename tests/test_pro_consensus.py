"""
tests/test_pro_consensus.py — PRO tier consensus gate.

Two concerns exercised:

1. Core behavioural contract — N-of-M agreement works, downgrades
   follow the explicit severity ladder, votes below threshold
   drop one severity band with an annotation that names the
   consensus count.

2. License-seam contract — the module imports cleanly under the
   permissive stub today and raises LicenseError the moment the
   stub tightens. We simulate "tightened" by monkey-patching
   `argus.license.has` to return False and verify the next
   import path fails loudly.
"""
from __future__ import annotations

import importlib
import sys

import pytest

from argus.pro.consensus import (
    ConsensusVerdict, require_agreement,
)


# ── Core N-of-M behaviour ────────────────────────────────────────────────────

def test_three_of_three_agreement_preserves_critical():
    v = require_agreement("CRITICAL",
                          ["CRITICAL", "CRITICAL", "CRITICAL"])
    assert v.agreed_severity == "CRITICAL"
    assert not v.downgraded
    assert v.agreement_count == 3
    assert "3/3" in v.annotation


def test_two_of_three_agreement_preserves_critical():
    v = require_agreement("CRITICAL",
                          ["CRITICAL", "HIGH", "CRITICAL"],
                          min_agreement=2)
    assert v.agreed_severity == "CRITICAL"
    assert not v.downgraded


def test_one_of_three_downgrades_critical_to_high():
    v = require_agreement("CRITICAL",
                          ["CRITICAL", "HIGH", "MEDIUM"],
                          min_agreement=2)
    assert v.agreed_severity == "HIGH"
    assert v.downgraded
    assert "downgraded from CRITICAL" in v.annotation
    assert "1/3" in v.annotation


def test_zero_agreement_still_downgrades_one_band():
    """Even if no judge agrees, downgrade is ONE band — not collapsed
    to INFO. The finding survived to judging, which itself is signal."""
    v = require_agreement("HIGH",
                          ["MEDIUM", "MEDIUM", "LOW"])
    assert v.agreed_severity == "MEDIUM"


def test_low_stays_low_when_downgraded():
    v = require_agreement("LOW", ["INFO"], min_agreement=2)
    assert v.agreed_severity == "LOW"


def test_verdict_is_hashable_immutable():
    v = require_agreement("HIGH", ["HIGH", "HIGH"])
    # frozen dataclass → hashable
    assert hash(v) == hash(v)
    with pytest.raises(Exception):
        v.agreement_count = 999  # type: ignore[misc]


# ── License-seam contract ────────────────────────────────────────────────────

def test_module_imports_under_permissive_stub():
    """Today the license stub permits everything — the module must
    import cleanly on a default install."""
    import argus.pro.consensus as mod
    assert hasattr(mod, "require_agreement")


def test_tightened_license_raises_on_import(monkeypatch):
    """Simulate what happens when the license stub flips to real
    verification and the caller has no token."""
    import argus.license as lic
    monkeypatch.setattr(lic, "has", lambda feature: False)

    # Force a re-import — module cache holds the permissive version.
    sys.modules.pop("argus.pro.consensus", None)
    with pytest.raises(lic.LicenseError) as exc:
        importlib.import_module("argus.pro.consensus")
    assert "consensus" in str(exc.value).lower()
