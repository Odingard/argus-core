"""
tests/test_entropy.py — EngagementSeed + SeedLedger.

Covers:
  - Fresh entropy uniqueness
  - Deterministic sub-seed derivation from same master
  - Pin/replay via hex and ARGUS_PIN_SEED env var
  - Per-agent, per-interaction, per-technique isolation
  - stamp_finding attaches provenance
  - SeedLedger write/read round-trip + pin command
"""
import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest

from argus.entropy import EngagementSeed, SeedLedger


# ── Construction ──────────────────────────────────────────────────────────────

def test_new_seeds_are_unique():
    assert EngagementSeed.new().hex != EngagementSeed.new().hex


def test_pin_reproduces_master():
    s = EngagementSeed.new()
    assert EngagementSeed.pin(s.hex).hex == s.hex


def test_pin_wrong_length_raises():
    with pytest.raises(ValueError):
        EngagementSeed.pin("deadbeef")  # 4 bytes, not 32


def test_pin_invalid_hex_raises():
    with pytest.raises(Exception):
        EngagementSeed.pin("not_valid_hex_at_all!!!")


def test_from_env_without_pin_is_fresh():
    os.environ.pop("ARGUS_PIN_SEED", None)
    assert EngagementSeed.from_env().hex != EngagementSeed.from_env().hex


def test_from_env_with_pin_replays():
    s = EngagementSeed.new()
    os.environ["ARGUS_PIN_SEED"] = s.hex
    try:
        assert EngagementSeed.from_env().hex == s.hex
    finally:
        os.environ.pop("ARGUS_PIN_SEED", None)


# ── Sub-seed derivation ───────────────────────────────────────────────────────

def test_agent_seeds_differ_per_agent():
    s = EngagementSeed.new()
    assert s.agent_seed("PI-01") != s.agent_seed("EP-11")
    assert s.agent_seed("ME-10") != s.agent_seed("SC-09")


def test_agent_seed_is_deterministic():
    s = EngagementSeed.new()
    pinned = EngagementSeed.pin(s.hex)
    assert s.agent_seed("PI-01") == pinned.agent_seed("PI-01")


def test_interaction_seeds_all_unique():
    s = EngagementSeed.new()
    seeds = [s.interaction_seed("PI-01", i) for i in range(10)]
    assert len(set(seeds)) == 10


def test_interaction_seed_is_deterministic():
    s = EngagementSeed.new()
    pinned = EngagementSeed.pin(s.hex)
    assert s.interaction_seed("PI-01", 7) == pinned.interaction_seed("PI-01", 7)


def test_technique_seed_is_deterministic():
    s = EngagementSeed.new()
    pinned = EngagementSeed.pin(s.hex)
    assert (s.technique_seed("EP-11", "EP-T12-shell-injection") ==
            pinned.technique_seed("EP-11", "EP-T12-shell-injection"))


def test_different_agents_different_interaction_seeds():
    s = EngagementSeed.new()
    assert (s.interaction_seed("PI-01", 0) !=
            s.interaction_seed("EP-11", 0))


# ── Properties ───────────────────────────────────────────────────────────────

def test_hex_is_64_chars():
    assert len(EngagementSeed.new().hex) == 64


def test_short_is_8_chars():
    assert len(EngagementSeed.new().short) == 8


def test_short_is_prefix_of_hex():
    s = EngagementSeed.new()
    assert s.hex.startswith(s.short)


# ── stamp_finding ─────────────────────────────────────────────────────────────

def test_stamp_attaches_master_and_sub_seed():
    s = EngagementSeed.new()
    f = MagicMock()
    f.engagement_seed = ""
    f.agent_sub_seed = ""
    s.stamp_finding(f, agent_id="EP-11")
    assert f.engagement_seed == s.hex
    assert len(f.agent_sub_seed) == 16   # 8 bytes as hex


def test_stamp_different_agents_different_sub_seeds():
    s = EngagementSeed.new()
    f1, f2 = MagicMock(), MagicMock()
    for f in (f1, f2):
        f.engagement_seed = f.agent_sub_seed = ""
    s.stamp_finding(f1, agent_id="PI-01")
    s.stamp_finding(f2, agent_id="EP-11")
    assert f1.agent_sub_seed != f2.agent_sub_seed
    assert f1.engagement_seed == f2.engagement_seed  # same master


def test_stamp_is_deterministic_with_pin():
    s = EngagementSeed.new()
    pinned = EngagementSeed.pin(s.hex)
    f1, f2 = MagicMock(), MagicMock()
    for f in (f1, f2):
        f.engagement_seed = f.agent_sub_seed = ""
    s.stamp_finding(f1, agent_id="EP-11")
    pinned.stamp_finding(f2, agent_id="EP-11")
    assert f1.agent_sub_seed == f2.agent_sub_seed


# ── SeedLedger ────────────────────────────────────────────────────────────────

def test_ledger_record_and_write():
    s = EngagementSeed.new()
    ledger = SeedLedger(engagement_seed=s.hex, engagement_short=s.short)
    ledger.record("PI-01", 0, 12345)
    ledger.record("EP-11", 3, 67890, produced_finding=True, finding_id="abc123")

    with tempfile.TemporaryDirectory() as d:
        path = ledger.write(d)
        assert path.exists()
        data = json.loads(path.read_text())

    assert data["engagement_seed"] == s.hex
    assert data["findings_count"] == 1
    assert "pin_command" in data
    assert s.hex in data["pin_command"]
    assert "argus engage" in data["pin_command"]
    assert data["total_interactions"] == 2


def test_ledger_mark_finding_retroactive():
    s = EngagementSeed.new()
    ledger = SeedLedger(engagement_seed=s.hex, engagement_short=s.short)
    ledger.record("EP-11", 0, 111)
    ledger.record("EP-11", 1, 222)
    ledger.mark_finding("finding_xyz", "EP-11")
    marked = [e for e in ledger.entries if e.produced_finding]
    assert len(marked) == 1
    assert marked[0].finding_id == "finding_xyz"
    assert marked[0].seed_int == 222  # most recent EP-11 entry


def test_ledger_findings_count():
    s = EngagementSeed.new()
    ledger = SeedLedger(engagement_seed=s.hex, engagement_short=s.short)
    ledger.record("EP-11", 0, 1, produced_finding=True, finding_id="f1")
    ledger.record("EP-11", 1, 2, produced_finding=True, finding_id="f2")
    ledger.record("PI-01", 0, 3)
    d = ledger.to_dict()
    assert d["findings_count"] == 2


def test_empty_ledger_writes_cleanly():
    s = EngagementSeed.new()
    ledger = SeedLedger(engagement_seed=s.hex, engagement_short=s.short)
    with tempfile.TemporaryDirectory() as d:
        path = ledger.write(d)
        data = json.loads(path.read_text())
    assert data["total_interactions"] == 0
    assert data["findings_count"] == 0
