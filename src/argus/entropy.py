"""
argus/entropy.py — Engagement Seed / Logged Entropy Orchestration

The Reproducibility Paradox, solved.

Discovery Phase: High entropy. Every agent interaction draws a unique
sub-seed derived from a master engagement seed. The swarm explores
different probability timelines of the target's stochastic behavior
on every run.

Validation Phase: The operator pins the master seed that produced a
confirmed finding. ARGUS replays the exact sub-seeds that generated
the exploit, producing a reproducible PoC from entropy.

Architecture
────────────
                        EngagementSeed (master)
                              │
              ┌───────────────┼───────────────┐
              │               │               │
        PI-01 sub-seed  EP-11 sub-seed  ME-10 sub-seed
              │               │               │
        variant_1 seed  technique seed  probe_1 seed
        variant_2 seed  ...             probe_2 seed

Every sub-seed is:
    HMAC-SHA256(master_seed + agent_id + interaction_index)[:8]
    → deterministic from master, unique per interaction

On finding confirmation, the finding carries:
    engagement_seed: <master hex>
    agent_sub_seed:  <agent-specific hex>

Replay:
    ARGUS_PIN_SEED=<master_hex> argus engage <target>
    → identical sub-seeds, identical attack path, reproducible PoC

Usage
─────
    # In runner — one seed per engagement
    seed = EngagementSeed.new()          # fresh entropy
    seed = EngagementSeed.pin("abc123")  # pinned replay

    # In agents
    agent_seed = seed.agent_seed("PI-01")
    variant_seed = seed.interaction_seed("PI-01", 0)   # variant 0
    variant_seed = seed.interaction_seed("PI-01", 7)   # variant 7

    # Attach to finding
    seed.stamp_finding(finding, agent_id="PI-01")
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── EngagementSeed ────────────────────────────────────────────────────────────

class EngagementSeed:
    """Master entropy source for one ARGUS engagement.

    All sub-seeds are deterministic functions of the master.
    The master itself is either fresh OS entropy (discovery) or
    a pinned hex string (replay/validation).
    """

    def __init__(self, master: bytes) -> None:
        if len(master) != 32:
            raise ValueError("master seed must be 32 bytes")
        self._master = master

    @classmethod
    def new(cls) -> "EngagementSeed":
        """Fresh OS entropy — discovery phase."""
        return cls(os.urandom(32))

    @classmethod
    def pin(cls, hex_seed: str) -> "EngagementSeed":
        """Replay a previous engagement from its hex master seed."""
        raw = bytes.fromhex(hex_seed.strip())
        if len(raw) != 32:
            raise ValueError(
                f"Pinned seed must be 64 hex chars (32 bytes); "
                f"got {len(raw)} bytes from {hex_seed!r}"
            )
        return cls(raw)

    @classmethod
    def from_env(cls) -> "EngagementSeed":
        """Read ARGUS_PIN_SEED env var — pins if set, else fresh entropy."""
        pin = os.environ.get("ARGUS_PIN_SEED", "").strip()
        if pin:
            return cls.pin(pin)
        return cls.new()

    def _derive(self, *parts: str | int) -> bytes:
        """HMAC-SHA256(master, concat(parts)) — 32-byte sub-key."""
        msg = b"|".join(
            p.encode() if isinstance(p, str)
            else struct.pack(">Q", p)
            for p in parts
        )
        return hmac.new(self._master, msg, hashlib.sha256).digest()

    def agent_seed(self, agent_id: str) -> int:
        """Stable integer seed for a specific agent."""
        raw = self._derive("agent", agent_id)
        return int.from_bytes(raw[:8], "big")

    def interaction_seed(self, agent_id: str, interaction_index: int) -> int:
        """Stable integer seed for one interaction within an agent.

        agent_id="PI-01", interaction_index=0  → seed for variant 0
        agent_id="PI-01", interaction_index=7  → seed for variant 7

        Use as the seed= argument to corpus.sample() or any RNG.
        """
        raw = self._derive("interaction", agent_id, interaction_index)
        return int.from_bytes(raw[:8], "big")

    def technique_seed(self, agent_id: str, technique_id: str) -> int:
        """Stable integer seed for a (agent, technique) pair."""
        raw = self._derive("technique", agent_id, technique_id)
        return int.from_bytes(raw[:8], "big")

    @property
    def hex(self) -> str:
        """64-char hex string — log this, pin with this."""
        return self._master.hex()

    @property
    def short(self) -> str:
        """First 8 chars — for operator display."""
        return self._master.hex()[:8]

    def stamp_finding(self, finding, *, agent_id: str) -> None:
        """Attach seed provenance to a finding for replay.

        Sets:
            finding.engagement_seed  — master hex (64 chars)
            finding.agent_sub_seed   — agent-specific hex (16 chars)
        """
        agent_raw = self._derive("agent", agent_id)
        finding.engagement_seed = self.hex
        finding.agent_sub_seed  = agent_raw[:8].hex()

    def __repr__(self) -> str:
        return f"EngagementSeed({self.short}…)"


# ── SeedLedger ────────────────────────────────────────────────────────────────

@dataclass
class SeedLedgerEntry:
    agent_id:          str
    interaction_index: int
    seed_int:          int
    seed_hex:          str
    used_at:           str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    produced_finding:  bool = False
    finding_id:        Optional[str] = None


@dataclass
class SeedLedger:
    """Records every sub-seed used in an engagement.

    Written to {run_dir}/seed_ledger.json at end of run.
    Operators audit which seeds produced which findings and pin
    the exact sub-seeds that triggered an exploit.
    """
    engagement_seed:  str
    engagement_short: str
    entries: list[SeedLedgerEntry] = field(default_factory=list)

    def record(
        self,
        agent_id: str,
        interaction_index: int,
        seed_int: int,
        *,
        produced_finding: bool = False,
        finding_id: Optional[str] = None,
    ) -> None:
        self.entries.append(SeedLedgerEntry(
            agent_id=agent_id,
            interaction_index=interaction_index,
            seed_int=seed_int,
            seed_hex=hex(seed_int),
            produced_finding=produced_finding,
            finding_id=finding_id,
        ))

    def mark_finding(self, finding_id: str, agent_id: str) -> None:
        """Mark entries from agent_id as having produced a finding."""
        for e in reversed(self.entries):
            if e.agent_id == agent_id and not e.produced_finding:
                e.produced_finding = True
                e.finding_id = finding_id
                break

    def to_dict(self) -> dict:
        return {
            "engagement_seed":  self.engagement_seed,
            "engagement_short": self.engagement_short,
            "pin_command": (
                f"ARGUS_PIN_SEED={self.engagement_seed} "
                f"argus engage <target> --output <dir>"
            ),
            "total_interactions": len(self.entries),
            "findings_count": sum(1 for e in self.entries if e.produced_finding),
            "entries": [asdict(e) for e in self.entries],
        }

    def write(self, run_dir: str) -> Path:
        out = Path(run_dir) / "seed_ledger.json"
        out.write_text(
            json.dumps(self.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        return out
