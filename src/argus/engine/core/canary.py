"""Canary token generation and matching primitives.

A canary is a deterministic token whose echo in a target's response (or in the
arguments of a downstream tool / OOB endpoint) constitutes IRREFUTABLE
evidence that an attack landed.

Canaries are derived from a 64-bit seed so the same generator run produces the
same canary set; this is what makes the framework reproducible.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

CANARY_PREFIX = "ARGT-CANARY"
CANARY_RE = re.compile(r"ARGT-CANARY-[A-Z0-9]{8,16}")


def make_canary(seed_value: int, label: str) -> str:
    """Produce a deterministic canary token for ``label`` under ``seed_value``."""
    digest = hashlib.blake2b(f"{seed_value}:{label}".encode(), digest_size=8, key=b"argus-engine").hexdigest()
    return f"{CANARY_PREFIX}-{digest.upper()}"


def make_secret_canary(label: str) -> str:
    """A non-deterministic canary; used for OOB beacons during a single live run."""
    return f"{CANARY_PREFIX}-{secrets.token_hex(6).upper()}"


@dataclass(frozen=True, slots=True)
class CanarySet:
    """The full set of canaries a single variant carries."""

    primary: str
    secondary: tuple[str, ...] = ()

    def all(self) -> tuple[str, ...]:
        return (self.primary, *self.secondary)

    def hits(self, body: str) -> tuple[str, ...]:
        if not body:
            return ()
        return tuple(c for c in self.all() if c in body)


def signature(seed_value: int, payload: str | bytes) -> str:
    """Return an HMAC signature of ``payload`` keyed on the seed.

    Used by matchers when the payload itself is unsuitable as a canary
    (e.g. binary blobs, image metadata) — the matcher checks for the
    signature in callbacks rather than the raw payload.
    """
    if isinstance(payload, str):
        payload = payload.encode()
    return hmac.new(str(seed_value).encode(), payload, hashlib.blake2s).hexdigest()[:16]
