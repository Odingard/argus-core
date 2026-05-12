"""Semantic diversity — keeps the variant pool from collapsing.

The genetic engine selects survivors greedily by fitness. Without a
diversity gate, three pathologies emerge:

1. **Local-maximum collapse.** All survivors cluster around the same
   payload shape because mutations preserving the shape always rank
   above mutations exploring elsewhere. Once collapsed, the engine
   has no way to escape — every child is a near-clone of every
   sibling.
2. **Cohort similarity.** Across independent runs, the same seed
   value produces near-identical populations because the search
   trajectory is determined by the static corpus's structural
   biases. Two runs that both find nothing fail in the *same way*.
3. **Wasted compute.** Firing 200 near-clones costs as much as
   firing 200 genuinely different variants but covers a tiny
   fraction of the attack surface.

This module supplies a deterministic min-hash / shingle sketch over
each variant's rendered payload and a :class:`DiversityGate` that
enforces a minimum Jaccard distance during selection. It is pure
arithmetic — no LLM, no random state across calls (AGENTS.md rule
#3 + rule #7). A temperature schedule helper produces a
deterministic high-T → low-T sequence the supervisor can hand to
mutator parameters during initial-population generation.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..core.variant import Variant

_TOKEN_RE = re.compile(r"\S+")

# Bounded shingle sizes — too small and noise dominates; too large
# and the sketch is sparse. k=4 is the standard text-similarity
# default and is what Phase O's tests pin.
_DEFAULT_SHINGLE_K = 4
_DEFAULT_SKETCH_SIZE = 64


def _variant_text(variant: Variant) -> str:
    """Deterministic flattening of a variant into a single string.

    Includes user-role content (the payload), tool descriptions, and
    a few resource hints. Excludes the variant_id / seed_id so two
    variants with the same payload sketch identically.
    """
    parts: list[str] = []
    for m in variant.messages:
        parts.append(f"{m.role}:{m.content}")
    for tool in variant.tools:
        parts.append(f"tool:{tool.name}:{tool.description}")
    for res in variant.resources:
        parts.append(f"res:{res.uri}:{res.description}")
    for doc in variant.rag_corpus:
        parts.append(f"rag:{doc}")
    if variant.carrier_surface:
        parts.append(f"carrier:{variant.carrier_surface}")
    return "\n".join(parts)


def shingle_set(text: str, *, k: int = _DEFAULT_SHINGLE_K) -> frozenset[str]:
    """Return the set of character k-shingles for ``text``.

    Deterministic. Lowercased. Whitespace collapsed so that two
    payloads that differ only in formatting hash to identical sets.
    Texts shorter than ``k`` chars produce a singleton set with the
    text itself.
    """
    if k <= 0:
        raise ValueError(f"shingle k must be > 0, got {k}")
    cleaned = " ".join(_TOKEN_RE.findall(text.lower()))
    if not cleaned:
        return frozenset()
    if len(cleaned) <= k:
        return frozenset({cleaned})
    return frozenset(cleaned[i : i + k] for i in range(len(cleaned) - k + 1))


def variant_shingle_set(variant: Variant, *, k: int = _DEFAULT_SHINGLE_K) -> frozenset[str]:
    """Convenience: shingle set of the variant's flattened text."""
    return shingle_set(_variant_text(variant), k=k)


def jaccard_distance(a: frozenset[str], b: frozenset[str]) -> float:
    """1.0 − Jaccard similarity. Two empty sets are *identical* (0.0).

    Bounded ``[0.0, 1.0]``. Symmetric. Deterministic.
    """
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    intersection = a & b
    similarity = len(intersection) / len(union)
    return max(0.0, min(1.0, 1.0 - similarity))


@dataclass(frozen=True, slots=True)
class VariantSketch:
    """Lightweight content sketch of one variant."""

    variant_id: str
    shingles: frozenset[str]
    minhash: tuple[int, ...]

    def jaccard_distance_to(self, other: VariantSketch) -> float:
        """Use the exact-shingle Jaccard when available — the minhash
        is only used for cheap pre-filtering inside the gate."""
        return jaccard_distance(self.shingles, other.shingles)


def _stable_minhash(shingles: frozenset[str], *, sketch_size: int = _DEFAULT_SKETCH_SIZE) -> tuple[int, ...]:
    """Deterministic min-hash sketch.

    For each of ``sketch_size`` hash slots, take the minimum of
    blake2b(shingle, salt=slot) over all shingles. Empty input
    returns an all-zero sketch (rule #9 — never None).
    """
    if not shingles:
        return (0,) * sketch_size
    sketch = [0xFFFFFFFFFFFFFFFF] * sketch_size
    for shingle in shingles:
        encoded = shingle.encode("utf-8")
        for slot in range(sketch_size):
            h = hashlib.blake2b(
                encoded,
                salt=slot.to_bytes(2, "big") + b"\x00" * 14,
                digest_size=8,
            )
            value = int.from_bytes(h.digest(), "big")
            if value < sketch[slot]:
                sketch[slot] = value
    return tuple(sketch)


def sketch_variant(
    variant: Variant,
    *,
    k: int = _DEFAULT_SHINGLE_K,
    sketch_size: int = _DEFAULT_SKETCH_SIZE,
) -> VariantSketch:
    """Pure function: variant → :class:`VariantSketch`."""
    shingles = variant_shingle_set(variant, k=k)
    return VariantSketch(
        variant_id=variant.variant_id,
        shingles=shingles,
        minhash=_stable_minhash(shingles, sketch_size=sketch_size),
    )


def minhash_similarity(a: VariantSketch, b: VariantSketch) -> float:
    """Approximate Jaccard via min-hash collision rate.

    Used as a fast O(sketch_size) pre-filter when the gate needs to
    sift large populations. The gate falls back to the exact-shingle
    Jaccard when the min-hash crosses the threshold (rule #9 — never
    silently approximate).
    """
    if not a.minhash or not b.minhash:
        return 0.0
    if len(a.minhash) != len(b.minhash):
        return 0.0
    matches = sum(1 for x, y in zip(a.minhash, b.minhash, strict=True) if x == y)
    return matches / len(a.minhash)


@dataclass(slots=True)
class DiversityGate:
    """Enforces a minimum Jaccard distance across an active pool.

    The gate has two responsibilities:

    * ``filter_pool`` — given a candidate list (typically genetic-
      engine offspring), keep only those that sit at least
      ``min_distance`` away from every variant already accepted.
      Returns the accepted list **and** a structured rejection
      record so the supervisor can emit an audit event per drop
      (AGENTS.md rule #9 — every empty result must be explainable).
    * ``temperature`` — produces a high→low schedule the seed
      generators can use to widen the initial population.

    The gate is stateful only across one ``filter_pool`` call — it
    does not accumulate sketches between calls. Callers that want
    cross-generation distance enforcement pass in the surviving
    pool explicitly via ``seed_sketches``.
    """

    min_distance: float = 0.3
    """Minimum Jaccard distance every accepted variant must keep
    from every other accepted variant. Lower = more permissive."""
    shingle_k: int = _DEFAULT_SHINGLE_K
    sketch_size: int = _DEFAULT_SKETCH_SIZE
    max_population: int | None = None
    """Optional hard cap on the accepted pool size. ``None`` means
    no cap (gate prunes only by distance)."""

    # Statistics maintained across the gate's lifetime so the
    # supervisor can surface them in reports.
    total_seen: int = field(default=0, init=False)
    total_accepted: int = field(default=0, init=False)
    total_rejected_distance: int = field(default=0, init=False)
    total_rejected_capacity: int = field(default=0, init=False)

    def filter_pool(
        self,
        candidates: Sequence[Variant],
        *,
        seed_sketches: Iterable[VariantSketch] | None = None,
    ) -> DiversityFilterResult:
        """Greedy pruning that preserves the highest-rank candidates.

        ``candidates`` is consumed *in order* — the supervisor
        therefore controls priority by passing children already
        sorted by fitness. The first candidate is always accepted
        (unless empty). Subsequent candidates are accepted only if
        their min-distance to *every* already-accepted sketch
        (including ``seed_sketches``) is ≥ ``min_distance``.
        """
        accepted_sketches: list[VariantSketch] = list(seed_sketches or [])
        accepted: list[Variant] = []
        rejected: list[DiversityRejection] = []

        for candidate in candidates:
            self.total_seen += 1
            sketch = sketch_variant(candidate, k=self.shingle_k, sketch_size=self.sketch_size)

            if self.max_population is not None and len(accepted) >= self.max_population:
                self.total_rejected_capacity += 1
                rejected.append(
                    DiversityRejection(
                        variant_id=candidate.variant_id,
                        reason="pool_capacity",
                        nearest_distance=None,
                        nearest_variant_id=None,
                    )
                )
                continue

            nearest_distance = 1.0
            nearest_id: str | None = None
            collided = False
            for existing in accepted_sketches:
                distance = sketch.jaccard_distance_to(existing)
                if distance < nearest_distance:
                    nearest_distance = distance
                    nearest_id = existing.variant_id
                if distance < self.min_distance:
                    collided = True
                    break

            if collided:
                self.total_rejected_distance += 1
                rejected.append(
                    DiversityRejection(
                        variant_id=candidate.variant_id,
                        reason="too_similar",
                        nearest_distance=nearest_distance,
                        nearest_variant_id=nearest_id,
                    )
                )
                continue

            accepted.append(candidate)
            accepted_sketches.append(sketch)
            self.total_accepted += 1

        return DiversityFilterResult(
            accepted=tuple(accepted),
            rejected=tuple(rejected),
            accepted_sketches=tuple(accepted_sketches),
        )

    def temperature(self, *, generation: int, max_generations: int) -> float:
        """Deterministic high-T → low-T schedule.

        Linear annealing from ``1.0`` at generation 0 to ``0.1`` at
        ``max_generations``. Values clamped to ``[0.1, 1.0]``. Used
        by mutator stages that accept a temperature parameter (e.g.
        the encoding mutator picks a wider alphabet at high T).
        """
        if max_generations <= 0:
            return 1.0
        progress = min(1.0, max(0.0, generation / max_generations))
        return max(0.1, 1.0 - 0.9 * progress)

    def stats(self) -> dict[str, Any]:
        """Lifetime statistics for the report renderer.

        Canonical keys consumed by
        :mod:`reporting.jsonl_reader` / HTML / Markdown:

        * ``observed`` — total candidates fed through ``filter_pool``.
        * ``accepted`` — kept (sit ≥ ``min_distance`` from every peer).
        * ``rejected`` — total dropped (sum of both reasons below).
        * ``rejected_distance`` — dropped because too similar to an
          already-accepted peer (the pool-collapse path).
        * ``rejected_capacity`` — dropped because the
          ``max_population`` cap was hit before they could compete.
        * ``min_distance`` — gate threshold for audit-trail context.
        """
        return {
            "min_distance": self.min_distance,
            "observed": self.total_seen,
            "accepted": self.total_accepted,
            "rejected": self.total_rejected_distance + self.total_rejected_capacity,
            "rejected_distance": self.total_rejected_distance,
            "rejected_capacity": self.total_rejected_capacity,
        }


@dataclass(frozen=True, slots=True)
class DiversityRejection:
    """One audit row per variant the gate dropped (AGENTS.md rule #9)."""

    variant_id: str
    reason: str
    nearest_distance: float | None
    nearest_variant_id: str | None


@dataclass(frozen=True, slots=True)
class DiversityFilterResult:
    """Outcome of one :meth:`DiversityGate.filter_pool` call."""

    accepted: tuple[Variant, ...]
    rejected: tuple[DiversityRejection, ...]
    accepted_sketches: tuple[VariantSketch, ...]

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)


__all__ = [
    "DiversityFilterResult",
    "DiversityGate",
    "DiversityRejection",
    "VariantSketch",
    "jaccard_distance",
    "minhash_similarity",
    "shingle_set",
    "sketch_variant",
    "variant_shingle_set",
]
