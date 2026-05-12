"""In-memory data model for the Phase M offline report renderers.

All structures are :class:`~dataclasses.dataclass` with ``frozen=True``
+ ``slots=True`` so they are hashable, deterministic, and cheap to
construct in tight loops over JSONL events.

Confidence tiers follow the AGENTS.md ladder
(``IRREFUTABLE`` / ``HIGH`` / ``MEDIUM`` / ``LOW``). The renderers
only headline ``IRREFUTABLE`` + ``HIGH`` per AGENTS.md (medium /
low are surfaced in the detail tables but not in the executive
summary card).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

# AGENTS.md confidence ladder. Sort order matters — the HTML / Markdown
# renderers iterate this tuple to keep tier presentation stable across
# runs (AGENTS.md rule #7 — deterministic output).
TIER_ORDER: Final[tuple[str, ...]] = ("IRREFUTABLE", "HIGH", "MEDIUM", "LOW")

# Public-facing headline tiers (AGENTS.md confidence-ladder docs).
HEADLINE_TIERS: Final[frozenset[str]] = frozenset({"IRREFUTABLE", "HIGH"})


@dataclass(frozen=True, slots=True)
class RunMetadata:
    """Engagement-level metadata extracted from the JSONL preamble."""

    target: str
    """Target endpoint URL or model identifier."""
    transport: str
    """Transport name (``openai`` / ``anthropic`` / ``ollama`` / ``argt`` / ``auto``)."""
    layer: str
    """Layer slug (e.g. ``layer2_contextual_injection``) the engagement
    primarily targeted. Reported verbatim from the ``done`` event."""
    seed: int
    """Deterministic seed value (AGENTS.md rule #7)."""
    duration_seconds: float
    """Wall-clock duration captured by the ``done`` event."""
    total_fired: int
    """Total variant fires across all classes."""
    total_findings: int
    """Total findings (any confidence tier)."""
    rehydrated: bool = False
    """True iff the engagement warm-started from EngagementMemory."""
    target_fingerprint_id: str | None = None
    """Fingerprint id if the engagement rehydrated (Phase J)."""


@dataclass(frozen=True, slots=True)
class FindingRow:
    """A single landed finding above the LOW tier."""

    variant_id: str
    attack_class: str
    confidence: str
    lethality: float
    phase: str
    """``probing`` / ``exploitation`` / ``chain_synthesis`` / etc."""
    generation: int
    """Genetic generation (0 = seed)."""
    evidence: dict[str, object] = field(default_factory=dict)
    """Matcher-emitted evidence dict — opaque to the renderers, dumped
    verbatim into the HTML evidence panel."""

    @property
    def is_headline(self) -> bool:
        return self.confidence in HEADLINE_TIERS


@dataclass(frozen=True, slots=True)
class ClassRollup:
    """Per-attack-class aggregated counts."""

    attack_class: str
    fired: int
    landed: int
    """Number of fire events that produced at least one finding (any tier).

    Bounded by ``fired`` so :attr:`landed_rate` is always in ``[0.0, 1.0]``.
    For a per-tier breakdown (which can exceed ``fired`` when a single fire
    produces multiple findings) consult :attr:`tier_counts`.
    """
    tier_counts: dict[str, int]
    """Mapping of confidence tier → count. Empty tiers are absent."""
    top_lethality: float
    """Maximum lethality score observed across the class's fires."""

    @property
    def headline_count(self) -> int:
        """Count of IRREFUTABLE + HIGH findings (the only tiers
        AGENTS.md surfaces in external reports)."""
        return sum(self.tier_counts.get(t, 0) for t in HEADLINE_TIERS)

    @property
    def landed_rate(self) -> float:
        """Landed-over-fired ratio (rule #10 — observable rate)."""
        if self.fired == 0:
            return 0.0
        return self.landed / self.fired


@dataclass(frozen=True, slots=True)
class RefusalRow:
    """Aggregated refusal-signature hit."""

    signature: str
    occurrences: int


@dataclass(frozen=True, slots=True)
class FallbackEvent:
    """Recon-plausibility fallback (X8 gate) audit row.

    AGENTS.md rule #9: never silently drop a fallback — it explains
    why a recon-aware class fell back to the baseline arm and how
    the X8 gate scored the two variants.
    """

    attack_class: str
    recon_variant_id: str
    baseline_variant_id: str
    recon_score: float
    baseline_score: float
    margin: float


@dataclass(frozen=True, slots=True)
class ChainEmergenceLink:
    """One producer→consumer hop emitted by Phase J's emergence log."""

    chain_id: str
    producer_class: str
    consumer_class: str
    slot: str
    """Slot the producer populated (e.g. ``leaked_credentials``) that
    unlocked the consumer."""
    landed: bool


@dataclass(frozen=True, slots=True)
class EngagementReport:
    """Pure, fully-populated view of one engagement run.

    Built by :func:`reporting.jsonl_reader.parse_jsonl`. Both the HTML
    and Markdown renderers operate on this struct and nothing else,
    keeping rendering logic free of any I/O or parsing concerns.
    """

    metadata: RunMetadata
    classes: tuple[ClassRollup, ...]
    """Sorted by ``attack_class`` ascending."""
    findings: tuple[FindingRow, ...]
    """Sorted by (tier rank, attack_class, variant_id). Tier rank is
    the position in :data:`TIER_ORDER` — IRREFUTABLE first."""
    refusals: tuple[RefusalRow, ...]
    """Sorted by descending occurrences then signature ascending."""
    fallbacks: tuple[FallbackEvent, ...]
    """Sorted by attack_class ascending, then recon_variant_id."""
    emergence_links: tuple[ChainEmergenceLink, ...]
    """Sorted by chain_id ascending, then producer_class."""

    signal_strength_summary: dict[str, float] = field(default_factory=dict)
    """Phase N — aggregate statistics over the continuous-gradient
    ``signal_strength`` score emitted by every fire. Empty when the
    run pre-dates Phase N or signal scoring was disabled. Keys:
    ``count``, ``mean``, ``max``, ``p50``, ``p90``, ``p99``. Even
    a run with zero canary landings now has a non-empty summary
    answering 'how close did the engine get' (AGENTS.md rule #9 —
    no silent failures: empty findings must be explainable)."""
    diversity_stats: dict[str, int] = field(default_factory=dict)
    """Phase O — :class:`DiversityGate` rejection telemetry.
    Keys: ``accepted``, ``rejected``, ``observed``. Surfaces 'the
    population was collapsing — gate pruned N%' in the report."""
    carrier_histogram: dict[str, int] = field(default_factory=dict)
    """Phase P — count of fires per carrier surface
    (``user_turn`` / ``tool_result`` / ``rag_document`` /
    ``roleplay_persona`` / ``system_reflection``). Lets reports
    show 'L3 ran 80% user_turn, 20% rag_document' so we can see
    which trust surfaces are actually being exercised."""
    arc_summary: dict[str, object] = field(default_factory=dict)
    """Phase Q — ARGT multi-call arc-progression aggregate from
    :func:`runtime.arc_planner.summarise_arc_outcomes`. Keys:
    ``arcs``, ``completed``, ``aborted``, ``total_rewinds``,
    ``stage_reach_counts``."""

    @property
    def headline_findings(self) -> tuple[FindingRow, ...]:
        return tuple(f for f in self.findings if f.is_headline)

    @property
    def overall_tier_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
        return counts
