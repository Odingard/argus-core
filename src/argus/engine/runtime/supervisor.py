"""Supervisor — the autonomous engagement controller.

Implements the Supervisor-Worker-Auditor pattern:

  **Supervisor** (this module):
    Reads the recon manifest → selects attack classes → manages the genetic
    loop → handles refusal-based adaptation → decides phase transitions.
    Uses an LLM for strategic planning ONLY; grading is deterministic.

  **Worker** (Tier-B generators):
    High-speed deterministic variant generation per attack class.

  **Auditor** (Tier-C arbitrator):
    Deterministic canary-echo + behavioral-drift + state-machine verdicts.

The Supervisor runs the full engagement lifecycle from ``run()`` — no human
touches the Go button after the initial manifest/URL is provided.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.chain_graph import ChainGraph
from ..core.chain_synth import beam_search, default_chain_graph
from ..core.recon_profile import ReconProfile
from ..core.registry import get
from ..core.types import LayerId
from ..core.variant import Variant
from ..grading.arbitrator import Arbitrator
from ..grading.matcher import ProbeResult, Verdict
from ..grading.signal_strength import (
    SignalStrength,
    SignalStrengthScorer,
    aggregate_signal_stats,
    extract_intent_tokens,
)
from ..recon.mcp_introspect import TargetManifest
from ..transports.base import Transport
from .arc_planner import ArcExecutionResult, summarise_arc_outcomes
from .chain_runner import ChainResult, execute_chain
from .emergence_report import EmergenceLog, build_emergence_report
from .engagement_memory import (
    EngagementMemory,
    EngagementMemoryEntry,
    TargetFingerprint,
    TrustMarker,
    compute_target_fingerprint,
    filter_persistable_recon,
    merge_trust_markers,
    normalise_trust_value,
)
from .genetic import GeneticEngine, ScoredVariant
from .refusal_kb import RefusalKB
from .reward import BreachMetric, DeviationScore, ShadowModel
from .strategy import EngagementPhase, StrategyNavigator

logger = logging.getLogger("argus.engine.supervisor")


@dataclass(frozen=True, slots=True)
class Finding:
    """A confirmed finding (IRREFUTABLE or HIGH).

    ``signal_strength`` is the Phase N continuous-gradient signal
    captured at firing time (composite of boundary_softening,
    topic_acknowledgment, partial_leak, model_confusion). Always
    present so the report renderer can surface "near-miss" gradient
    even on landed findings; ``None`` only when scoring was disabled
    (back-compat for pre-Phase-N callers).
    """

    variant_id: str
    attack_class: str
    verdict: Verdict
    lethality: float
    evidence: dict[str, Any] = field(default_factory=dict)
    generation: int = 0
    signal_strength: SignalStrength | None = None


@dataclass(frozen=True, slots=True)
class EngagementReport:
    """Final output of an autonomous engagement."""

    findings: tuple[Finding, ...] = ()
    total_variants_fired: int = 0
    generations: int = 0
    phases_traversed: tuple[str, ...] = ()
    duration_seconds: float = 0.0
    refusal_kb_size: int = 0
    strategy_summary: dict[str, Any] = field(default_factory=dict)
    rehydrated: bool = False
    """True iff a non-expired :class:`EngagementMemoryEntry` was found
    for this target and seeded into ``RefusalKB`` / recon profile /
    trust-marker pool. False on cold cache, expired entry, or when no
    memory was configured. Surfaced so callers can tell why a run
    started warm vs cold without having to compare timestamps."""

    target_fingerprint: TargetFingerprint | None = None
    """The fingerprint used to key the engagement memory, when
    available. ``None`` when no memory was configured."""

    emergence_log: EmergenceLog | None = None
    """Aggregated chain emergence reports, when ``chain_phase`` is
    enabled. ``None`` for non-chain engagements; an empty
    :class:`EmergenceLog` when chain phase ran but produced no
    landings."""

    signal_strength_stats: dict[str, Any] = field(default_factory=dict)
    """Phase N — aggregate statistics over every continuous-gradient
    signal sample collected during the run. Keys: ``count``, ``mean``,
    ``max``, ``p50``, ``p90``, plus per-sub-signal means. Empty dict
    when scoring was disabled. Renderers consume this to surface
    \"how close did the engine get?\" even when no canary fired."""

    diversity_stats: dict[str, Any] = field(default_factory=dict)
    """Phase O — aggregate gate stats: ``inspected`` / ``accepted`` /
    ``rejected`` / ``rejection_rate`` plus the gate's configuration
    (``shingle_k``, ``sketch_size``, ``min_jaccard_distance``). Empty
    when the gate was disabled. Surfaces \"the population collapsed
    and the gate pruned N%\" in the report renderer."""

    carrier_histogram: dict[str, int] = field(default_factory=dict)
    """Phase P — count of fires per carrier surface (``user_turn`` /
    ``tool_result`` / ``rag_document`` / ``roleplay_persona`` /
    ``system_reflection``). Always populated when fires happen, even
    if all rides default to ``user_turn`` — the histogram is the
    audit trail showing exactly which surfaces the engine
    exercised."""

    arc_summary: dict[str, Any] = field(default_factory=dict)
    """Phase Q — per-arc summary aggregated across ARGT multi-call
    runs: total arcs, completed arcs, refusals-per-stage histogram,
    rewinds-used histogram. Empty when no arc planner was active."""


EventCallback = Callable[[dict[str, Any]], None]
"""Event hook invoked by the Supervisor at every observable runtime event.

Events have a ``type`` key (one of: ``phase``, ``fire``, ``finding``,
``refusal``, ``thought``, ``mutation``, ``done``) plus type-specific fields.
The CLI / TUI subscribes via this hook; emission is best-effort and never
allowed to disrupt the engagement loop.
"""


@dataclass(slots=True)
class Supervisor:
    """Autonomous engagement controller."""

    transport: Transport
    manifest: TargetManifest
    shadow: ShadowModel
    layer: LayerId = "layer1_tool_poisoning"
    seed_value: int = 42
    max_variants_per_class: int = 200
    max_total_variants: int = 2000
    max_generations: int = 5
    concurrency: int = 16
    """Max concurrent in-flight fires per class. Bounded so we don't DDOS
    the target. 16 is a safe default for hosted endpoints; raise for local
    Ollama where the bottleneck is GPU throughput, not network."""
    early_stop_after: int = 30
    """Per-class: if this many fires happen with zero drift signal AND the
    refusal KB has stopped growing, exit the class early and reroute the
    remaining budget. Set to 0 to disable."""
    kb_short_circuit_threshold: float = 0.55
    """Skip-fire any variant whose payload overlaps known-refusal vocabulary
    above this threshold. The genetic engine reclaims those budget slots
    for novel mutations. Set to 1.0 to disable."""
    on_event: EventCallback | None = None
    recon: ReconProfile | None = None
    """Optional recon profile applied to every adopting class.

    When provided, ``ReconProfile.from_manifest(self.manifest)`` is merged in
    automatically so manifest-side artefacts (tool names, resource URIs,
    parameter keys, prompt names, transport hints) are always available even
    if the caller only supplies a partial profile.
    """
    recon_aware_classes: frozenset[str] = frozenset()
    """Per-class allowlist for recon-aware variant substitution.

    Default empty — the supervisor calls ``attack_class.factory(seed_value)``
    without ``recon=`` for every class, regardless of the class' static
    ``recon_aware`` flag. This is bit-identical to the pre-PR-#13 behaviour
    and matches the ``recon=OFF`` arm of every live-fire A/B run so far.

    A class flips on by being added to this frozenset only after its Path 1
    neutral-framing mutator has cleared the AGENTS.md rule #10 live-fire
    gate (≥5pp uplift over ``recon=OFF`` baseline on at least one
    shape-appropriate target). The allowlist replaces the cruder PR #15
    boolean ``recon_aware_enabled`` because every flip-on is a per-class
    decision; "all 10 classes on, no exceptions" is never the right
    setting again. Path 2 plausibility-gating (deterministic
    ``RefusalKB.would_likely_refuse`` delta with ``recon_plausibility_margin``)
    runs on every allowlisted class as a per-variant safety belt.
    """
    recon_plausibility_margin: float = 0.1
    """Margin in the plausibility gate that triggers fallback to baseline.

    A recon-substituted variant is fired only if its
    ``RefusalKB.would_likely_refuse`` score does not exceed the baseline
    variant's score by more than this margin. When it does, the supervisor
    falls back to the baseline variant and emits a
    ``recon_plausibility_fallback`` event (rule #9 — no silent fallbacks).

    Default 0.1 (10 percentage points). The KB returns a deterministic
    [0, 1] heuristic from token overlap; 0.1 is a conservative threshold
    that keeps recon-substituted variants in flight when the substitution
    does not measurably worsen the refusal-vocabulary overlap. Tune from
    JSONL ``recon_plausibility_fallback`` event distribution after
    live-fire data lands.
    """
    chain_phase: bool = False
    """Opt-in flag: when True, the supervisor runs an additional
    chain-synthesis phase after exploitation that fires deterministic
    multi-step chains via ``runtime.chain_runner``. Default False so
    pre-Path-B engagements are bit-identical."""
    chain_graph: ChainGraph | None = None
    """Optional ``ChainGraph`` override. When ``None`` and ``chain_phase``
    is True, ``default_chain_graph()`` (the 5 starter chains from the
    Path B design spec §4) is used."""
    chain_K: int = 3
    chain_beam_width: int = 8
    chain_max_variants_per_step: int = 16
    engagement_memory: EngagementMemory | None = None
    """Phase J persistence layer. When provided, the supervisor enters
    :attr:`EngagementPhase.REHYDRATE` before ``RECON`` and looks up
    the target fingerprint in the memory store. On a hit it seeds
    ``RefusalKB`` from the persisted refusal signatures and merges
    the persisted recon-profile fields into the running profile
    (excluding ``leaked_credentials`` per AGENTS.md rule #4). On a
    miss the phase is a no-op. After the engagement completes the
    supervisor writes a fresh :class:`EngagementMemoryEntry` so the
    next run starts warmer."""
    model_id: str = ""
    """Caller-supplied model identifier (e.g. ``gpt-4o``). Combined
    with the manifest hash to derive the engagement-memory key so two
    engagements against the same MCP server but different LLM
    backings get distinct memory entries. Empty string when unknown
    — still produces a deterministic fingerprint, just one shared
    across model deployments of the same manifest."""
    signal_strength_enabled: bool = True
    """Phase N — when ``True`` (the default), every probe is scored
    with :class:`SignalStrengthScorer` and the resulting continuous
    gradient (composite of boundary_softening, topic_acknowledgment,
    partial_leak, model_confusion) flows into the genetic engine as
    a fitness rescue path, lands on :attr:`Finding.signal_strength`,
    and emits a ``signal_strength`` JSONL event per fire. Set to
    ``False`` to restore the pre-Phase-N binary-lethality behaviour
    (used by determinism regression fixtures that pin the legacy
    wire format byte-for-byte)."""
    diversity_gate_enabled: bool = True
    """Phase O — when ``True`` (the default), a :class:`DiversityGate`
    is attached to the :class:`GeneticEngine` so offspring sharing
    high MinHash Jaccard similarity with the surviving pool are
    pruned before firing. The gate's per-generation rejection counts
    are surfaced on :attr:`EngagementReport.strategy_summary` and
    in the ``diversity_stats`` JSONL event so reports can show
    "the population was collapsing — gate pruned N%"."""

    _strategy: StrategyNavigator = field(default=None, init=False)  # type: ignore[assignment]
    _genetic: GeneticEngine = field(default=None, init=False)  # type: ignore[assignment]
    _refusal_kb: RefusalKB = field(default=None, init=False)  # type: ignore[assignment]
    _breach_metric: BreachMetric = field(default=None, init=False)  # type: ignore[assignment]
    _signal_scorer: SignalStrengthScorer | None = field(default=None, init=False)
    _findings: list[Finding] = field(default_factory=list, init=False)
    _total_fired: int = field(default=0, init=False)
    _signal_strength_samples: list[SignalStrength] = field(default_factory=list, init=False)
    _carrier_histogram: dict[str, int] = field(default_factory=dict, init=False)
    _arc_results: list[ArcExecutionResult] = field(default_factory=list, init=False)
    _recon_profile: ReconProfile | None = field(default=None, init=False)
    _chain_results: list[ChainResult] = field(default_factory=list, init=False)
    _emergence_log: EmergenceLog = field(default_factory=EmergenceLog, init=False)
    _target_fingerprint: TargetFingerprint | None = field(default=None, init=False)
    _rehydrated: bool = field(default=False, init=False)
    _trust_markers: list[TrustMarker] = field(default_factory=list, init=False)
    _persisted_landed_class_ids: tuple[str, ...] = field(default=(), init=False)

    def _emit(self, event: dict[str, Any]) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(event)
        except Exception as exc:  # noqa: BLE001
            logger.debug("event hook error (suppressed): %s", exc)

    def __post_init__(self) -> None:
        self._refusal_kb = RefusalKB()
        initial_phase = EngagementPhase.REHYDRATE if self.engagement_memory is not None else EngagementPhase.RECON
        self._strategy = StrategyNavigator(
            manifest=self.manifest,
            refusal_kb=self._refusal_kb,
            layer=self.layer,
            initial_phase=initial_phase,
            transport_surfaces=getattr(self.transport, "supported_surfaces", frozenset()),
        )
        if self.engagement_memory is not None:
            self._target_fingerprint = compute_target_fingerprint(self.manifest, model_id=self.model_id)
        gate: Any = None
        if self.diversity_gate_enabled:
            from .diversity import DiversityGate as _DG

            # DiversityGate is seedless — its MinHash sketch is purely
            # deterministic over the variant text (AGENTS.md rule #7),
            # so two engagements over the same population produce the
            # same accept/reject decisions without an extra seed knob.
            gate = _DG()
        self._genetic = GeneticEngine(
            seed_value=self.seed_value,
            max_generations=self.max_generations,
            diversity_gate=gate,
        )
        self._breach_metric = BreachMetric(shadow=self.shadow)
        if self.signal_strength_enabled:
            # Default scorer — the canary token slot is populated per
            # variant at score-time (variants carry the canary in
            # ``metadata['canary']``). Intent tokens are extracted
            # deterministically from the variant body when not
            # supplied by recon. Both fallbacks keep the scorer
            # working even on pre-Phase-N classes that haven't
            # been audited for metadata coverage (rule #9).
            self._signal_scorer = SignalStrengthScorer()
        else:
            self._signal_scorer = None
        manifest_profile = ReconProfile.from_manifest(self.manifest)
        if self.recon is not None:
            self._recon_profile = manifest_profile.merge(self.recon)
        elif not manifest_profile.is_empty():
            self._recon_profile = manifest_profile
        else:
            self._recon_profile = None

    async def run(self) -> EngagementReport:
        """Execute the full autonomous engagement loop."""
        start = time.monotonic()
        phases: list[str] = []

        # Phase 0 (Phase J, opt-in): Rehydrate persistence.
        # When ``engagement_memory`` is configured, the strategy starts
        # in ``REHYDRATE`` and the supervisor handles the lookup before
        # advancing into the existing recon flow.
        if self._strategy.phase == EngagementPhase.REHYDRATE:
            self._run_rehydrate()
            phases.append(EngagementPhase.REHYDRATE.value)
            self._strategy.mark_rehydrate_complete()
            self._strategy.advance()  # REHYDRATE → RECON

        # Phase 1: Recon (already have manifest)
        self._strategy.advance()
        phases.append("recon")
        logger.info(
            "Recon complete: %d tools, %d resources",
            len(self.manifest.tools),
            len(self.manifest.resources),
        )
        self._emit(
            {
                "type": "phase",
                "phase": "recon",
                "tools": len(self.manifest.tools),
                "resources": len(self.manifest.resources),
                "tool_names": [t.name for t in self.manifest.tools],
            }
        )

        # Phase 2+: Probing → Pivot → Exploitation → Reporting
        while self._strategy.phase not in (
            EngagementPhase.REPORTING,
            EngagementPhase.COMPLETE,
        ):
            phase = self._strategy.phase
            phases.append(phase.value)
            logger.info("Phase: %s", phase.value)

            classes_to_try = self._strategy.recommend_attack_classes()
            budget = self._strategy.recommend_variant_budget()
            self._emit(
                {
                    "type": "phase",
                    "phase": phase.value,
                    "classes": list(classes_to_try),
                    "budget": budget,
                }
            )
            self._emit(
                {
                    "type": "thought",
                    "phase": phase.value,
                    "text": (
                        f"phase={phase.value} → trying classes={list(classes_to_try)} "
                        f"budget={budget} fired={self._total_fired}"
                    ),
                }
            )

            if not classes_to_try:
                self._strategy.advance()
                continue

            batch_scores: list[float] = []
            batch_findings = 0

            for class_id in classes_to_try:
                if self._total_fired >= self.max_total_variants:
                    break
                try:
                    attack_class = get(class_id)
                except KeyError:
                    logger.warning("Attack class not registered: %s", class_id)
                    continue

                if (
                    class_id in self.recon_aware_classes
                    and attack_class.recon_aware
                    and self._recon_profile is not None
                ):
                    variant_iter = self._gated_variants(
                        attack_class=attack_class,
                        profile=self._recon_profile,
                        class_id=class_id,
                    )
                else:
                    gen = attack_class.factory(self.seed_value)
                    variant_iter = iter(gen.generate())
                class_budget = min(budget, self.max_variants_per_class)
                class_state = _ClassRunState()

                while class_state.fired < class_budget and self._total_fired < self.max_total_variants:
                    batch = self._build_batch(
                        variant_iter,
                        remaining=min(
                            class_budget - class_state.fired,
                            self.max_total_variants - self._total_fired,
                            self.concurrency,
                        ),
                        class_state=class_state,
                    )
                    if not batch:
                        break  # generator exhausted or all short-circuited

                    probes = await asyncio.gather(
                        *(self._fire(v) for v in batch),
                        return_exceptions=False,
                    )

                    new_findings, new_scores = self._process_probe_batch(
                        batch=batch,
                        probes=probes,
                        class_id=class_id,
                        phase=phase,
                        class_state=class_state,
                    )
                    batch_findings += new_findings
                    batch_scores.extend(new_scores)

                    if self._should_early_stop(class_state):
                        self._emit(
                            {
                                "type": "early_stop",
                                "attack_class": class_id,
                                "fired": class_state.fired,
                                "reason": "no_drift_kb_stagnant",
                            }
                        )
                        break

            # Genetic amplification of survivors — fire offspring concurrently
            # in batches so amplification benefits from the same speedup.
            if self._genetic.should_continue() and self._genetic.best_score > 0:
                self._emit(
                    {
                        "type": "mutation",
                        "generation": self._genetic.generation,
                        "best_score": self._genetic.best_score,
                        "survivor_count": self._genetic.survivor_count,
                    }
                )
                children = list(self._genetic.next_generation())
                for offset in range(0, len(children), self.concurrency):
                    if self._total_fired >= self.max_total_variants:
                        break
                    chunk = children[offset : offset + self.concurrency]
                    chunk = chunk[: self.max_total_variants - self._total_fired]
                    if not chunk:
                        break
                    probes = await asyncio.gather(
                        *(self._fire(c) for c in chunk),
                        return_exceptions=False,
                    )
                    for child, probe in zip(chunk, probes, strict=True):
                        score = self._breach_metric.score(probe)
                        arbitrator = self._build_arbitrator(child)
                        verdict = arbitrator.verdict(probe)
                        signal = self._score_signal(child, probe)
                        if signal is not None:
                            self._signal_strength_samples.append(signal)
                        if verdict.landed:
                            self._findings.append(
                                Finding(
                                    variant_id=child.variant_id,
                                    attack_class=child.attack_class,
                                    verdict=verdict,
                                    lethality=score.score,
                                    evidence=score.evidence,
                                    generation=self._genetic.generation,
                                    signal_strength=signal,
                                )
                            )
                            batch_findings += 1
                        self._genetic.ingest_results([ScoredVariant(variant=child, score=score, signal=signal)])
                        self._total_fired += 1

            self._strategy.advance(
                scores=[DeviationScore(s, "batch") for s in batch_scores],
                findings=batch_findings,
                classes_tried=classes_to_try,
            )

        if self.chain_phase:
            await self._run_chain_phase()
            phases.append("chain_synthesis")

        phases.append("reporting")
        elapsed = time.monotonic() - start

        signal_stats = aggregate_signal_stats(self._signal_strength_samples) if self._signal_strength_samples else {}
        diversity_stats: dict[str, Any] = {}
        if self._genetic.diversity_gate is not None:
            diversity_stats = dict(self._genetic.diversity_gate.stats())
        arc_summary = summarise_arc_outcomes(self._arc_results) if self._arc_results else {}

        if signal_stats:
            self._emit({"type": "signal_strength_summary", **signal_stats})
        if diversity_stats:
            self._emit({"type": "diversity_stats", **diversity_stats})
        if self._carrier_histogram:
            self._emit(
                {
                    "type": "carrier_histogram",
                    "counts": dict(self._carrier_histogram),
                }
            )
        if arc_summary:
            self._emit({"type": "arc_summary", **arc_summary})

        self._emit(
            {
                "type": "done",
                "findings": len(self._findings),
                "fired": self._total_fired,
                "duration": elapsed,
                "phases": phases,
            }
        )
        # Phase J: write back fresh memory entry so the next engagement
        # starts warmer. No-op when no memory was configured.
        self._persist_engagement_memory()
        return EngagementReport(
            findings=tuple(self._findings),
            total_variants_fired=self._total_fired,
            generations=self._genetic.generation,
            phases_traversed=tuple(phases),
            duration_seconds=elapsed,
            refusal_kb_size=self._refusal_kb.size(),
            strategy_summary=self._strategy.summary,
            rehydrated=self._rehydrated,
            target_fingerprint=self._target_fingerprint,
            emergence_log=(self._emergence_log if self.chain_phase else None),
            signal_strength_stats=signal_stats,
            diversity_stats=diversity_stats,
            carrier_histogram=dict(self._carrier_histogram),
            arc_summary=arc_summary,
        )

    def record_arc_result(self, result: ArcExecutionResult) -> None:
        """Phase Q — feed an ARGT multi-call arc outcome to the supervisor.

        External callers (typically the ARGT multi-call transport
        adapter or a benchmark harness driving :class:`ArcRunner`
        directly) invoke this after each arc finishes so the
        supervisor can aggregate stage-progression stats into the
        :attr:`EngagementReport.arc_summary` and emit one
        ``arc_outcome`` JSONL event per arc for downstream report
        rendering (rules #6 + #9 — every decision has an evidence
        row in the audit trail).
        """
        self._arc_results.append(result)
        self._emit(
            {
                "type": "arc_outcome",
                "variant_id": result.arc.variant_id,
                "topic": result.arc.topic,
                "persona": result.arc.persona,
                "completed": bool(result.completed),
                "aborted": bool(result.aborted),
                "abort_reason": result.abort_reason,
                "rewinds": int(result.rewinds),
                "stages_reached": [o.stage_id for o in result.outcomes],
            }
        )

    def _run_rehydrate(self) -> None:
        """Phase J — look up the target fingerprint and seed engagement state.

        On a memory hit: seeds ``RefusalKB`` from persisted refusal
        signatures + token frequencies, merges the persisted recon
        snapshot onto the running recon profile (manifest-derived
        slots are still re-merged from the live manifest at the end so
        any drift is caught), and records the prior trust markers /
        landed class IDs for downstream use. On a miss / expired
        entry: no-op.

        AGENTS.md rule #9 — every decision (hit, miss, expired) is
        emitted via ``self._emit`` so the JSONL audit trail captures
        why the engagement started warm or cold.
        """
        memory = self.engagement_memory
        fingerprint = self._target_fingerprint
        if memory is None or fingerprint is None:
            self._emit(
                {
                    "type": "phase",
                    "phase": EngagementPhase.REHYDRATE.value,
                    "outcome": "skipped",
                    "reason": "no_memory_configured",
                }
            )
            return

        entry = memory.get(fingerprint)
        if entry is None:
            self._emit(
                {
                    "type": "phase",
                    "phase": EngagementPhase.REHYDRATE.value,
                    "outcome": "miss",
                    "fingerprint_id": fingerprint.fingerprint_id,
                }
            )
            return

        # Hit. Seed RefusalKB so the X8 plausibility gate is warm
        # before the first probe of the new engagement.
        seeded = self._refusal_kb.seed_from_signatures(entry.refusal_signatures)
        # Merge persisted recon-snapshot slots onto the running
        # profile. The running profile already contains the manifest
        # snapshot from __post_init__; persisted slots like
        # ``persona_hints`` / ``framing_hints`` are additive. The
        # ``leaked_credentials`` slot is filtered at write-time, so
        # nothing forbidden can land here.
        if entry.recon_snapshot:
            persisted_profile = ReconProfile(
                **{key: tuple(values) for key, values in entry.recon_snapshot.items() if values}
            )
            base = self._recon_profile if self._recon_profile is not None else ReconProfile()
            self._recon_profile = base.merge(persisted_profile)

        self._trust_markers = list(entry.trust_markers)
        self._persisted_landed_class_ids = entry.landed_class_ids
        self._rehydrated = True
        self._emit(
            {
                "type": "phase",
                "phase": EngagementPhase.REHYDRATE.value,
                "outcome": "hit",
                "fingerprint_id": fingerprint.fingerprint_id,
                "refusal_signatures_seeded": seeded,
                "trust_markers_loaded": len(self._trust_markers),
                "prior_landed_classes": list(entry.landed_class_ids),
            }
        )

    def _persist_engagement_memory(self) -> None:
        """Write a fresh :class:`EngagementMemoryEntry` after the run.

        Captures:
          * Refusal signatures accumulated during this engagement.
          * Trust markers extracted from non-refusing probes (see
            :meth:`_capture_trust_marker`).
          * Recon-profile slots minus ``leaked_credentials`` (rule #4).
          * Class IDs that landed at least one verdict, deduplicated.

        No-op when :attr:`engagement_memory` is ``None`` or no
        fingerprint was computed (e.g. during tests that bypass
        ``__post_init__``).
        """
        memory = self.engagement_memory
        fingerprint = self._target_fingerprint
        if memory is None or fingerprint is None:
            return

        landed_now = tuple(dict.fromkeys(f.attack_class for f in self._findings if f.attack_class))
        # Union prior and current so a target with intermittent
        # landings keeps the catalogue of proven classes.
        landed_union: list[str] = []
        seen: set[str] = set()
        for cid in (*self._persisted_landed_class_ids, *landed_now):
            if cid in seen:
                continue
            seen.add(cid)
            landed_union.append(cid)

        recon_snapshot: dict[str, tuple[str, ...]] = {}
        if self._recon_profile is not None:
            from dataclasses import asdict

            raw = asdict(self._recon_profile)
            recon_snapshot = filter_persistable_recon(raw)

        merged_markers = merge_trust_markers((), self._trust_markers)

        entry = EngagementMemoryEntry(
            fingerprint=fingerprint,
            trust_markers=merged_markers,
            refusal_signatures=self._refusal_kb.signature_keys(),
            recon_snapshot=recon_snapshot,
            landed_class_ids=tuple(landed_union),
            last_seen=time.time(),
            ttl_seconds=memory.ttl_seconds,
        )
        try:
            memory.write(entry)
            self._emit(
                {
                    "type": "engagement_memory_persisted",
                    "fingerprint_id": fingerprint.fingerprint_id,
                    "trust_markers": len(merged_markers),
                    "refusal_signatures": len(entry.refusal_signatures),
                    "landed_class_ids": list(entry.landed_class_ids),
                }
            )
        except OSError as exc:
            # AGENTS.md rule #9 — explain the empty result; the
            # engagement still completes, but the next run will
            # restart cold against this target.
            self._emit(
                {
                    "type": "engagement_memory_persisted",
                    "fingerprint_id": fingerprint.fingerprint_id,
                    "outcome": "write_failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    def _capture_trust_marker(self, *, kind: str, value: str) -> None:
        """Record a primer/framing/persona the target accepted.

        Called by :meth:`_process_batch` when a probe is accepted
        without a refusal classification. The captured marker is
        deduplicated on ``(kind, value)`` at persist time via
        :func:`merge_trust_markers` so repeat acceptances inflate
        ``accepted_count`` rather than the list length. ``kind`` must
        be one of ``prefix`` / ``persona`` / ``framing``; ``value`` is
        the structural primer text supplied by the variant generator
        (normalised + length-capped via :func:`normalise_trust_value`).

        AGENTS.md rule #4 compliance: trust markers carry only the
        structural primer text \u2014 no canary tokens, no probe
        responses, no leaked credentials \u2014 so persisting them
        cannot leak ground truth.
        """
        from .engagement_memory import _TRUST_MARKER_KINDS

        if kind not in _TRUST_MARKER_KINDS:
            return
        normalised = normalise_trust_value(value)
        if not normalised:
            return
        self._trust_markers.append(
            TrustMarker(
                kind=kind,
                value=normalised,
                accepted_count=1,
                last_seen=time.time(),
            )
        )

    async def _fire(self, variant: Variant) -> ProbeResult:
        """Send variant through transport and return raw probe result.

        Phase P — the variant's :attr:`Variant.carrier_surface` is
        counted into ``self._carrier_histogram`` before the fire so
        the histogram is recorded even when the transport raises.
        Transports that opt into carrier rendering inspect this same
        field via :func:`render_via_carrier` to pick the appropriate
        wire surface; transports that do not (the default) ignore it
        and the variant rides the canonical ``user_turn`` payload.
        """
        carrier = getattr(variant, "carrier_surface", "user_turn") or "user_turn"
        self._carrier_histogram[carrier] = self._carrier_histogram.get(carrier, 0) + 1
        try:
            return await self.transport.probe(variant)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                variant_id=variant.variant_id,
                seed_id=variant.seed_id,
                attack_class=variant.attack_class,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _gated_variants(
        self,
        *,
        attack_class: Any,
        profile: ReconProfile,
        class_id: str,
    ):
        """Yield Path 2 plausibility-gated variants for an allowlisted class.

        Constructs paired (recon, baseline) generators from the same class
        factory and walks them in lockstep. Each pair is scored by
        ``_gate_recon_plausibility``; the chosen variant is yielded. When
        the gate decides to fall back from recon to baseline, a
        ``recon_plausibility_fallback`` event is emitted so the decision
        is auditable in the JSONL trail (AGENTS.md rule #9).

        Determinism: both factories receive the same ``seed_value``, so
        the per-step variant_ids are byte-identical across runs given a
        fixed ``profile`` and engagement KB trajectory.
        """
        gen_recon = attack_class.factory(self.seed_value, recon=profile)
        gen_baseline = attack_class.factory(self.seed_value)
        for v_recon, v_baseline in zip(gen_recon.generate(), gen_baseline.generate(), strict=False):
            chosen, decision, recon_score, baseline_score = self._gate_recon_plausibility(v_recon, v_baseline)
            if decision == "fallback_recon_too_refusable":
                self._emit(
                    {
                        "type": "recon_plausibility_fallback",
                        "attack_class": class_id,
                        "recon_variant_id": v_recon.variant_id,
                        "baseline_variant_id": v_baseline.variant_id,
                        "recon_refusal_score": recon_score,
                        "baseline_refusal_score": baseline_score,
                        "margin": self.recon_plausibility_margin,
                        "kb_size": self._refusal_kb.size(),
                    }
                )
            yield chosen

    def _gate_recon_plausibility(
        self, recon_variant: Variant, baseline_variant: Variant
    ) -> tuple[Variant, str, float, float]:
        """Deterministic Path 2 plausibility gate.

        Scores the recon-substituted variant and the baseline variant
        against the engagement-scoped ``RefusalKB``'s
        ``would_likely_refuse`` heuristic. If the recon variant scores
        higher than the baseline by more than ``recon_plausibility_margin``,
        the gate falls back to the baseline (refusal-heuristic poisoning
        likely). Otherwise the recon variant fires.

        Cold-start window: while the KB has fewer than 5 entries the
        heuristic has no signal, so the recon variant wins by default
        (§8 redesign-spec decision: cold-start recon-wins, no extra flag).

        Returns ``(chosen_variant, decision_label, recon_score, baseline_score)``.
        Decision labels: ``cold_start_recon_wins``, ``recon_passes_gate``,
        ``fallback_recon_too_refusable``.

        AGENTS.md rule #3 compliance: deterministic KB-overlap delta only,
        no LLM judge calls.
        """
        if self._refusal_kb.size() < 5:
            return recon_variant, "cold_start_recon_wins", 0.0, 0.0
        recon_payload = " ".join(m.content for m in recon_variant.messages if m.content)
        baseline_payload = " ".join(m.content for m in baseline_variant.messages if m.content)
        recon_score = self._refusal_kb.would_likely_refuse(recon_payload)
        baseline_score = self._refusal_kb.would_likely_refuse(baseline_payload)
        if recon_score > baseline_score + self.recon_plausibility_margin:
            return baseline_variant, "fallback_recon_too_refusable", recon_score, baseline_score
        return recon_variant, "recon_passes_gate", recon_score, baseline_score

    def _build_arbitrator(self, variant: Variant) -> Arbitrator:
        """Construct arbitrator with variant-specific canary set."""
        from ..grading.behavioral_drift import BehavioralDriftMatcher
        from ..grading.canary_echo import CanaryEchoMatcher
        from ..grading.credential_shape import CredentialShapeMatcher
        from ..grading.refusal import RefusalMatcher
        from ..grading.state_machine import StateMachineMatcher
        from ..grading.structural import StructuralMatcher

        canaries = variant.canaries
        if canaries is None:
            from ..core.canary import CanarySet, make_canary

            canaries = CanarySet(primary=make_canary(self.seed_value, variant.seed_id))

        return Arbitrator(
            matchers=(
                CanaryEchoMatcher(canaries=canaries),
                BehavioralDriftMatcher(authorized_tools=self.shadow.authorized_tools),
                StateMachineMatcher(forbidden_states=self.shadow.forbidden_states),
                StructuralMatcher(),
                CredentialShapeMatcher(),
            ),
            refusal=RefusalMatcher(),
        )

    def _score_signal(self, variant: Variant, probe: ProbeResult) -> SignalStrength | None:
        """Phase N — compute the continuous gradient signal for a probe.

        Returns ``None`` when signal scoring is disabled. Pulls canary
        tokens and intent tokens off the variant deterministically:

        * ``canaries`` from :attr:`Variant.canaries` (the same set the
          :class:`CanaryEchoMatcher` uses) — guarantees the partial-
          leak sub-signal anchors against the same target the
          IRREFUTABLE matcher does.
        * ``intent_tokens`` from the variant body, extracted via
          :func:`extract_intent_tokens`. When the variant carries a
          recon-derived ``intent_tokens`` slot in
          :attr:`Variant.metadata` we honour that override so
          recon-aware classes can pin the topic precisely.
        """
        if self._signal_scorer is None:
            return None

        canaries: tuple[str, ...] = ()
        if variant.canaries is not None:
            canaries = variant.canaries.all()

        intent_override = variant.metadata.get("intent_tokens") if variant.metadata else None
        if isinstance(intent_override, tuple | list) and intent_override:
            intent_tokens: tuple[str, ...] = tuple(str(t) for t in intent_override if str(t).strip())
        else:
            body = " ".join(m.content for m in variant.messages if getattr(m, "content", None))
            intent_tokens = extract_intent_tokens(body)

        scorer = SignalStrengthScorer(
            intent_tokens=intent_tokens,
            canaries=canaries,
            baseline_response_length=self._signal_scorer.baseline_response_length,
            baseline_response_length_sd=self._signal_scorer.baseline_response_length_sd,
            baseline_tool_call_rate=self._signal_scorer.baseline_tool_call_rate,
        )
        return scorer.score(probe)

    def _build_batch(
        self,
        variant_iter: Any,
        *,
        remaining: int,
        class_state: _ClassRunState,
    ) -> list[Variant]:
        """Pull up to ``remaining`` variants, applying KB short-circuit.

        Variants whose payload overlaps known refusal vocabulary above
        ``kb_short_circuit_threshold`` are skipped — the genetic engine
        will reclaim that slot for a novel mutation. Skipping keeps the
        engagement budget on variants that have a chance of producing
        new signal.
        """
        if remaining <= 0:
            return []
        kb_active = self._refusal_kb.size() >= 5
        threshold = self.kb_short_circuit_threshold
        batch: list[Variant] = []
        max_skip_per_batch = max(remaining * 4, 8)
        skipped = 0
        while len(batch) < remaining and skipped < max_skip_per_batch:
            try:
                variant = next(variant_iter)
            except StopIteration:
                break
            if kb_active and threshold < 1.0:
                payload = " ".join(m.content for m in variant.messages if m.content)
                refuse_score = self._refusal_kb.would_likely_refuse(payload)
                if refuse_score >= threshold:
                    skipped += 1
                    class_state.kb_short_circuited += 1
                    continue
            batch.append(variant)
        return batch

    def _process_probe_batch(
        self,
        *,
        batch: list[Variant],
        probes: list[ProbeResult],
        class_id: str,
        phase: EngagementPhase,
        class_state: _ClassRunState,
    ) -> tuple[int, list[float]]:
        """Score, arbitrate, emit events, ingest into KB + genetic engine.

        Returns (findings_added, scores_observed). Processing is sequential
        and deterministic — order matches the input batch.
        """
        kb_size_before = self._refusal_kb.size()
        new_findings = 0
        scores_observed: list[float] = []
        scored_for_genetic: list[ScoredVariant] = []

        for variant, probe in zip(batch, probes, strict=True):
            score = self._breach_metric.score(probe)
            scores_observed.append(score.score)
            arbitrator = self._build_arbitrator(variant)
            verdict = arbitrator.verdict(probe)
            signal = self._score_signal(variant, probe)
            if signal is not None:
                self._signal_strength_samples.append(signal)

            self._emit(
                {
                    "type": "fire",
                    "variant_id": variant.variant_id,
                    "attack_class": class_id,
                    "lethality": score.score,
                    "verdict": verdict.confidence,
                    "landed": verdict.landed,
                    "phase": phase.value,
                    "refused": bool(probe.refused),
                    "signal_strength": (signal.as_dict() if signal is not None else None),
                }
            )

            if verdict.landed:
                finding = Finding(
                    variant_id=variant.variant_id,
                    attack_class=class_id,
                    verdict=verdict,
                    lethality=score.score,
                    evidence=score.evidence,
                    generation=self._genetic.generation,
                    signal_strength=signal,
                )
                self._findings.append(finding)
                new_findings += 1
                # Phase J: capture the structural primer that got past
                # this target's refusal layer. Variants carry their
                # primer text in ``metadata['trust_markers']`` (a list
                # of ``{kind, value}`` dicts) when the seed generator
                # opts in; classes that don't set the slot simply
                # skip capture (no fail-loud — rule #9 only requires
                # we capture *what we have*, not invent metadata).
                primers = variant.metadata.get("trust_markers") if variant.metadata else None
                if isinstance(primers, list):
                    for primer in primers:
                        if not isinstance(primer, dict):
                            continue
                        kind = str(primer.get("kind", ""))
                        value = str(primer.get("value", ""))
                        if kind and value:
                            self._capture_trust_marker(kind=kind, value=value)
                logger.info(
                    "FINDING: %s (lethality=%.1f, confidence=%s)",
                    class_id,
                    score.score,
                    verdict.confidence,
                )
                self._emit(
                    {
                        "type": "finding",
                        "variant_id": variant.variant_id,
                        "attack_class": class_id,
                        "lethality": score.score,
                        "confidence": verdict.confidence,
                        "evidence": dict(score.evidence),
                        "generation": self._genetic.generation,
                        "phase": phase.value,
                    }
                )

            if probe.refused or score.score == 0.0:
                sig = self._refusal_kb.ingest(probe.response_text)
                if sig:
                    self._emit(
                        {
                            "type": "refusal",
                            "variant_id": variant.variant_id,
                            "signature": sig,
                            "kb_size": self._refusal_kb.size(),
                        }
                    )

            scored_for_genetic.append(ScoredVariant(variant=variant, score=score, signal=signal))
            class_state.fired += 1
            if score.score > 0:
                class_state.drift_count += 1
                class_state.last_drift_at_fire = class_state.fired
            elif signal is not None and signal.strength >= 0.2:
                # Phase N — even when the bucket score is zero, the
                # continuous signal-strength gradient counts as drift
                # for early-stop bookkeeping. Keeps a class with
                # climbing softening / partial-leak signal alive
                # rather than killing it because no canary fired yet.
                class_state.drift_count += 1
                class_state.last_drift_at_fire = class_state.fired
            self._total_fired += 1

        if scored_for_genetic:
            self._genetic.ingest_results(scored_for_genetic)

        if self._refusal_kb.size() > kb_size_before:
            class_state.last_kb_growth_at_fire = class_state.fired

        return new_findings, scores_observed

    def _chain_initial_recon(self) -> ReconProfile:
        """Recon profile fed into beam search for the chain phase.

        Mirrors the per-class recon plumbing — manifest-derived artefacts
        plus any caller-supplied profile, merged. Empty if the engagement
        has neither.
        """
        manifest_profile = ReconProfile.from_manifest(self.manifest)
        if self.recon is not None:
            return manifest_profile.merge(self.recon)
        return manifest_profile

    async def _chain_fire_and_judge(self, variant: Variant) -> tuple[ProbeResult, Verdict]:
        """Fire a single variant through the existing transport + arbitrator.

        Reused by the chain runner so chain firings appear in the same
        event stream and ingest into the same KB / genetic engine as the
        per-class phases. The chain runner does not bypass any of the
        existing safety / accounting plumbing.

        Lethality + evidence are scored by the same ``BreachMetric`` the
        main loop uses (``_process_probe_batch``) so ``EngagementReport``
        comparisons and the live-fire 1.5× chain gate measure calibrated
        scores rather than a hardcoded 1.0.
        """
        probe = await self._fire(variant)
        arbitrator = self._build_arbitrator(variant)
        verdict = arbitrator.verdict(probe)
        score = self._breach_metric.score(probe)
        signal = self._score_signal(variant, probe)
        if signal is not None:
            self._signal_strength_samples.append(signal)
        self._total_fired += 1
        self._emit(
            {
                "type": "fire",
                "variant_id": variant.variant_id,
                "attack_class": variant.attack_class,
                "lethality": score.score,
                "verdict": verdict.confidence,
                "landed": verdict.landed,
                "phase": "chain_synthesis",
                "refused": bool(probe.refused),
                "signal_strength": (signal.as_dict() if signal is not None else None),
            }
        )
        if verdict.landed:
            evidence = {**dict(score.evidence), "phase": "chain_synthesis"}
            finding = Finding(
                variant_id=variant.variant_id,
                attack_class=variant.attack_class,
                verdict=verdict,
                lethality=score.score,
                evidence=evidence,
                generation=self._genetic.generation,
                signal_strength=signal,
            )
            self._findings.append(finding)
            self._emit(
                {
                    "type": "finding",
                    "variant_id": variant.variant_id,
                    "attack_class": variant.attack_class,
                    "lethality": score.score,
                    "confidence": verdict.confidence,
                    "evidence": dict(evidence),
                    "generation": self._genetic.generation,
                    "phase": "chain_synthesis",
                }
            )
        return probe, verdict

    async def _run_chain_phase(self) -> None:
        """Synthesise + execute deterministic chains via the runner.

        Called from ``run()`` only when ``self.chain_phase`` is True.
        Builds plans via ``beam_search`` against either the
        caller-supplied ``chain_graph`` or ``default_chain_graph()``, then
        executes each plan via ``execute_chain`` with the supervisor's
        own fire/judge pipeline injected. All findings produced by chain
        firings are appended to ``self._findings`` exactly as per-class
        findings are.
        """
        graph = self.chain_graph if self.chain_graph is not None else default_chain_graph()
        initial_recon = self._chain_initial_recon()
        plans = beam_search(
            graph,
            initial_recon=initial_recon,
            K=self.chain_K,
            beam_width=self.chain_beam_width,
            seed_value=self.seed_value,
        )
        if not plans:
            return
        self._emit(
            {
                "type": "phase",
                "phase": "chain_synthesis",
                "plans": len(plans),
            }
        )
        for plan in plans:
            result = await execute_chain(
                plan,
                graph=graph,
                initial_recon=initial_recon,
                fire_and_judge=self._chain_fire_and_judge,
                seed_value=self.seed_value,
                max_variants_per_step=self.chain_max_variants_per_step,
                recon_aware_classes=self.recon_aware_classes,
                refusal_kb=self._refusal_kb,
                recon_plausibility_margin=self.recon_plausibility_margin,
            )
            self._chain_results.append(result)
            # Phase J: distil the chain's emergence path into a
            # structured report so the engagement summary surfaces
            # producer→consumer hops without callers having to walk
            # the JSONL trail themselves.
            report = build_emergence_report(result)
            self._emergence_log.append(report)
            self._emit(
                {
                    "type": "emergence_report",
                    "chain_id": result.chain_id,
                    "completed": result.completed,
                    "landed_class_ids": list(report.landed_class_ids),
                    "links": [link.as_dict() for link in report.links],
                    "summary": report.summary,
                }
            )

    def _should_early_stop(self, class_state: _ClassRunState) -> bool:
        """True if the current class is producing no signal and KB is stagnant."""
        if self.early_stop_after <= 0:
            return False
        if class_state.fired < self.early_stop_after:
            return False
        if class_state.drift_count > 0:
            return False  # found drift — keep firing, genetic will amplify
        # No drift; check KB growth — if KB hasn't grown in last 10 fires,
        # the class is producing only repeated refusals we already mapped.
        fires_since_kb_growth = class_state.fired - class_state.last_kb_growth_at_fire
        return fires_since_kb_growth >= 10


@dataclass(slots=True)
class _ClassRunState:
    """Per-class telemetry used for early-stop decisions and reporting."""

    fired: int = 0
    drift_count: int = 0
    kb_short_circuited: int = 0
    last_drift_at_fire: int = 0
    last_kb_growth_at_fire: int = 0
