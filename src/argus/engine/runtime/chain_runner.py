"""Deterministic chain-execution runtime.

The runner accepts a ``ChainPlan`` produced by ``core.chain_synth.beam_search``
plus an injected ``fire_and_judge`` callable — typically a thin wrapper
the supervisor builds around its existing ``transport.probe`` +
``Arbitrator.verdict`` pipeline. The runner walks the plan node by
node, fires variants from the registered ``AttackClass.factory``, and
on the first landed verdict per step calls
``AttackClass.harvest`` to extract artefacts that get merged into the
running ``ReconProfile`` for the next step.

Determinism guarantees:

* For a fixed ``(plan, initial_recon, seed_value, fire_and_judge)``
  tuple, the variant ids fired per step are byte-identical across runs.
* Harvest is purely a function of the landed ``ProbeResult``; the same
  probe → the same artefacts on every run.
* Empty harvest (a class produces nothing concrete from its finding) is
  not an error — the chain still continues, but downstream consumers
  might find their slots unsatisfied.

The runner does not own the transport. Tests inject a stub
``fire_and_judge`` so the runner is testable without any network.

Backward compatibility: the runner is opt-in. The supervisor only
constructs and runs it when ``chain_phase=True`` is passed. With the
default ``chain_phase=False`` the supervisor's behaviour is bit-identical
to the pre-Path-B head; this is hard-pinned by
``test_chain_runner.test_backward_compat_chain_phase_off``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..core.chain_graph import ChainGraph, ChainPlan
from ..core.recon_profile import _FIELDS, ReconProfile
from ..core.registry import AttackClass, get
from ..core.variant import Variant
from ..grading.matcher import ProbeResult, Verdict
from .refusal_kb import RefusalKB

ProbeJudge = Callable[[Variant], Awaitable[tuple[ProbeResult, Verdict]]]
"""Async callable that fires a variant and returns (probe, verdict)."""


@dataclass(frozen=True, slots=True)
class ChainStepRecord:
    """Per-step transcript entry — one is emitted for every node in the plan.

    ``landed`` is True iff the step's first landed verdict was reached
    within the per-step variant budget. ``harvested`` is the deterministic
    artefact dict the class' ``harvest`` callable returned (empty if the
    class declares no produces or harvest returned nothing).
    """

    class_id: str
    fired: int
    landed: bool
    variant_id: str | None
    harvested: tuple[tuple[str, tuple[str, ...]], ...] = ()
    refusal_count: int = 0

    @property
    def harvested_dict(self) -> dict[str, tuple[str, ...]]:
        return dict(self.harvested)


@dataclass(frozen=True, slots=True)
class ChainResult:
    """End-to-end outcome of a single ``ChainPlan`` execution."""

    chain_id: str
    plan: ChainPlan
    steps: tuple[ChainStepRecord, ...]
    completed: bool
    final_recon: ReconProfile
    fallback_events: tuple[dict[str, object], ...] = ()
    """Plausibility-gate fallback events emitted during the chain.

    Surfaces ``ChainContext.fallback_events`` so callers (and the
    JSONL audit trail) can observe every recon→baseline fallback the
    X8 gate triggered. Required by AGENTS.md rule #9 (no silent
    failures); ``Supervisor._gated_variants`` emits the equivalent
    events on the per-class path via ``self._emit``, and the chain
    runner mirrors that contract through this field.
    """

    @property
    def landed_count(self) -> int:
        return sum(1 for s in self.steps if s.landed)


@dataclass(slots=True)
class ChainContext:
    """Mutable state held across a chain's per-step execution."""

    initial_recon: ReconProfile
    running_recon: ReconProfile
    seed_value: int
    recon_aware_classes: frozenset[str] = frozenset()
    """Per-class allowlist for recon-aware variant substitution.

    Default empty — recon artefacts harvested from prior steps are still
    merged into ``running_recon`` (so the chain transcript is
    informative), but per-step generators are constructed without
    ``recon=`` for every class regardless of the class' static
    ``recon_aware`` flag. A class flips on by being added to this
    frozenset only after its Path 1 neutral-framing mutator has cleared
    the AGENTS.md rule #10 live-fire gate (≥5pp uplift over
    ``recon=OFF`` baseline on a shape-appropriate target). Mirrors
    ``SupervisorConfig.recon_aware_classes``; the chain runner does not
    own a separate setting because chain firings should never engage
    recon substitution unless the per-class supervisor pass has
    validated it.
    """
    refusal_kb: RefusalKB = field(default_factory=RefusalKB)
    """Engagement-scoped refusal KB threaded into the chain runner.

    Mirrors ``Supervisor._refusal_kb`` so chain steps participate in the
    same Path 2 plausibility gate the per-class probing/exploitation
    phases use. When the KB has fewer than 5 entries, the gate
    short-circuits to ``cold_start_recon_wins`` (recon-substituted
    variant fires unconditionally). After the KB warms up,
    ``would_likely_refuse`` deltas drive the decision per
    ``recon_plausibility_margin`` below.

    The KB is shared by reference with the supervisor when the chain
    runner is invoked from ``Supervisor._chain_phase``; tests pass a
    fresh ``RefusalKB()`` instance for isolation.
    """
    recon_plausibility_margin: float = 0.1
    """Delta above which a recon-substituted variant is considered too
    refusable and the gate falls back to baseline.

    Mirrors ``SupervisorConfig.recon_plausibility_margin`` —
    ``recon_score - baseline_score > margin`` triggers fallback. Default
    ``0.1`` matches the supervisor default. Tests can lower this to
    force fallback or raise it to force recon-passes-through.
    """
    steps: list[ChainStepRecord] = field(default_factory=list)
    fallback_events: list[dict[str, object]] = field(default_factory=list)

    def merge_harvest(self, harvested: dict[str, tuple[str, ...]]) -> None:
        """Fold harvested artefacts into ``running_recon``.

        Only known recon-profile field names are accepted; anything else
        is silently dropped. Sanitisation (length cap + control-char
        strip + dedup + 64/field cap) reuses the recon-param plumbing
        shipped in PR #13 — no separate sanitisation path exists.
        """
        if not harvested:
            return
        valid: dict[str, tuple[str, ...]] = {}
        for key, values in harvested.items():
            if key not in _FIELDS:
                continue
            if not values:
                continue
            valid[key] = tuple(values)
        if not valid:
            return
        addition = ReconProfile(**valid)
        self.running_recon = self.running_recon.merge(addition)


def _build_generator(attack_class: AttackClass, ctx: ChainContext):
    """Construct the per-step generator with recon plumbing if applicable.

    Recon plumbing requires three conditions: the class statically opts in
    via ``recon_aware=True``, ``ctx.running_recon`` is non-empty, AND the
    class is present in ``ctx.recon_aware_classes`` (the per-class
    allowlist). Allowlist defaults to empty per the PR #13 live-fire-gate
    failure (substrate regresses on 3/3 targets); a class enters the
    allowlist only after its Path 1 mutator has been live-fire validated
    per AGENTS.md rule #10.
    """
    if (
        attack_class.class_id in ctx.recon_aware_classes
        and attack_class.recon_aware
        and not ctx.running_recon.is_empty()
    ):
        return attack_class.factory(ctx.seed_value, recon=ctx.running_recon)
    return attack_class.factory(ctx.seed_value)


def _gate_recon_plausibility(
    recon_variant: Variant,
    baseline_variant: Variant,
    refusal_kb: RefusalKB,
    margin: float,
) -> tuple[Variant, str, float, float]:
    """Deterministic Path 2 plausibility gate — chain-runner mirror.

    Mirrors ``Supervisor._gate_recon_plausibility`` so chain steps and
    per-class supervisor steps make identical fall-back decisions.
    AGENTS.md rule #3 compliance: deterministic KB-overlap delta only,
    no LLM judge calls. When the KB has fewer than 5 entries the gate
    short-circuits to ``cold_start_recon_wins``; otherwise the recon
    variant fires unless it scores higher than baseline by more than
    ``margin``.
    """
    if refusal_kb.size() < 5:
        return recon_variant, "cold_start_recon_wins", 0.0, 0.0
    recon_payload = " ".join(m.content for m in recon_variant.messages if m.content)
    baseline_payload = " ".join(m.content for m in baseline_variant.messages if m.content)
    recon_score = refusal_kb.would_likely_refuse(recon_payload)
    baseline_score = refusal_kb.would_likely_refuse(baseline_payload)
    if recon_score > baseline_score + margin:
        return (
            baseline_variant,
            "fallback_recon_too_refusable",
            recon_score,
            baseline_score,
        )
    return recon_variant, "recon_passes_gate", recon_score, baseline_score


def _gated_chain_variants(
    attack_class: AttackClass,
    ctx: ChainContext,
    class_id: str,
):
    """Yield variants for a chain step under the X8 plausibility gate.

    Constructs paired (recon, baseline) generators from the same class
    factory and walks them in lockstep, scoring each pair via
    ``_gate_recon_plausibility``. When the gate decides to fall back
    from recon to baseline, a ``recon_plausibility_fallback`` event is
    appended to ``ctx.fallback_events`` so the chain transcript captures
    the decision (AGENTS.md rule #9 — no silent failures).
    """
    gen_recon = attack_class.factory(ctx.seed_value, recon=ctx.running_recon)
    gen_baseline = attack_class.factory(ctx.seed_value)
    for v_recon, v_baseline in zip(gen_recon.generate(), gen_baseline.generate(), strict=False):
        chosen, decision, recon_score, baseline_score = _gate_recon_plausibility(
            v_recon, v_baseline, ctx.refusal_kb, ctx.recon_plausibility_margin
        )
        if decision == "fallback_recon_too_refusable":
            ctx.fallback_events.append(
                {
                    "event": "recon_plausibility_fallback",
                    "class_id": class_id,
                    "recon_variant_id": v_recon.variant_id,
                    "baseline_variant_id": v_baseline.variant_id,
                    "recon_refusal_score": recon_score,
                    "baseline_refusal_score": baseline_score,
                    "margin": ctx.recon_plausibility_margin,
                    "kb_size": ctx.refusal_kb.size(),
                }
            )
        yield chosen


async def execute_chain(
    plan: ChainPlan,
    *,
    graph: ChainGraph,
    initial_recon: ReconProfile,
    fire_and_judge: ProbeJudge,
    seed_value: int = 0,
    max_variants_per_step: int = 16,
    recon_aware_classes: frozenset[str] = frozenset(),
    refusal_kb: RefusalKB | None = None,
    recon_plausibility_margin: float = 0.1,
) -> ChainResult:
    """Run a single chain plan end-to-end.

    Args:
        plan: the chain plan emitted by ``beam_search``.
        graph: the ``ChainGraph`` the plan was synthesised against;
            consulted to look up each node's ``produces`` tuple at
            harvest time.
        initial_recon: the recon profile entering the chain (typically
            the supervisor's manifest-derived profile merged with any
            external recon).
        fire_and_judge: async callable mapping a ``Variant`` to a
            ``(ProbeResult, Verdict)`` pair. Tests inject a stub here.
        seed_value: deterministic seed forwarded to every per-step
            generator factory.
        max_variants_per_step: cap on variants fired per step. Keeps
            chain runtime bounded; the runner returns as soon as the
            first landed verdict appears regardless of this cap.
        recon_aware_classes: per-class allowlist threaded into
            ``ChainContext``. Default empty per the PR #13 live-fire
            failure; harvest still feeds ``running_recon`` for the
            transcript but per-step generators are constructed without
            ``recon=`` for any class not in the allowlist.

    Returns:
        A ``ChainResult`` with per-step records, the final running
        recon profile, and a ``completed`` flag (True iff every step
        landed).

    Behaviour on a step that never lands within the per-step budget:
    the chain aborts immediately. Downstream steps are not fired —
    chain composition has no value if the upstream artefact never
    surfaced live.
    """
    if max_variants_per_step < 1:
        raise ValueError("max_variants_per_step must be >= 1")
    if not plan.nodes:
        raise ValueError("ChainPlan.nodes is empty")
    for class_id in plan.nodes:
        if not graph.has_node(class_id):
            raise KeyError(f"ChainPlan references {class_id!r} but it is not in the graph")

    ctx = ChainContext(
        initial_recon=initial_recon,
        running_recon=initial_recon,
        seed_value=seed_value,
        recon_aware_classes=recon_aware_classes,
        refusal_kb=refusal_kb if refusal_kb is not None else RefusalKB(),
        recon_plausibility_margin=recon_plausibility_margin,
    )

    completed = True
    for class_id in plan.nodes:
        attack_class = get(class_id)
        node = graph.get_node(class_id)

        if node.produces and attack_class.harvest is None:
            raise RuntimeError(
                f"Chain node {class_id} declares produces={node.produces} "
                "but the attack class has no harvest() registered. "
                "Producing classes must implement harvest()."
            )

        # X8 plausibility gate is engaged only when this class is on the
        # recon-aware allowlist AND running recon is non-empty AND the
        # class statically opts into recon. Otherwise we walk the
        # baseline generator unchanged.
        gated = class_id in ctx.recon_aware_classes and attack_class.recon_aware and not ctx.running_recon.is_empty()
        if gated:
            variant_iter = _gated_chain_variants(attack_class, ctx, class_id)
        else:
            gen = _build_generator(attack_class, ctx)
            variant_iter = gen.generate()

        record = await _run_step(
            class_id=class_id,
            attack_class=attack_class,
            node_produces=node.produces,
            variant_iter=variant_iter,
            fire_and_judge=fire_and_judge,
            max_variants=max_variants_per_step,
            refusal_kb=ctx.refusal_kb,
        )
        ctx.steps.append(record)

        if not record.landed:
            completed = False
            break

        if record.harvested:
            ctx.merge_harvest(record.harvested_dict)

    return ChainResult(
        chain_id=plan.chain_id,
        plan=plan,
        steps=tuple(ctx.steps),
        completed=completed,
        final_recon=ctx.running_recon,
        fallback_events=tuple(ctx.fallback_events),
    )


async def _run_step(
    *,
    class_id: str,
    attack_class: AttackClass,
    node_produces: tuple[str, ...],
    variant_iter,
    fire_and_judge: ProbeJudge,
    max_variants: int,
    refusal_kb: RefusalKB,
) -> ChainStepRecord:
    """Fire variants from ``variant_iter`` until landed or budget exhausted.

    Refused probes are ingested into the supplied ``refusal_kb`` so the
    plausibility gate warms up across steps in the same way the
    supervisor's per-class loop warms its KB during probing.
    """
    fired = 0
    refusal_count = 0
    landed_variant: Variant | None = None
    landed_probe: ProbeResult | None = None
    for variant in variant_iter:
        if fired >= max_variants:
            break
        probe, verdict = await fire_and_judge(variant)
        fired += 1
        if probe.refused:
            refusal_count += 1
            refusal_kb.ingest(probe.response_text)
        if verdict.landed:
            landed_variant = variant
            landed_probe = probe
            break

    harvested: dict[str, tuple[str, ...]] = {}
    if landed_probe is not None and node_produces and attack_class.harvest is not None:
        raw = attack_class.harvest(landed_probe)
        for key, values in raw.items():
            if key not in node_produces:
                continue
            if not values:
                continue
            harvested[key] = tuple(values)

    return ChainStepRecord(
        class_id=class_id,
        fired=fired,
        landed=landed_variant is not None,
        variant_id=landed_variant.variant_id if landed_variant else None,
        harvested=tuple(sorted(harvested.items())),
        refusal_count=refusal_count,
    )


__all__ = [
    "ChainContext",
    "ChainResult",
    "ChainStepRecord",
    "ProbeJudge",
    "execute_chain",
]
