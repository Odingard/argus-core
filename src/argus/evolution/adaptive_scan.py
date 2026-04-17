# argus/evolution/adaptive_scan.py
# Adaptive evolutionary scan — runs PopulationManager for N generations
# where agents evolve their attack strategies based on what worked/failed.
# This fires automatically as part of normal scan commands (no separate CLI).

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from argus.evolution.fitness import EvolutionScanResult
from argus.evolution.genome import AgentGenome
from argus.evolution.population import PopulationManager

logger = logging.getLogger(__name__)


async def adaptive_scan(
    target: str,
    scan_fn: Callable[[str, AgentGenome], Awaitable[EvolutionScanResult]],
    generations: int = 3,
    population_size: int = 13,
    base_genome: AgentGenome | None = None,
    corpus: dict[str, list[str]] | None = None,
    verbose: bool = False,
) -> dict:
    """Run an adaptive evolutionary scan against a target.

    This is the main entry point called by the orchestrator after the
    standard scan pass completes. It takes the scan results from the
    first pass and evolves agent strategies across multiple generations.

    Args:
        target: Target URL/endpoint being scanned.
        scan_fn: Async function(target, genome) -> EvolutionScanResult.
                 This wraps the actual ARGUS agent execution.
        generations: Number of evolutionary generations to run.
        population_size: Number of genomes per generation.
        base_genome: Optional seed genome from the first scan pass.
        corpus: Optional corpus patterns keyed by category.
        verbose: Log detailed generation summaries.

    Returns:
        Dict with generation_summaries, fitness_progression,
        maladaptive_progression, best_genome, hall_of_fame,
        and armed_deferred_payloads.
    """
    start = time.monotonic()

    pm = PopulationManager(population_size=population_size)

    # Seed population
    if corpus:
        pm.seed_from_corpus(corpus)
    else:
        pm.seed_population()

    # If we have a base genome from the first pass, inject it as the seed
    if base_genome is not None:
        if pm.population:
            pm.population[0] = base_genome

    generation_summaries: list[dict] = []
    fitness_progression: list[float] = []
    maladaptive_progression: list[float] = []

    for gen_idx in range(generations):
        logger.info(
            "Evolution generation %d/%d — %d genomes",
            gen_idx + 1,
            generations,
            len(pm.population),
        )

        # Wrap scan_fn to bind the target
        async def _execute(genome: AgentGenome) -> EvolutionScanResult:
            return await scan_fn(target, genome)

        # Run the generation
        scored = await pm.run_generation(_execute)

        # Track fitness progression
        best_genome, best_scores = scored[0] if scored else (None, {})
        best_fitness = best_scores.get("total_fitness", 0.0)
        best_maladaptive = best_scores.get("maladaptive_fitness", 0.0)

        fitness_progression.append(best_fitness)
        maladaptive_progression.append(best_maladaptive)

        summary = pm.generation_summary()
        summary["best_fitness"] = best_fitness
        summary["best_maladaptive"] = best_maladaptive
        generation_summaries.append(summary)

        if verbose:
            logger.info(
                "Gen %d: best=%.4f avg=%.4f armed=%d",
                gen_idx + 1,
                summary.get("max_fitness", 0),
                summary.get("avg_fitness", 0),
                summary.get("armed_payloads", 0),
            )

        # Evolve for next generation (skip on last iteration)
        if gen_idx < generations - 1:
            pm.evolve(scored)

    # Check for armed deferred payloads
    armed = pm.check_armed_payloads()

    # Fire armed payloads in a final pass
    deferred_results = []
    if armed:
        logger.info("Firing %d armed deferred payloads", len(armed))
        deferred_results = await _fire_deferred_payloads(target, armed, scan_fn)

    elapsed = time.monotonic() - start

    best = pm.get_best_genome()
    return {
        "generations_completed": generations,
        "population_size": population_size,
        "elapsed_seconds": round(elapsed, 2),
        "generation_summaries": generation_summaries,
        "fitness_progression": fitness_progression,
        "maladaptive_progression": maladaptive_progression,
        "best_genome": best.to_dict() if best else None,
        "hall_of_fame": pm.export_hall_of_fame(),
        "armed_deferred_payloads": len(armed),
        "deferred_results": deferred_results,
    }


async def _fire_deferred_payloads(
    target: str,
    armed: list[dict],
    scan_fn: Callable[[str, AgentGenome], Awaitable[EvolutionScanResult]],
) -> list[dict]:
    """Fire armed deferred payloads as a final exploitation pass.

    These are high-value exploits that were held back during conditioning
    phases and are now deployed against a defender trained to ignore them.
    """
    results = []
    for payload_info in armed[:5]:  # Cap at 5 deferred payloads
        genome = AgentGenome(
            agent_id=f"deferred-{payload_info['category']}",
            agent_category=payload_info["category"],
            attack_posture="aggressive",  # Deferred payloads always fire aggressively
            deferred_payloads=[payload_info["payload"]],
        )
        try:
            result = await scan_fn(target, genome)
            results.append(
                {
                    "genome_id": genome.agent_id,
                    "category": payload_info["category"],
                    "findings": result.total_findings,
                    "validated": result.validated_findings,
                }
            )
        except Exception as e:
            logger.warning("Deferred payload %s failed: %s", genome.agent_id, e)
            results.append(
                {
                    "genome_id": genome.agent_id,
                    "category": payload_info["category"],
                    "error": str(e),
                }
            )
    return results
