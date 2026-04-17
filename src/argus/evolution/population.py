# argus/evolution/population.py
# Population manager — manages concurrent agent genomes per generation.
# Matches ARGUS v0.1.x parallel agent count (13 agents).

from __future__ import annotations

import asyncio
import logging
import random
import uuid
from collections.abc import Awaitable, Callable

from argus.evolution.fitness import EvolutionScanResult, FitnessEvaluator
from argus.evolution.genome import ARGUS_AGENT_CATEGORIES, AgentGenome
from argus.evolution.mutator import MutationEngine

logger = logging.getLogger(__name__)


class PopulationManager:
    """Manages a population of agent genomes across generations.

    Attributes:
        population_size: Number of genomes per generation (default 13 = ARGUS agent count).
        elite_ratio: Fraction of top performers to preserve unchanged.
        mutation_rate: Probability of mutation per genome.
        maladaptive_rate: Probability of maladaptive mutation per genome.
    """

    def __init__(
        self,
        population_size: int = 13,
        elite_ratio: float = 0.25,
        mutation_rate: float = 0.25,
        maladaptive_rate: float = 0.15,
    ):
        self.population_size = population_size
        self.elite_ratio = elite_ratio
        self.mutator = MutationEngine(
            mutation_rate=mutation_rate,
            maladaptive_rate=maladaptive_rate,
        )
        self.evaluator = FitnessEvaluator()
        self.population: list[AgentGenome] = []
        self.generation: int = 0
        self.hall_of_fame: list[dict] = []

    def seed_population(self) -> list[AgentGenome]:
        """Create initial population with diverse agent categories."""
        self.population = []
        for i in range(self.population_size):
            category = ARGUS_AGENT_CATEGORIES[i % len(ARGUS_AGENT_CATEGORIES)]
            genome = AgentGenome(
                agent_id=f"gen0-{category}-{uuid.uuid4().hex[:6]}",
                generation=0,
                agent_category=category,
                corpus_patterns=[],
                attack_posture=random.choice(["aggressive", "passive", "deceptive", "mimetic", "fragmented"]),
            )
            self.population.append(genome)
        return self.population

    def seed_from_corpus(self, corpus_patterns: dict[str, list[str]]) -> list[AgentGenome]:
        """Seed population from actual attack corpus patterns."""
        self.population = []
        categories = list(corpus_patterns.keys())
        for i in range(self.population_size):
            category = categories[i % len(categories)] if categories else "prompt_injection_hunter"
            patterns = corpus_patterns.get(category, [])
            genome = AgentGenome(
                agent_id=f"gen0-{category}-{uuid.uuid4().hex[:6]}",
                generation=0,
                agent_category=category,
                corpus_patterns=patterns[:20],  # Take up to 20 patterns per genome
            )
            self.population.append(genome)
        return self.population

    async def run_generation(
        self,
        scan_fn: Callable[[AgentGenome], Awaitable[EvolutionScanResult]],
    ) -> list[tuple[AgentGenome, dict]]:
        """Run all genomes in the current generation concurrently.

        Args:
            scan_fn: Async function that executes a genome and returns scan results.

        Returns:
            List of (genome, fitness_scores) tuples sorted by total fitness descending.
        """
        # Run all genomes concurrently
        tasks = [scan_fn(genome) for genome in self.population]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        scored: list[tuple[AgentGenome, dict]] = []
        for genome, result in zip(self.population, results, strict=False):
            if isinstance(result, Exception):
                logger.warning("Genome %s failed: %s", genome.agent_id, result)
                # Assign zero fitness on failure
                scores = {
                    "total_fitness": 0.0,
                    "standard_fitness": 0.0,
                    "maladaptive_fitness": 0.0,
                }
            else:
                scores = self.evaluator.score(genome, result)
                genome.fitness_score = scores["total_fitness"]
                genome.maladaptive_score = scores.get("maladaptive_fitness", 0.0)
            scored.append((genome, scores))

        # Sort by total fitness descending
        scored.sort(key=lambda x: x[1]["total_fitness"], reverse=True)
        return scored

    def evolve(self, scored: list[tuple[AgentGenome, dict]]) -> list[AgentGenome]:
        """Evolve the population based on fitness scores.

        Selection strategy:
          - Elite preservation: top N% carry over unchanged
          - Tournament selection for remaining slots
          - Crossover + mutation for new genomes
        """
        self.generation += 1
        elite_count = max(1, int(self.population_size * self.elite_ratio))

        # Elite preservation
        elites = [copy_genome(g, self.generation) for g, _ in scored[:elite_count]]

        # Record best genome in hall of fame
        best_genome, best_scores = scored[0]
        self.hall_of_fame.append(
            {
                "generation": self.generation - 1,
                "genome_id": best_genome.agent_id,
                "fingerprint": best_genome.fingerprint(),
                "fitness": best_scores["total_fitness"],
                "category": best_genome.agent_category,
                "findings": best_scores.get("standard_fitness", 0),
            }
        )

        # Fill remaining slots via tournament selection + crossover + mutation
        new_pop = list(elites)

        while len(new_pop) < self.population_size:
            parent_a = self._tournament_select(scored)
            parent_b = self._tournament_select(scored)

            if parent_a.agent_id != parent_b.agent_id:
                child = self.mutator.crossover(parent_a, parent_b)
            else:
                child = self.mutator.mutate(parent_a)

            child.agent_id = f"gen{self.generation}-{child.agent_category}-{uuid.uuid4().hex[:6]}"
            child.generation = self.generation
            child.fitness_score = 0.0
            child.maladaptive_score = 0.0
            child.cw_scores = []

            new_pop.append(child)

        self.population = new_pop[: self.population_size]
        return self.population

    def _tournament_select(self, scored: list[tuple[AgentGenome, dict]], k: int = 3) -> AgentGenome:
        """Tournament selection: pick k random genomes, return the fittest."""
        candidates = random.sample(scored, min(k, len(scored)))
        best = max(candidates, key=lambda x: x[1]["total_fitness"])
        return best[0]

    def check_armed_payloads(self) -> list[dict]:
        """Check all genomes for deferred payloads that should fire."""
        armed = []
        for genome in self.population:
            for payload in genome.deferred_payloads:
                armed.append(
                    {
                        "genome_id": genome.agent_id,
                        "category": genome.agent_category,
                        "payload": payload,
                    }
                )
        return armed

    def generation_summary(self) -> dict:
        """Summary stats for the current generation."""
        if not self.population:
            return {"generation": self.generation, "size": 0}

        fitnesses = [g.fitness_score for g in self.population]
        return {
            "generation": self.generation,
            "size": len(self.population),
            "avg_fitness": round(sum(fitnesses) / len(fitnesses), 4) if fitnesses else 0,
            "max_fitness": round(max(fitnesses), 4) if fitnesses else 0,
            "min_fitness": round(min(fitnesses), 4) if fitnesses else 0,
            "categories": list({g.agent_category for g in self.population}),
            "armed_payloads": sum(len(g.deferred_payloads) for g in self.population),
        }

    def get_best_genome(self) -> AgentGenome | None:
        """Return the genome with the highest fitness."""
        if not self.population:
            return None
        return max(self.population, key=lambda g: g.fitness_score)

    def export_hall_of_fame(self) -> list[dict]:
        """Export the hall of fame across all generations."""
        return list(self.hall_of_fame)


def copy_genome(genome: AgentGenome, new_generation: int) -> AgentGenome:
    """Deep-copy a genome for elite preservation."""
    import copy

    child = copy.deepcopy(genome)
    child.generation = new_generation
    return child
