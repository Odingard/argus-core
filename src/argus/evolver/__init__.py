"""
argus.evolver — Pillar-2 Raptor Cycle engine.

Per the spec, ARGUS' differentiating promise is a corpus that gets
sharper with every engagement. Phase-0 Ticket 0.8 shipped the
mechanical substrate (LLMMutator + CrossoverMutator + EvolveCorpus).
This module is the EVOLUTIONARY loop on top: MAP-Elites quality-
diversity + fitness-driven selection, modelled on codelion/openevolve
(the most mature open implementation of DeepMind AlphaEvolve).

Design tenets:

  1. **LLM mutator, deterministic evaluator.** The spec rule ("no
     LLM in the validation path") holds end-to-end. Mutation is the
     creative leg (LLM or offline text transform); fitness is scored
     by the existing ObservationEngine. The evaluator never calls
     an LLM.

  2. **Backend-pluggable mutation.** ``MutatorBackend`` is the
     protocol; ``OfflineMutatorBackend`` ships for tests and no-LLM
     envs; ``OpenEvolveMutatorBackend`` is imported lazily when
     ``openevolve`` is installed and degrades cleanly when it isn't.

  3. **MAP-Elites grid.** Feature dimensions are configurable —
     default (owasp_tag × token_length_bucket). Every elite is the
     best-fitness member of its cell, preserving diversity across
     the attack space instead of collapsing to a single global
     optimum.

  4. **Every elite promotes into EvolveCorpus.** The loop's output
     isn't a leaderboard — it's a bigger, more diverse corpus that
     the next engagement starts with.

Public surface:

    from argus.evolver import (
        EvolverController, EvolverConfig, PayloadLineage,
        MutatorBackend, OfflineMutatorBackend,
    )

    controller = EvolverController(
        backend=OfflineMutatorBackend(),
        fitness_fn=my_fitness,
    )
    result = controller.run(seeds=[...], generations=50)
    controller.promote_elites_to_corpus(result, evolve_corpus=ev)
"""
from argus.evolver.lineage import EvolvedPayload, PayloadLineage
from argus.evolver.controller import (
    EvolverConfig, EvolverController, EvolverResult, MapElitesCell,
    default_projector,
)
from argus.evolver.backends import (
    MutatorBackend, OfflineMutatorBackend, OpenEvolveMutatorBackend,
    try_openevolve,
)

__all__ = [
    "EvolvedPayload", "PayloadLineage",
    "EvolverConfig", "EvolverController", "EvolverResult",
    "MapElitesCell", "default_projector",
    "MutatorBackend", "OfflineMutatorBackend",
    "OpenEvolveMutatorBackend", "try_openevolve",
]
