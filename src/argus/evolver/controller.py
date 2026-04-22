"""
argus/evolver/controller.py — MAP-Elites quality-diversity controller.

The main loop:

  seeds → ( for generation g in 0..G )
             for each live cell:
               mutate best(cell) with backend → variants
               score each variant with fitness_fn (deterministic)
               project variant onto feature grid → target cell
               if fitness > current best(target cell): replace

Output is the final grid (``EvolverResult.elites``) — one payload
per cell, the best-fitness member ARGUS saw at that coordinate. The
promote-to-corpus helper writes every elite as a ``discovered`` seed
via ``EvolveCorpus.add_template``, which is the Raptor Cycle closing
its loop.

The fitness function is caller-supplied:
    Callable[[str], tuple[float, dict]]
Signature: (payload_text) → (numeric_fitness, metadata_dict).
Deterministic — no LLM. The default projector bucket payloads by
OWASP tag + token-length quartile; callers can supply their own.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from argus.evolver.backends import MutatorBackend
from argus.evolver.lineage import EvolvedPayload, PayloadLineage


# ── Feature projection ─────────────────────────────────────────────────────
# Maps a payload_text → feature coordinates. Each coordinate dim is
# a string bucket; the grid is the Cartesian product. Default dims:
#   OWASP tag    (AAI01..AAI10 + AAI00 fallback)
#   token-length bucket  (xs / s / m / l / xl)
# The projector is pluggable — customer engagements can layer in
# target-family or surface-kind axes.

_OWASP_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("AAI01", ("prompt", "ignore", "system prompt", "instruction")),
    ("AAI02", ("tool description", "tool_poison", "hidden instruction")),
    ("AAI03", ("remember", "memory", "skill", "crystallise", "persist")),
    ("AAI04", ("identity", "spoof", "impersonate", "handoff", "as admin")),
    ("AAI05", ("long conversation", "turn", "context", "gradual")),
    ("AAI06", ("forward", "exfil", "cross-agent", "pass to")),
    ("AAI07", ("admin", "sudo", "elevate", "privilege")),
    ("AAI08", ("parallel", "race", "concurrent", "toctou")),
    ("AAI09", ("oauth", "scope", "supply chain", "install")),
    ("AAI10", ("system prompt", "training data", "policy", "rephrase")),
)

_LEN_BUCKETS: tuple[tuple[str, int], ...] = (
    ("xs", 40),
    ("s",  120),
    ("m",  320),
    ("l",  800),
    ("xl", 10**9),
)


def default_projector(text: str) -> tuple[str, ...]:
    low = text.lower()
    tag = "AAI00"
    for t, markers in _OWASP_MARKERS:
        if any(m in low for m in markers):
            tag = t
            break
    n = len(text)
    length_bucket = next(
        name for name, ceil in _LEN_BUCKETS if n <= ceil
    )
    return (tag, length_bucket)


# ── Config + result ─────────────────────────────────────────────────────────

@dataclass
class EvolverConfig:
    generations:   int = 10
    seed:          int = 1337
    max_elites:    int = 200          # grid cap so unbounded runs terminate
    min_fitness:   float = 0.0        # any fitness >= this enters the grid
    notes:         str = ""


@dataclass
class MapElitesCell:
    coordinates: tuple[str, ...]
    elite:       EvolvedPayload

    def to_dict(self) -> dict:
        return {
            "coordinates": list(self.coordinates),
            "elite":       self.elite.to_dict(),
        }


@dataclass
class EvolverResult:
    config:        EvolverConfig
    elites:        dict[tuple[str, ...], EvolvedPayload]
    history:       list[dict] = field(default_factory=list)

    def as_cells(self) -> list[MapElitesCell]:
        return [MapElitesCell(coordinates=coords, elite=ev)
                for coords, ev in self.elites.items()]

    def top_n(self, n: int = 10) -> list[EvolvedPayload]:
        return sorted(self.elites.values(),
                      key=lambda p: p.fitness, reverse=True)[:n]

    def to_dict(self) -> dict:
        return {
            "config":       self.config.__dict__,
            "elite_count":  len(self.elites),
            "cells": [c.to_dict() for c in self.as_cells()],
            "history":      self.history,
        }


# ── Controller ─────────────────────────────────────────────────────────────

FitnessFn = Callable[[str], tuple[float, dict]]
ProjectorFn = Callable[[str], tuple[str, ...]]


class EvolverController:
    """
    Runs the MAP-Elites evolution loop.

    Construction:

        controller = EvolverController(
            backend=OfflineMutatorBackend(),
            fitness_fn=my_fitness,          # (text) -> (float, meta)
            projector=default_projector,    # optional
            config=EvolverConfig(generations=50),
        )

    Execution:

        result = controller.run(seeds=[("seed_xyz", "payload text"), ...])
        controller.promote_elites_to_corpus(result, evolve_corpus=ev)
    """

    def __init__(
        self,
        *,
        backend:    MutatorBackend,
        fitness_fn: FitnessFn,
        projector:  ProjectorFn = default_projector,
        config:     Optional[EvolverConfig] = None,
    ) -> None:
        self.backend    = backend
        self.fitness_fn = fitness_fn
        self.projector  = projector
        self.config     = config or EvolverConfig()

    # ── Core run ────────────────────────────────────────────────────

    def run(
        self,
        *,
        seeds: Iterable[tuple[str, str]],
    ) -> EvolverResult:
        """
        ``seeds`` is an iterable of (seed_id, text) pairs — typically
        pulled from the existing corpus:

            seeds = [(t.id, t.text) for t in corpus.templates()]
        """
        grid: dict[tuple[str, ...], EvolvedPayload] = {}
        history: list[dict] = []

        # 1) Seed the grid.
        for seed_id, text in seeds:
            fitness, meta = self._score(text)
            if fitness < self.config.min_fitness:
                continue
            coords = self.projector(text)
            payload = EvolvedPayload(
                payload_id=EvolvedPayload.id_for(
                    text, seed_id=seed_id, operators=[],
                ),
                text=text,
                fitness=fitness,
                feature_coords=coords,
                lineage=PayloadLineage(
                    payload_id="", seed_id=seed_id, steps=[],
                ),
                metadata={"source": "seed", **meta},
            )
            payload.lineage.payload_id = payload.payload_id
            self._offer(grid, coords, payload)

        history.append({
            "phase": "seeded",
            "cells": len(grid),
            "top_fitness": max(
                (p.fitness for p in grid.values()), default=0.0,
            ),
        })

        # 2) Evolve.
        for generation in range(self.config.generations):
            if len(grid) >= self.config.max_elites:
                break
            improved = 0
            # Snapshot cells to mutate — don't iterate a mutating dict.
            parents = list(grid.items())
            for coords, parent in parents:
                variants = self.backend.mutate(
                    parent.text,
                    generation=generation,
                    seed=self.config.seed + len(grid),
                )
                for v_text in variants:
                    fitness, meta = self._score(v_text)
                    if fitness < self.config.min_fitness:
                        continue
                    target = self.projector(v_text)
                    # Build lineage from parent.
                    lineage = PayloadLineage(
                        payload_id="",
                        seed_id=parent.lineage.seed_id,
                        steps=list(parent.lineage.steps),
                    )
                    lineage.add_step(
                        operator=f"{self.backend.name}:gen{generation}",
                        predecessor_id=parent.payload_id,
                        fitness_before=parent.fitness,
                        fitness_after=fitness,
                        notes=(meta.get("notes") or "")[:120],
                    )
                    operators = lineage.operators_used()
                    payload_id = EvolvedPayload.id_for(
                        v_text,
                        seed_id=parent.lineage.seed_id,
                        operators=operators,
                    )
                    lineage.payload_id = payload_id
                    payload = EvolvedPayload(
                        payload_id=payload_id,
                        text=v_text,
                        fitness=fitness,
                        feature_coords=target,
                        lineage=lineage,
                        metadata={"source": self.backend.name, **meta},
                    )
                    if self._offer(grid, target, payload):
                        improved += 1
            history.append({
                "phase": f"gen_{generation}",
                "cells": len(grid),
                "improved": improved,
                "top_fitness": max(
                    (p.fitness for p in grid.values()), default=0.0,
                ),
            })
            # Early exit when a generation yields no gains.
            if improved == 0 and generation > 0:
                break

        return EvolverResult(
            config=self.config,
            elites=grid,
            history=history,
        )

    # ── Elite promotion ─────────────────────────────────────────────

    def promote_elites_to_corpus(
        self,
        result:        EvolverResult,
        *,
        evolve_corpus,              # argus.corpus_attacks.EvolveCorpus
        target_id:     str = "evolver://offline",
        min_fitness:   float = 0.0,
    ) -> list[dict]:
        """
        Write each elite payload into the corpus as a discovered
        seed. Returns the entry dicts persisted (one per elite).
        Closing the Raptor Cycle: the next engagement starts with
        every elite this run produced.
        """
        out: list[dict] = []
        for coords, elite in result.elites.items():
            if elite.fitness < min_fitness:
                continue
            tags = ["evolver_elite", f"fitness:{elite.fitness:.2f}"]
            tags.extend(f"cell:{c}" for c in coords)
            try:
                entry = evolve_corpus.add_template(
                    text=elite.text,
                    category="discovered",
                    tags=tags,
                    surfaces=[],
                    severity="HIGH",
                    target_id=target_id,
                    finding_id=elite.payload_id,
                )
                out.append(entry)
            except Exception:
                continue
        return out

    # ── Internals ───────────────────────────────────────────────────

    def _score(self, text: str) -> tuple[float, dict]:
        out = self.fitness_fn(text)
        if isinstance(out, tuple) and len(out) == 2:
            return float(out[0]), dict(out[1] or {})
        # Fitness-only return — wrap.
        return float(out), {}      # type: ignore[arg-type]

    @staticmethod
    def _offer(
        grid:    dict[tuple[str, ...], EvolvedPayload],
        coords:  tuple[str, ...],
        payload: EvolvedPayload,
    ) -> bool:
        """Return True iff ``payload`` became the new elite for ``coords``."""
        current = grid.get(coords)
        if current is None or payload.fitness > current.fitness:
            grid[coords] = payload
            return True
        return False
