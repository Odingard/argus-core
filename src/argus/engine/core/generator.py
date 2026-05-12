"""Variant generator.

The generator walks a list of seeds × mutator-stack and produces a
deterministic, hash-deduplicated stream of ``Variant`` objects.

Determinism contract:
    Generator(seeds, mutators, seed_value=N).generate() ==
    Generator(seeds, mutators, seed_value=N).generate()

This is enforced by tests/unit/test_determinism.py.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from random import Random
from typing import Any

from .canary import CanarySet, make_canary
from .mutator import Mutator
from .recon_param import SeedParameterizer
from .recon_profile import ReconProfile
from .seed import Seed
from .variant import Message, ResourceSpec, ToolSpec, Variant, hash_variant

RenderHook = Callable[[Seed, dict[str, Any], CanarySet], dict[str, Any]]
"""A render hook turns the merged rendered-dict from the mutator stack into
the concrete fields a Variant needs (messages/tools/resources/rag_corpus)."""


def default_render(seed: Seed, rendered: dict[str, Any], canaries: CanarySet) -> dict[str, Any]:
    """Default render: substitute ``{canary}`` and seed placeholders into the
    seed template, return one user message.
    """
    template = rendered.get("template", seed.template)
    subs: dict[str, str] = {"canary": canaries.primary}
    for k, options in seed.placeholders.items():
        # the mutator-stack may have set a placeholder explicitly
        subs[k] = rendered.get(k, options[0])
    text = template.format(**{k: v for k, v in subs.items() if f"{{{k}}}" in template})
    return {"messages": [Message(role="user", content=text)]}


class Generator:
    """Compose seeds × mutators × render-hook into a deterministic Variant stream.

    Args:
        seeds: One or more verified seeds for a single attack class.
        mutators: Stack of mutators applied to each seed. Empty list = identity.
        seed_value: Master seed for the RNG. Drives canary derivation.
        render: Hook turning rendered-dicts into Variant fields.
        matcher_ids: Default matcher ids attached to every emitted variant.
        max_variants: Hard cap on the variant count for safety. Default 25,000.
    """

    def __init__(
        self,
        seeds: Iterable[Seed],
        mutators: Iterable[Mutator],
        *,
        seed_value: int,
        render: RenderHook = default_render,
        matcher_ids: tuple[str, ...] = ("canary-echo",),
        max_variants: int = 25_000,
        recon: ReconProfile | None = None,
    ) -> None:
        seeds_tuple: tuple[Seed, ...] = tuple(seeds)
        if recon is not None:
            seeds_tuple = SeedParameterizer(recon).parameterize_all(seeds_tuple)
        self._seeds: tuple[Seed, ...] = seeds_tuple
        self._mutators: tuple[Mutator, ...] = tuple(mutators)
        self._seed_value = seed_value
        self._render = render
        self._matcher_ids = matcher_ids
        self._max_variants = max_variants
        self._recon = recon

    def generate(self) -> Iterator[Variant]:
        emitted: set[str] = set()
        count = 0
        for seed in self._seeds:
            rng = Random(self._seed_value ^ hash(seed.seed_id) & 0xFFFFFFFF)
            canaries = self._derive_canaries(seed)
            stack = self._mutators or (_IdentitySingleton,)
            for rendered, label, params in _walk(stack, seed, rng):
                merged = self._render(seed, rendered, canaries)
                vid = hash_variant(
                    seed_id=seed.seed_id,
                    mutator_chain=tuple(label.split(">")) if label else (),
                    rendered=_render_summary(merged),
                )
                if vid in emitted:
                    continue
                emitted.add(vid)
                yield Variant(
                    variant_id=vid,
                    seed_id=seed.seed_id,
                    attack_class=seed.attack_class,
                    layer=seed.layer,
                    messages=tuple(merged.get("messages", ())),
                    tools=tuple(merged.get("tools", ())),
                    resources=tuple(merged.get("resources", ())),
                    rag_corpus=tuple(merged.get("rag_corpus", ())),
                    canaries=canaries,
                    matcher_ids=self._matcher_ids,
                    mutator_chain=tuple(label.split(">")) if label else (),
                    metadata={
                        "seed_value": self._seed_value,
                        "seed_version": seed.version,
                        "params": params,
                    },
                )
                count += 1
                if count >= self._max_variants:
                    return

    def _derive_canaries(self, seed: Seed) -> CanarySet:
        primary = make_canary(self._seed_value, f"{seed.seed_id}.primary")
        secondary = (
            make_canary(self._seed_value, f"{seed.seed_id}.s1"),
            make_canary(self._seed_value, f"{seed.seed_id}.s2"),
        )
        return CanarySet(primary=primary, secondary=secondary)


class _IdentitySingleton:
    name = "identity"

    @staticmethod
    def mutate(seed: Seed, rng: Random):
        yield ({}, "identity", {})


def _walk(stack, seed: Seed, rng: Random):
    """Iteratively walk the cartesian product of a mutator stack.

    Implemented as DFS over a single shared RNG to keep determinism while
    avoiding deep recursion limits for large variant counts.
    """
    head, *rest = stack
    if not rest:
        yield from head.mutate(seed, rng)
        return
    for rendered_a, label_a, params_a in head.mutate(seed, rng):
        for rendered_b, label_b, params_b in _walk(rest, seed, rng):
            merged = _merge(rendered_a, rendered_b)
            yield (merged, f"{label_a}>{label_b}", {**params_a, **params_b})


def _merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], (list, tuple)) and isinstance(v, (list, tuple)):
            out[k] = list(out[k]) + list(v)
        else:
            out[k] = v
    return out


def _render_summary(merged: dict[str, Any]) -> dict[str, Any]:
    """A summarized, hashable view of the rendered fields for variant_id."""
    return {
        "messages": [(m.role, m.content) for m in merged.get("messages", ())],
        "tools": [
            (t.name, t.description, sorted(t.parameters_schema.keys()))
            for t in merged.get("tools", ())
            if isinstance(t, ToolSpec)
        ],
        "resources": [
            (r.uri, r.mime_type, r.description) for r in merged.get("resources", ()) if isinstance(r, ResourceSpec)
        ],
        "rag_corpus": list(merged.get("rag_corpus", ())),
    }
